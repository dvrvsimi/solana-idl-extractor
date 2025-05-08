//! SBF instruction parsing for Solana programs.
//!
//! This module provides utilities for parsing Solana BPF instructions
//! from binary data. It includes support for different SBPF versions,
//! instruction types, and error recovery mechanisms.

use anyhow::{Result, anyhow, Context};
use log::{debug, info, warn};
use crate::constants::opcodes::opcodes;
use crate::errors::{ExtractorError, ExtractorResult};
use solana_sbpf::{
    elf::Executable,
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    static_analysis::Analysis,
    test_utils::TestContextObject,
};
use std::sync::Arc;
use crate::utils::instruction_patterns::{
    is_instruction_handler,
    is_discriminator_check,
    is_anchor_discriminator,
    is_syscall,
    is_account_validation,
    is_parameter_loading,
};
use crate::utils::memory_analysis::{
    accesses_memory,
    memory_access_type,
    mem_size,
    is_load,
    is_store,
};

/// Memory access type for SBF instructions
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryAccessType {
    /// Load from memory
    Load,
    /// Store to memory
    Store,
}

/// SBPF version
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SbpfVersion {
    /// V0 (original)
    V0,
    /// V1 (added 64-bit instructions)
    V1,
    /// V2 (added ALU32 instructions)
    V2,
    /// V3 (latest version with additional syscalls)
    V3,
}

/// SBF instruction class
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InstructionClass {
    MemoryLoadOr32BitALU = 0,
    MemoryStoreOr64BitALU = 1,
    ProductQuotientRemainder = 2,
    ControlFlow = 3,
}

/// Enhanced SBF instruction representation
#[derive(Debug, Clone)]
pub struct SbfInstruction {
    /// Instruction class (bits 0-2)
    pub class: InstructionClass,
    /// Operation code (bits 3-7)
    pub opcode: u8,
    /// Destination register (bits 8-11)
    pub dst_reg: u8,
    /// Source register (bits 12-15) 
    pub src_reg: u8,
    /// Offset (bits 16-31)
    pub offset: i16,
    /// Immediate value (bits 32-63)
    pub imm: i64,
    /// Size of memory access (1, 2, 4, or 8 bytes)
    pub size: usize,
    /// SBPF version this instruction is from
    pub version: SbpfVersion,
    /// Whether this is a two-slot instruction
    pub is_two_slot: bool,
}

impl SbfInstruction {
    /// Parse an SBF instruction from a byte slice.
    ///
    /// This method parses a single SBF instruction from a byte slice,
    /// extracting the opcode, registers, offset, and immediate value.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte slice containing the instruction.
    /// * `address` - The address of the instruction in memory.
    ///
    /// # Returns
    ///
    /// A result containing the parsed instruction, or an error
    /// if the data could not be parsed.
    pub fn parse(data: &[u8], address: usize) -> ExtractorResult<Self> {
        if data.len() < 8 {
            return Err(ExtractorError::BytecodeAnalysis(
                format!("Instruction data too short at address 0x{:x}", address)
            ));
        }
        
        // Extract instruction components using bit operations
        let class = (data[0] & 0x07) as u8; // bits 0-2
        let opcode = (data[0] >> 3) & 0x1F; // bits 3-7
        let dst_reg = (data[1] >> 4) & 0x0F; // bits 8-11
        let src_reg = data[1] & 0x0F; // bits 12-15
        let offset = i16::from_le_bytes([data[2], data[3]]); // bits 16-31
        let imm = i32::from_le_bytes([data[4], data[5], data[6], data[7]]) as i64; // bits 32-63

        // Determine if this is a two-slot instruction (LDDW)
        let is_two_slot = opcode == opcodes::LDDW;
        
        // Validate instruction class
        let class = match class {
            0 => InstructionClass::MemoryLoadOr32BitALU,
            1 => InstructionClass::MemoryStoreOr64BitALU,
            2 => InstructionClass::ProductQuotientRemainder,
            3 => InstructionClass::ControlFlow,
            _ => return Err(ExtractorError::BytecodeAnalysis(
                format!("Invalid instruction class {} at address 0x{:x}", class, address)
            )),
        };

        // Enhanced size detection based on instruction type
        let size = match (class, opcode) {
            (InstructionClass::MemoryLoadOr32BitALU, _) => 4,
            (InstructionClass::MemoryStoreOr64BitALU, _) => 8,
            _ => 0,
        };

        Ok(Self {
            class,
            opcode,
            dst_reg,
            src_reg,
            offset,
            imm,
            size,
            version: detect_sbpf_version(data).unwrap_or(SbpfVersion::V0),
            is_two_slot,
        })
    }
    
    /// Check if this is a jump instruction.
    ///
    /// # Returns
    ///
    /// `true` if this is a jump instruction, `false` otherwise.
    pub fn is_jump(&self) -> bool {
        matches!(
            self.opcode,
            opcodes::JA | opcodes::JEQ_REG | opcodes::JEQ_IMM | 
            opcodes::JNE_REG | opcodes::JNE_IMM | opcodes::JGT_IMM |
            opcodes::JGT_REG | opcodes::JGE_IMM | opcodes::JGE_REG |
            opcodes::JLT_IMM | opcodes::JLT_REG | opcodes::JLE_IMM |
            opcodes::JLE_REG | opcodes::JSET_IMM | opcodes::JSET_REG |
            opcodes::JSGT_IMM | opcodes::JSGT_REG | opcodes::JSGE_IMM |
            opcodes::JSGE_REG | opcodes::JSLT_IMM | opcodes::JSLT_REG |
            opcodes::JSLE_IMM | opcodes::JSLE_REG
        )
    }
    
    /// Check if this is a call instruction.
    ///
    /// # Returns
    ///
    /// `true` if this is a call instruction, `false` otherwise.
    pub fn is_call(&self) -> bool {
        self.opcode == opcodes::CALL || self.opcode == opcodes::CALLX
    }
    
    /// Check if this is an exit instruction.
    ///
    /// # Returns
    ///
    /// `true` if this is an exit instruction, `false` otherwise.
    pub fn is_exit(&self) -> bool {
        self.opcode == opcodes::EXIT || self.opcode == opcodes::RETURN
    }
    
    /// Check if this is a load instruction.
    ///
    /// # Returns
    ///
    /// `true` if this is a load instruction, `false` otherwise.
    pub fn is_load(&self) -> bool {
        (self.opcode & 0xF0) == 0x20
    }
    
    /// Check if this is a store instruction.
    ///
    /// # Returns
    ///
    /// `true` if this is a store instruction, `false` otherwise.
    pub fn is_store(&self) -> bool {
        (self.opcode & 0xF0) == 0x60
    }
    
    /// Check if this is an ALU operation.
    ///
    /// # Returns
    ///
    /// `true` if this is an ALU operation, `false` otherwise.
    pub fn is_alu(&self) -> bool {
        matches!(
            self.opcode,
            opcodes::ADD32_IMM | opcodes::ADD32_REG | opcodes::ADD64_IMM | opcodes::ADD64_REG |
            opcodes::SUB32_IMM | opcodes::SUB32_REG | opcodes::SUB64_IMM | opcodes::SUB64_REG |
            opcodes::MUL32_IMM | opcodes::MUL32_REG | opcodes::MUL64_IMM | opcodes::MUL64_REG |
            opcodes::OR32_IMM | opcodes::OR32_REG | opcodes::OR64_IMM | opcodes::OR64_REG |
            opcodes::AND32_IMM | opcodes::AND32_REG | opcodes::AND64_IMM | opcodes::AND64_REG |
            opcodes::LSH32_IMM | opcodes::LSH32_REG | opcodes::LSH64_IMM | opcodes::LSH64_REG |
            opcodes::RSH32_IMM | opcodes::RSH32_REG | opcodes::RSH64_IMM | opcodes::RSH64_REG |
            opcodes::NEG32 | opcodes::NEG64 | opcodes::XOR32_IMM | opcodes::XOR32_REG |
            opcodes::XOR64_IMM | opcodes::XOR64_REG | opcodes::MOV32_IMM | opcodes::MOV32_REG |
            opcodes::MOV64_IMM | opcodes::MOV64_REG | opcodes::ARSH32_IMM | opcodes::ARSH32_REG |
            opcodes::ARSH64_IMM | opcodes::ARSH64_REG
        )
    }
    
    /// Get the size of the load/store operation.
    ///
    /// # Returns
    ///
    /// The size of the load/store operation in bytes, or `None` if this is not a load/store instruction.
    pub fn mem_size(&self) -> Option<usize> {
        if self.is_load() || self.is_store() {
            Some(self.size)
        } else {
            None
        }
    }
    
    /// Check if this instruction is a V2+ ALU32 instruction.
    ///
    /// # Returns
    ///
    /// `true` if this is a V2+ ALU32 instruction, `false` otherwise.
    pub fn is_alu32(&self) -> bool {
        self.version >= SbpfVersion::V2 && 
        (self.opcode & 0x07) == 0x04
    }
    
    /// Check if this instruction uses a V3 syscall.
    ///
    /// # Returns
    ///
    /// `true` if this instruction uses a V3 syscall, `false` otherwise.
    pub fn is_v3_syscall(&self) -> bool {
        self.version == SbpfVersion::V3 && 
        self.opcode == 0x85 &&
        self.imm >= 0x100000
    }
    
    pub fn is_load_imm(&self) -> bool {
        self.opcode == opcodes::LDDW
    }
    
    pub fn is_mov_reg(&self) -> bool {
        self.opcode == opcodes::MOV64_REG
    }
    
    pub fn is_add_imm(&self) -> bool {
        self.opcode == opcodes::ADD64_IMM
    }

    pub fn is_add_reg(&self) -> bool {
        self.opcode == opcodes::ADD64_REG
    }
    
    pub fn is_cmp(&self) -> bool {
        self.opcode == opcodes::JEQ_REG ||
        self.opcode == opcodes::JNE_REG
    }
    
    pub fn is_branch(&self) -> bool {
        self.opcode == opcodes::JA ||
        self.opcode == opcodes::JEQ_IMM ||
        self.opcode == opcodes::JNE_IMM ||
        self.opcode == opcodes::JEQ_REG ||
        self.opcode == opcodes::JNE_REG
    }
    
    pub fn is_conditional_branch(&self) -> bool {
        self.opcode == opcodes::JEQ_IMM ||
        self.opcode == opcodes::JNE_IMM ||
        self.opcode == opcodes::JEQ_REG ||
        self.opcode == opcodes::JNE_REG
    }
    
    pub fn is_return(&self) -> bool {
        self.opcode == opcodes::EXIT
    }
    
    pub fn branch_target(&self) -> Option<usize> {
        if self.is_branch() {
            Some((self.offset as isize + self.imm as isize) as usize)
        } else {
            None
        }
    }
    
    pub fn call_target(&self) -> Option<usize> {
        if self.opcode == opcodes::CALL {
            Some((self.offset as isize + self.imm as isize) as usize)
        } else {
            None
        }
    }
    
    pub fn is_mov_imm(&self) -> bool {
        self.opcode == opcodes::MOV64_IMM
    }
    
    pub fn is_cmp_imm(&self) -> bool {
        self.opcode == opcodes::JEQ_IMM ||
        self.opcode == opcodes::JNE_IMM
    }
    
    pub fn is_cmp_reg(&self) -> bool {
        self.opcode == opcodes::JEQ_REG ||
        self.opcode == opcodes::JNE_REG
    }

    /// Get the instruction mnemonic
    pub fn mnemonic(&self) -> &'static str {
        match (self.class, self.opcode) {
            (InstructionClass::MemoryLoadOr32BitALU, opcodes::ADD32_IMM) => "add32",
            (InstructionClass::MemoryLoadOr32BitALU, opcodes::ADD32_REG) => "add32",
            // Add all other mnemonics...
            _ => "unknown"
        }
    }

    /// Check if instruction accesses memory
    pub fn accesses_memory(&self) -> bool {
        accesses_memory(self)
    }

    /// Get memory access type if applicable
    pub fn memory_access_type(&self) -> Option<MemoryAccessType> {
        memory_access_type(self)
    }

    /// Check if instruction modifies control flow
    pub fn modifies_control_flow(&self) -> bool {
        self.is_jump() || self.is_call() || self.is_exit()
    }

    /// Get jump target if this is a jump instruction
    pub fn jump_target(&self, current_address: usize) -> Option<usize> {
        if self.is_jump() {
            Some(current_address.wrapping_add(self.offset as usize))
        } else {
            None
        }
    }

    /// Verify instruction validity
    pub fn verify(&self) -> Result<(), String> {
        // Verify register ranges
        if self.src_reg > 10 {
            return Err(format!("Invalid source register r{}", self.src_reg));
        }
        
        if self.dst_reg > 9 && !self.is_store() {
            return Err(format!("Invalid destination register r{}", self.dst_reg));
        }

        // Verify immediate values
        match self.opcode {
            opcodes::SDIV32_IMM | opcodes::SDIV64_IMM |
            opcodes::UDIV32_IMM | opcodes::UDIV64_IMM => {
                if self.imm == 0 {
                    return Err("Division by zero".to_string());
                }
            }
            opcodes::LSH32_IMM | opcodes::RSH32_IMM | opcodes::ARSH32_IMM => {
                if self.imm < 0 || self.imm >= 32 {
                    return Err(format!("Invalid 32-bit shift amount {}", self.imm));
                }
            }
            opcodes::LSH64_IMM | opcodes::RSH64_IMM | opcodes::ARSH64_IMM => {
                if self.imm < 0 || self.imm >= 64 {
                    return Err(format!("Invalid 64-bit shift amount {}", self.imm));
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Check if this instruction is likely part of an instruction handler
    pub fn is_instruction_handler(&self) -> bool {
        is_instruction_handler(self)
    }

    /// Check if this is a discriminator check
    pub fn is_discriminator_check(&self) -> bool {
        is_discriminator_check(self)
    }

    /// Check if this is an Anchor discriminator check
    pub fn is_anchor_discriminator(&self) -> bool {
        is_anchor_discriminator(self)
    }

    /// Check if this is a syscall
    pub fn is_syscall(&self) -> bool {
        is_syscall(self)
    }

    /// Check if this instruction is part of account validation
    pub fn is_account_validation(&self) -> bool {
        is_account_validation(self)
    }

    /// Check if this instruction is loading parameters
    pub fn is_parameter_loading(&self) -> bool {
        is_parameter_loading(self)
    }
}

/// Parse instructions using official SBPF tools
pub fn parse_instructions(data: &[u8], base_address: usize) -> ExtractorResult<Vec<SbfInstruction>> {
    let executable = Executable::<TestContextObject>::from_text_bytes(
        data,
        Arc::new(BuiltinProgram::new_mock()),
        SBPFVersion::V3,
        FunctionRegistry::default(),
    ).map_err(|e| ExtractorError::BytecodeAnalysis(format!("Failed to create executable: {}", e)))?;

    let analysis = Analysis::from_executable(&executable)
        .map_err(|e| ExtractorError::BytecodeAnalysis(format!("Failed to analyze executable: {}", e)))?;

    // Use SBPF's analysis to group instructions into handlers
    let handlers = group_instruction_handlers(&analysis);
    
    // Flatten handlers into single instruction list
    let instructions = handlers.into_iter().flatten().collect();
    
    Ok(instructions)
}

/// Extract discriminator from instruction data.
///
/// This function extracts the discriminator byte from instruction data.
///
/// # Arguments
///
/// * `data` - The instruction data.
///
/// # Returns
///
/// The discriminator byte, or 0 if the data is empty.
pub fn extract_discriminator(data: &[u8]) -> u8 {
    if data.is_empty() {
        return 0;
    }
    
    data[0]
}

/// Infer parameter types from instruction data.
///
/// This function analyzes instruction data to infer the types of parameters
/// based on their sizes and patterns.
///
/// # Arguments
///
/// * `data` - The instruction data to analyze.
///
/// # Returns
///
/// A vector of inferred parameter types.
pub fn infer_parameter_types(data: &[u8]) -> Vec<String> {
    // Implementation based on data size and patterns
    if data.is_empty() {
        return Vec::new();
    }
    
    let mut types = Vec::new();
    
    // Check data length to infer types
    match data.len() {
        1 => types.push("u8".to_string()),
        2 => types.push("u16".to_string()),
        4 => types.push("u32".to_string()),
        8 => types.push("u64".to_string()),
        32 => types.push("pubkey".to_string()),
        _ => {
            // Try to break down into multiple types
            let mut offset = 0;
            while offset < data.len() {
                let remaining = data.len() - offset;
                if remaining >= 32 {
                    types.push("pubkey".to_string());
                    offset += 32;
                } else if remaining >= 8 {
                    types.push("u64".to_string());
                    offset += 8;
                } else if remaining >= 4 {
                    types.push("u32".to_string());
                    offset += 4;
                } else if remaining >= 2 {
                    types.push("u16".to_string());
                    offset += 2;
                } else {
                    types.push("u8".to_string());
                    offset += 1;
                }
            }
        }
    }
    
    types
}

/// Detect SBPF version from bytecode.
///
/// This function analyzes bytecode to determine the SBPF version
/// based on instruction patterns and ELF header information.
///
/// # Arguments
///
/// * `data` - The bytecode to analyze.
///
/// # Returns
///
/// A result containing the detected SBPF version, or an error
/// if the version could not be determined.
fn detect_sbpf_version(data: &[u8]) -> ExtractorResult<SbpfVersion> {
    // Check ELF header for version information
    if data.len() >= 0x40 {
        // Check e_flags in ELF header (offset 0x24, 4 bytes)
        let e_flags_offset = 0x24;
        if e_flags_offset + 4 <= data.len() {
            let e_flags = u32::from_le_bytes([
                data[e_flags_offset],
                data[e_flags_offset + 1],
                data[e_flags_offset + 2],
                data[e_flags_offset + 3],
            ]);
            
            // Extract BPF version from flags
            // Solana uses specific bits in e_flags to indicate BPF version
            let version_bits = (e_flags >> 24) & 0x0F;
            
            match version_bits {
                0 => return Ok(SbpfVersion::V0),
                1 => return Ok(SbpfVersion::V1),
                2 => return Ok(SbpfVersion::V2),
                3 => return Ok(SbpfVersion::V3),
                _ => {} // Continue with heuristic detection
            }
        }
    }
    
    // Fallback: Use heuristics to detect version
    
    // Check for V3-specific syscalls
    for i in (0..data.len()).step_by(8) {
        if i + 8 <= data.len() {
            let opcode = data[i];
            if opcode == 0x85 { // call instruction
                let imm_bytes = [data[i + 4], data[i + 5], data[i + 6], data[i + 7]];
                let imm = i32::from_le_bytes(imm_bytes);
                
                if imm >= 0x100000 { // V3 syscall range
                    return Ok(SbpfVersion::V3);
                }
            }
        }
    }
    
    // Check for V2-specific ALU32 instructions
    for i in (0..data.len()).step_by(8) {
        if i + 8 <= data.len() {
            let opcode = data[i];
            if (opcode & 0x07) == 0x04 { // ALU32 class
                return Ok(SbpfVersion::V2);
            }
        }
    }
    
    // Check for V1-specific 64-bit instructions
    for i in (0..data.len()).step_by(8) {
        if i + 16 <= data.len() {
            let opcode = data[i];
            if opcode == 0x18 || opcode == 0x1a { // lddw instructions
                return Ok(SbpfVersion::V1);
            }
        }
    }
    
    // Default to V0 if no specific features detected
    Ok(SbpfVersion::V0)
}

/// Analyze program using official SBPF tools
pub fn analyze_with_sbpf(program_data: &[u8]) -> ExtractorResult<Vec<SbfInstruction>> {
    // Create executable using official SBPF tools
    let executable = Executable::<TestContextObject>::from_text_bytes(
        program_data,
        Arc::new(BuiltinProgram::new_mock()),
        SBPFVersion::V3,
        FunctionRegistry::default(),
    ).map_err(|e| ExtractorError::BytecodeAnalysis(format!("Failed to create executable: {}", e)))?;

    // Get analysis from executable
    let analysis = Analysis::from_executable(&executable)
        .map_err(|e| ExtractorError::BytecodeAnalysis(format!("Failed to analyze executable: {}", e)))?;

    // Convert SBPF instructions to our format
    let mut instructions = Vec::new();
    for (pc, insn) in analysis.instructions.iter().enumerate() {
        instructions.push(SbfInstruction {
            class: match insn.opc & 0x07 {
                0 => InstructionClass::MemoryLoadOr32BitALU,
                1 => InstructionClass::MemoryStoreOr64BitALU,
                2 => InstructionClass::ProductQuotientRemainder,
                3 => InstructionClass::ControlFlow,
                _ => return Err(ExtractorError::BytecodeAnalysis(
                    format!("Invalid instruction class at PC {}: {}", pc, insn.opc)
                ))
            },
            opcode: insn.opc,
            dst_reg: insn.dst,
            src_reg: insn.src,
            offset: insn.off,
            imm: insn.imm,
            size: match insn.opc {
                0x61 => 4,  // ldxw
                0x69 => 2,  // ldxh
                0x71 => 1,  // ldxb
                0x79 => 8,  // ldxdw
                _ => 0
            },
            version: SbpfVersion::V3,
            is_two_slot: insn.opc == 0x18, // lddw
        });
    }

    Ok(instructions)
}

/// Group instructions into handlers using SBPF analysis
pub fn group_instruction_handlers(analysis: &Analysis) -> Vec<Vec<SbfInstruction>> {
    let mut handlers = Vec::new();
    let mut current_handler = Vec::new();
    let mut in_handler = false;

    for (pc, insn) in analysis.instructions.iter().enumerate() {
        let instruction = SbfInstruction {
            class: match insn.opc & 0x07 {
                0 => InstructionClass::MemoryLoadOr32BitALU,
                1 => InstructionClass::MemoryStoreOr64BitALU,
                2 => InstructionClass::ProductQuotientRemainder,
                3 => InstructionClass::ControlFlow,
                _ => continue,
            },
            opcode: insn.opc,
            dst_reg: insn.dst,
            src_reg: insn.src,
            offset: insn.off,
            imm: insn.imm,
            size: match insn.opc {
                0x61 => 4,  // ldxw
                0x69 => 2,  // ldxh
                0x71 => 1,  // ldxb
                0x79 => 8,  // ldxdw
                _ => 0
            },
            version: SbpfVersion::V3,
            is_two_slot: insn.opc == 0x18,
        };

        // Use instruction patterns to detect handler boundaries
        if instruction.is_instruction_handler() {
            if !current_handler.is_empty() {
                handlers.push(current_handler);
                current_handler = Vec::new();
            }
            in_handler = true;
        }

        if in_handler {
            current_handler.push(instruction);
        }

        // Check for handler end using instruction patterns
        if instruction.is_exit() {
            in_handler = false;
            if !current_handler.is_empty() {
                handlers.push(current_handler);
                current_handler = Vec::new();
            }
        }
    }

    // Add final handler if any
    if !current_handler.is_empty() {
        handlers.push(current_handler);
    }

    handlers
}