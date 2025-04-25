//! SBF instruction parsing

use anyhow::{Result, anyhow, Context};
use log::{debug, info, warn};
use std::collections::HashMap;
use crate::constants::opcodes;

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

/// SBF instruction
#[derive(Debug, Clone, Copy)]
pub struct SbfInstruction {
    /// Instruction opcode
    pub opcode: u8,
    /// Destination register
    pub dst_reg: u8,
    /// Source register
    pub src_reg: u8,
    /// Offset
    pub offset: i16,
    /// Immediate value
    pub imm: i64,
    /// Size of memory access (1, 2, 4, or 8 bytes)
    pub size: usize,
    /// SBPF version this instruction is from
    pub version: SbpfVersion,
}

impl SbfInstruction {
    /// Parse an SBF instruction from a byte slice
    pub fn parse(data: &[u8], address: usize) -> Result<Self> {
        if data.len() < 8 {
            return Err(anyhow!("Instruction data too short"));
        }
        
        let opcode = data[0];
        let dst_reg = (data[1] & 0xf0) >> 4;
        let src_reg = data[1] & 0x0f;
        let offset = i16::from_le_bytes([data[2], data[3]]);
        let imm = i32::from_le_bytes([data[4], data[5], data[6], data[7]]) as i64;
        
        Ok(Self {
            opcode,
            dst_reg,
            src_reg,
            offset,
            imm,
            size: match opcode & 0xF8 {
                0x20 => 1,
                0x28 => 2,
                0x30 => 4,
                0x38 => 8,
                _ => 0,
            },
            version: detect_sbpf_version(data)?,
        })
    }
    
    /// Check if this is a jump instruction
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
    
    /// Check if this is a call instruction
    pub fn is_call(&self) -> bool {
        self.opcode == opcodes::CALL || self.opcode == opcodes::CALLX
    }
    
    /// Check if this is an exit instruction
    pub fn is_exit(&self) -> bool {
        self.opcode == opcodes::EXIT || self.opcode == opcodes::RETURN
    }
    
    /// Check if this is a load instruction
    pub fn is_load(&self) -> bool {
        (self.opcode & 0xF0) == 0x20
    }
    
    /// Check if this is a store instruction
    pub fn is_store(&self) -> bool {
        (self.opcode & 0xF0) == 0x60
    }
    
    /// Check if this is an ALU operation
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
    
    /// Get the size of the load/store operation
    pub fn mem_size(&self) -> Option<usize> {
        if self.is_load() || self.is_store() {
            Some(self.size)
        } else {
            None
        }
    }
    
    /// Check if this instruction is a V2+ ALU32 instruction
    pub fn is_alu32(&self) -> bool {
        self.version >= SbpfVersion::V2 && 
        (self.opcode & 0x07) == 0x04
    }
    
    /// Check if this instruction uses a V3 syscall
    pub fn is_v3_syscall(&self) -> bool {
        self.version == SbpfVersion::V3 && 
        self.opcode == 0x85 &&
        self.imm >= 0x100000
    }
}

/// Parse instructions from a byte slice
pub fn parse_instructions(data: &[u8], base_address: usize) -> Result<Vec<SbfInstruction>> {
    let mut instructions = Vec::new();
    let mut offset = 0;
    
    // Try to detect SBPF version from ELF header or instruction patterns
    let version = detect_sbpf_version(data)?;
    info!("Detected SBPF version: {:?}", version);
    
    while offset + 8 <= data.len() {
        let insn = SbfInstruction::parse(&data[offset..offset + 8], base_address + offset)?;
        instructions.push(insn);
        offset += 8;
    }
    
    Ok(instructions)
}

/// Extract discriminator from instruction data
pub fn extract_discriminator(data: &[u8]) -> u8 {
    if data.is_empty() {
        return 0;
    }
    
    data[0]
}

/// Add this function for the tests
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

/// Detect SBPF version from bytecode
fn detect_sbpf_version(data: &[u8]) -> Result<SbpfVersion> {
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