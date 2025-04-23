//! Bytecode parsing and analysis for Solana programs

use anyhow::{Result, anyhow, Context};
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use goblin::elf;
use goblin::elf::header::{EM_BPF, EM_X86_64, EM_AARCH64};
use goblin::elf::section_header::{SHT_SYMTAB, SHT_STRTAB, SHT_REL, SHT_RELA};
use goblin::elf::dynamic::DT_NULL;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use goblin::elf::Elf;

use crate::models::{instruction::Instruction, account::Account};
use crate::constants::{opcodes, syscalls, discriminators};

/// SBF Instruction opcodes
mod opcodes {
    // Jump instructions
    pub const JA: u8 = 0x05;
    pub const JEQ_REG: u8 = 0x15;
    pub const JEQ_IMM: u8 = 0x1d;
    pub const JNE_REG: u8 = 0x55;
    pub const JNE_IMM: u8 = 0x5d;
    
    // Call instructions
    pub const CALL: u8 = 0x85;
    pub const EXIT: u8 = 0x95;
    
    // Load instructions
    pub const LDDW: u8 = 0x18;
    pub const LDXB: u8 = 0x71;
    pub const LDXH: u8 = 0x69;
    pub const LDXW: u8 = 0x61;
    pub const LDXDW: u8 = 0x79;
    
    // Store instructions
    pub const STB: u8 = 0x72;
    pub const STH: u8 = 0x6a;
    pub const STW: u8 = 0x62;
    pub const STDW: u8 = 0x7a;
    pub const STXB: u8 = 0x73;
    pub const STXH: u8 = 0x6b;
    pub const STXW: u8 = 0x63;
    pub const STXDW: u8 = 0x7b;
    
    // ALU instructions
    pub const MOV_IMM: u8 = 0xb7;
    pub const MOV_REG: u8 = 0xbf;
}

/// Common Sealevel syscall hashes
mod syscalls {
    pub const SOL_LOG: u32 = 0x207559bd;
    pub const SOL_LOG_PUBKEY: u32 = 0x7ef088ca;
    pub const SOL_CREATE_PROGRAM_ADDRESS: u32 = 0x9377323c;
    pub const SOL_TRY_FIND_PROGRAM_ADDRESS: u32 = 0x48504a38;
    pub const SOL_INVOKE_SIGNED_C: u32 = 0xa22b9c85;
    pub const SOL_INVOKE_SIGNED_RUST: u32 = 0xd7449092;
    pub const SOL_PANIC: u32 = 0x686093bb;
}

/// SBF instruction format
#[derive(Debug, Clone)]
struct SbfInstruction {
    /// Opcode
    opcode: u8,
    /// Destination register
    dst_reg: u8,
    /// Source register
    src_reg: u8,
    /// Offset
    offset: i16,
    /// Immediate value
    imm: i32,
    /// Address in the binary
    address: usize,
}

impl SbfInstruction {
    /// Parse an SBF instruction from a byte slice
    fn parse(data: &[u8], address: usize) -> Result<Self> {
        if data.len() < 8 {
            return Err(anyhow!("Instruction data too short"));
        }
        
        let opcode = data[0];
        let dst_reg = (data[1] & 0xf0) >> 4;
        let src_reg = data[1] & 0x0f;
        let offset = i16::from_le_bytes([data[2], data[3]]);
        let imm = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        
        Ok(Self {
            opcode,
            dst_reg,
            src_reg,
            offset,
            imm,
            address,
        })
    }
    
    /// Check if this is a jump instruction
    fn is_jump(&self) -> bool {
        matches!(
            self.opcode,
            opcodes::JA | opcodes::JEQ_REG | opcodes::JEQ_IMM | 
            opcodes::JNE_REG | opcodes::JNE_IMM
        )
    }
    
    /// Check if this is a call instruction
    fn is_call(&self) -> bool {
        self.opcode == opcodes::CALL
    }
    
    /// Check if this is an exit instruction
    fn is_exit(&self) -> bool {
        self.opcode == opcodes::EXIT
    }
    
    /// Check if this is a load instruction
    fn is_load(&self) -> bool {
        matches!(
            self.opcode,
            opcodes::LDXB | opcodes::LDXH | opcodes::LDXW | opcodes::LDXDW
        )
    }
    
    /// Check if this is a store instruction
    fn is_store(&self) -> bool {
        matches!(
            self.opcode,
            opcodes::STB | opcodes::STH | opcodes::STW | opcodes::STDW |
            opcodes::STXB | opcodes::STXH | opcodes::STXW | opcodes::STXDW
        )
    }
    
    /// Get the size of the load/store operation
    fn mem_size(&self) -> Option<usize> {
        match self.opcode {
            opcodes::LDXB | opcodes::STB | opcodes::STXB => Some(1),
            opcodes::LDXH | opcodes::STH | opcodes::STXH => Some(2),
            opcodes::LDXW | opcodes::STW | opcodes::STXW => Some(4),
            opcodes::LDXDW | opcodes::STDW | opcodes::STXDW => Some(8),
            _ => None,
        }
    }
}

/// ELF section
#[derive(Debug, Clone)]
struct ElfSection {
    /// Section name
    name: String,
    /// Section data
    data: Vec<u8>,
    /// Section address
    address: usize,
    /// Section size
    size: usize,
}

/// Basic block in the control flow graph
#[derive(Debug, Clone)]
struct BasicBlock {
    /// Start address
    start: usize,
    /// End address
    end: usize,
    /// Instructions in this block
    instructions: Vec<SbfInstruction>,
    /// Successor blocks
    successors: Vec<usize>,
    /// Predecessor blocks
    predecessors: Vec<usize>,
}

/// Function in the program
#[derive(Debug, Clone)]
struct Function {
    /// Function name
    name: String,
    /// Entry point address
    entry: usize,
    /// Exit points
    exits: Vec<usize>,
    /// Basic blocks in this function
    blocks: Vec<usize>,
}

/// Instruction handler
#[derive(Debug, Clone)]
struct InstructionHandler {
    /// Handler name
    name: String,
    /// Entry point address
    entry: usize,
    /// Discriminator
    discriminator: Option<u8>,
    /// Anchor discriminator (8 bytes)
    anchor_discriminator: Option<[u8; 8]>,
    /// Parameter types
    parameters: Vec<String>,
    /// Required accounts
    accounts: Vec<(String, bool, bool)>, // (name, is_signer, is_writable)
}

/// Results of bytecode analysis
#[derive(Debug)]
pub struct BytecodeAnalysis {
    /// Extracted instructions
    pub instructions: Vec<Instruction>,
    /// Extracted account structures
    pub accounts: Vec<Account>,
    /// Is this an Anchor program?
    pub is_anchor: bool,
    /// Error codes
    pub error_codes: HashMap<u32, String>,
}

/// Analyze program bytecode to extract instruction and account information
pub fn analyze(program_data: &[u8]) -> Result<BytecodeAnalysis> {
    // For backward compatibility with tests
    analyze_with_id(program_data, "unknown")
}

/// Analyze program bytecode with program ID
pub fn analyze_with_id(program_data: &[u8], program_id: &str) -> Result<BytecodeAnalysis> {
    info!("Analyzing program bytecode, size: {} bytes", program_data.len());
    
    if program_data.len() < 8 {
        info!("Program data too small to be a valid Solana program (size: {} bytes)", program_data.len());
        return create_minimal_analysis();
    }
    
    // Check if this is an ELF file
    if program_data.len() >= 4 && 
       program_data[0] == 0x7F && 
       program_data[1] == b'E' && 
       program_data[2] == b'L' && 
       program_data[3] == b'F' {
        info!("Valid ELF file detected");
    } else {
        // Print the first few bytes for debugging
        let prefix = if program_data.len() >= 16 {
            &program_data[0..16]
        } else {
            program_data
        };
        
        let prefix_hex = prefix.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        
        info!("Not a valid ELF file. First bytes: {}", prefix_hex);
        
        // Try to create a minimal analysis anyway
        return create_minimal_analysis();
    }
    
    // Parse ELF sections
    let sections = parse_elf_sections(program_data)
        .context("Failed to parse ELF sections")?;
    
    // Find .text section for code analysis
    let text_section = sections.iter()
        .find(|s| s.name == ".text")
        .ok_or_else(|| anyhow!("No .text section found"))?;
    
    // Find .rodata section for string analysis
    let rodata_section = sections.iter()
        .find(|s| s.name == ".rodata")
        .or_else(|| sections.iter().find(|s| s.name == ".data"));
    
    // Find .symtab section for symbol analysis
    let symtab_section = sections.iter()
        .find(|s| s.name == ".symtab");
    
    // Parse instructions from .text section
    let instructions = parse_instructions(&text_section.data, text_section.address)
        .context("Failed to parse instructions")?;
    
    // Build control flow graph
    let (blocks, functions) = build_control_flow_graph(&instructions)
        .context("Failed to build control flow graph")?;
    
    // Extract strings from .rodata section
    let strings = if let Some(rodata) = rodata_section {
        extract_strings(&rodata.data)
    } else {
        Vec::new()
    };
    
    // Check if this is an Anchor program
    let is_anchor = detect_anchor_program(&instructions, &strings);
    
    // Find instruction handlers
    let handlers = if is_anchor {
        find_anchor_instruction_handlers(&instructions, &blocks, &strings)
    } else {
        find_instruction_handlers(&instructions, &blocks, &functions, &strings)
    };
    
    // Extract error codes
    let error_codes = extract_error_codes(&instructions, &strings);
    
    // Convert to IDL instructions
    let idl_instructions = convert_to_idl_instructions(&handlers, is_anchor);
    
    // Extract account structures
    let accounts = extract_account_structures(&instructions, &strings, is_anchor);
    
    Ok(BytecodeAnalysis {
        instructions: idl_instructions,
        accounts,
        is_anchor,
        error_codes,
    })
}

/// Parse ELF sections from program data
fn parse_elf_sections(program_data: &[u8]) -> Result<Vec<ElfSection>> {
    let mut sections = Vec::new();
    
    // Check ELF header
    if program_data.len() < 64 {
        return Err(anyhow!("Program data too small to be a valid ELF file"));
    }
    
    // Get section header offset (e_shoff)
    let sh_offset = u64::from_le_bytes(program_data[40..48].try_into().unwrap()) as usize;
    
    // Get section header entry size (e_shentsize)
    let sh_entsize = u16::from_le_bytes(program_data[58..60].try_into().unwrap()) as usize;
    
    // Get number of section headers (e_shnum)
    let sh_num = u16::from_le_bytes(program_data[60..62].try_into().unwrap()) as usize;
    
    // Get section header string table index (e_shstrndx)
    let sh_strndx = u16::from_le_bytes(program_data[62..64].try_into().unwrap()) as usize;
    
    if sh_offset == 0 || sh_entsize == 0 || sh_num == 0 {
        return Err(anyhow!("Invalid ELF section header information"));
    }
    
    // Get section header string table
    let str_hdr_offset = sh_offset + sh_strndx * sh_entsize;
    if str_hdr_offset + 24 >= program_data.len() {
        return Err(anyhow!("Invalid section header string table offset"));
    }
    
    let str_offset = u64::from_le_bytes(program_data[str_hdr_offset + 24..str_hdr_offset + 32].try_into().unwrap()) as usize;
    let str_size = u64::from_le_bytes(program_data[str_hdr_offset + 32..str_hdr_offset + 40].try_into().unwrap()) as usize;
    
    if str_offset + str_size > program_data.len() {
        return Err(anyhow!("Invalid section header string table data"));
    }
    
    let str_table = &program_data[str_offset..str_offset + str_size];
    
    // Parse section headers
    for i in 0..sh_num {
        let hdr_offset = sh_offset + i * sh_entsize;
        if hdr_offset + sh_entsize > program_data.len() {
            continue;
        }
        
        // Get section name offset
        let name_offset = u32::from_le_bytes(program_data[hdr_offset..hdr_offset + 4].try_into().unwrap()) as usize;
        
        // Get section offset
        let offset = u64::from_le_bytes(program_data[hdr_offset + 24..hdr_offset + 32].try_into().unwrap()) as usize;
        
        // Get section size
        let size = u64::from_le_bytes(program_data[hdr_offset + 32..hdr_offset + 40].try_into().unwrap()) as usize;
        
        // Get section address
        let address = u64::from_le_bytes(program_data[hdr_offset + 16..hdr_offset + 24].try_into().unwrap()) as usize;
        
        if offset + size > program_data.len() {
            continue;
        }
        
        // Extract section name
        let mut name_end = name_offset;
        while name_end < str_table.len() && str_table[name_end] != 0 {
            name_end += 1;
        }
        
        let name = if name_offset < str_table.len() {
            String::from_utf8_lossy(&str_table[name_offset..name_end]).to_string()
        } else {
            format!("section_{}", i)
        };
        
        // Extract section data
        let data = program_data[offset..offset + size].to_vec();
        
        sections.push(ElfSection {
            name,
            data,
            address,
            size,
        });
    }
    
    if sections.is_empty() {
        return Err(anyhow!("No valid sections found"));
    }
    
    Ok(sections)
}

/// Parse instructions from a byte slice
fn parse_instructions(data: &[u8], base_address: usize) -> Result<Vec<SbfInstruction>> {
    let mut instructions = Vec::new();
    let mut offset = 0;
    
    while offset + 8 <= data.len() {
        let insn = SbfInstruction::parse(&data[offset..offset + 8], base_address + offset)?;
        instructions.push(insn);
        offset += 8;
    }
    
    Ok(instructions)
}

/// Build a control flow graph from instructions
fn build_control_flow_graph(instructions: &[SbfInstruction]) -> Result<(Vec<BasicBlock>, Vec<Function>)> {
    let mut blocks = Vec::new();
    let mut functions = Vec::new();
    
    // Find basic block boundaries
    let mut block_starts = vec![0];
    
    for (i, insn) in instructions.iter().enumerate() {
        if insn.is_jump() {
            // Add the next instruction as a block start
            if i + 1 < instructions.len() {
                block_starts.push(i + 1);
            }
            
            // Add the jump target as a block start
            let target_addr = insn.address + 8 + (insn.offset as isize * 8) as usize;
            let target_idx = instructions.iter().position(|i| i.address == target_addr);
            if let Some(idx) = target_idx {
                block_starts.push(idx);
            }
        } else if insn.is_exit() {
            // Add the next instruction as a block start
            if i + 1 < instructions.len() {
                block_starts.push(i + 1);
            }
        }
    }
    
    // Sort and deduplicate block starts
    block_starts.sort();
    block_starts.dedup();
    
    // Create basic blocks
    for (i, &start) in block_starts.iter().enumerate() {
        let end = if i + 1 < block_starts.len() {
            block_starts[i + 1]
        } else {
            instructions.len()
        };
        
        let start_addr = if start < instructions.len() {
            instructions[start].address
        } else {
            continue;
        };
        
        let end_addr = if end <= instructions.len() && end > 0 {
            instructions[end - 1].address + 8
        } else {
            continue;
        };
        
        let block_instructions = instructions[start..end].to_vec();
        
        let block = BasicBlock {
            start: start_addr,
            end: end_addr,
            instructions: block_instructions,
            successors: Vec::new(),
            predecessors: Vec::new(),
        };
        
        blocks.push(block);
    }
    
    // Store pending updates to avoid borrow checker issues
    let mut pending_successors = Vec::new();
    let mut pending_predecessors = Vec::new();
    
    // Connect blocks
    for (i, block) in blocks.iter().enumerate() {
        if let Some(last_insn) = block.instructions.last() {
            if last_insn.is_jump() {
                // Add the jump target as a successor
                let target_addr = last_insn.address + 8 + (last_insn.offset as isize * 8) as usize;
                
                // Find the block containing this address
                let target_idx = blocks.iter().position(|b| b.start <= target_addr && target_addr < b.end);
                if let Some(idx) = target_idx {
                    pending_successors.push((i, idx));
                    pending_predecessors.push((idx, i));
                }
                
                // For conditional jumps, also add the fall-through block
                if last_insn.opcode != opcodes::JA {
                    if i + 1 < blocks.len() {
                        pending_successors.push((i, i + 1));
                        pending_predecessors.push((i + 1, i));
                    }
                }
            } else if !last_insn.is_exit() {
                // For non-jump, non-exit instructions, add the fall-through block
                if i + 1 < blocks.len() {
                    pending_successors.push((i, i + 1));
                    pending_predecessors.push((i + 1, i));
                }
            }
        }
    }
    
    // Apply the pending updates
    for (block_idx, succ_idx) in pending_successors {
        blocks[block_idx].successors.push(succ_idx);
    }
    
    for (block_idx, pred_idx) in pending_predecessors {
        blocks[block_idx].predecessors.push(pred_idx);
    }
    
    // Identify functions
    // For now, we'll just create a single function for the entire program
    let mut function = Function {
        name: "main".to_string(),
        entry: blocks[0].start,
        exits: Vec::new(),
        blocks: (0..blocks.len()).collect(),
    };
    
    // Find exit points
    for (i, block) in blocks.iter().enumerate() {
        if let Some(last_insn) = block.instructions.last() {
            if last_insn.is_exit() {
                function.exits.push(i);
            }
        }
    }
    
    functions.push(function);
    
    Ok((blocks, functions))
}

/// Extract strings from .rodata section
fn extract_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut start = 0;
    
    while start < data.len() {
        // Find the next null terminator
        if let Some(end) = data[start..].iter().position(|&b| b == 0) {
            if end > 0 {
                // Extract the string
                if let Ok(s) = std::str::from_utf8(&data[start..start + end]) {
                    if s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                        strings.push(s.to_string());
                    }
                }
            }
            
            // Move past the null terminator
            start += end + 1;
        } else {
            // No more null terminators
            break;
        }
    }
    
    strings
}

/// Detect if this is an Anchor program
fn detect_anchor_program(instructions: &[SbfInstruction], strings: &[String]) -> bool {
    // Check for Anchor's characteristic log message pattern
    if strings.iter().any(|s| s.contains("Instruction: ")) {
        return true;
    }
    
    // Check for Anchor's error code patterns
    if strings.iter().any(|s| 
        s.contains("ConstraintMut") || 
        s.contains("ConstraintSigner") || 
        s.contains("ConstraintRentExempt") ||
        s.contains("AccountDiscriminator")
    ) {
        return true;
    }
    
    // Check for Anchor's discriminator generation pattern
    if strings.iter().any(|s| s.contains("global:") || s.contains("account:")) {
        return true;
    }
    
    // Look for 8-byte discriminator patterns
    // This is a more complex check that looks for common Anchor instruction dispatch patterns
    let mut consecutive_comparisons = 0;
    let mut last_comparison_offset = 0;
    
    for (i, insn) in instructions.iter().enumerate() {
        // Look for comparison instructions
        if matches!(insn.opcode, opcodes::JEQ_REG | opcodes::JEQ_IMM | opcodes::JNE_REG | opcodes::JNE_IMM) {
            if last_comparison_offset > 0 && i - last_comparison_offset <= 10 {
                consecutive_comparisons += 1;
                if consecutive_comparisons >= 7 {  // Need 8 bytes, but allow for some flexibility
                    return true;
                }
            } else {
                consecutive_comparisons = 1;
            }
            
            last_comparison_offset = i;
        }
    }
    
    // Look for constraint check patterns
    for window in instructions.windows(5) {
        if is_checking_signer(window) || is_checking_writable(window) || 
           is_checking_rent_exempt(window) || is_checking_discriminator(window) {
            return true;
        }
    }
    
    false
}

/// Find instruction handlers in an Anchor program
fn find_anchor_instruction_handlers(
    instructions: &[SbfInstruction], 
    blocks: &[BasicBlock],
    strings: &[String]
) -> Vec<InstructionHandler> {
    let mut handlers = Vec::new();
    
    // Extract instruction names from strings
    let instruction_names: Vec<_> = strings.iter()
        .filter_map(|s| {
            if s.starts_with("Instruction: ") {
                Some(s[12..].to_string())
            } else {
                None
            }
        })
        .collect();
    
    // Look for discriminator comparisons
    for (i, block) in blocks.iter().enumerate() {
        // Check if this block contains a discriminator comparison
        let mut has_discriminator_check = false;
        let mut discriminator = [0u8; 8];
        
        for window in block.instructions.windows(3) {
            // Look for a pattern like:
            // ldxdw r0, [r1+0]   // Load 8-byte discriminator
            // mov r1, <imm>      // Load immediate value (part of discriminator)
            // jeq r0, r1, +12    // Compare and jump
            
            if window[0].is_load() && 
               window[0].mem_size() == Some(8) && 
               window[1].opcode == opcodes::MOV_IMM && 
               window[2].opcode == opcodes::JEQ_REG {
                
                has_discriminator_check = true;
                
                // Extract the discriminator (this is simplified)
                discriminator[0..4].copy_from_slice(&window[1].imm.to_le_bytes());
                
                // We'd need to track more instructions to get the full 8 bytes
                break;
            }
        }
        
        if has_discriminator_check && i < instruction_names.len() {
            // Create a handler for this instruction
            let name = instruction_names[i].clone();
            
            // Generate the full discriminator using Anchor's algorithm
            let full_discriminator = generate_anchor_discriminator(&name);
            
            let handler = InstructionHandler {
                name,
                entry: block.start,
                discriminator: None,
                anchor_discriminator: Some(full_discriminator),
                parameters: infer_parameters(block),
                accounts: infer_accounts(block),
            };
            
            handlers.push(handler);
        }
    }
    
    handlers
}

/// Generate an Anchor instruction discriminator
fn generate_anchor_discriminator(name: &str) -> [u8; 8] {
    let namespace = format!("global:{}", name);
    let hash_bytes = hash(namespace.as_bytes()).to_bytes();
    let mut result = [0u8; 8];
    result.copy_from_slice(&hash_bytes[..8]);
    result
}

/// Find instruction handlers in a non-Anchor program
fn find_instruction_handlers(
    instructions: &[SbfInstruction],
    blocks: &[BasicBlock],
    functions: &[Function],
    strings: &[String]
) -> Vec<InstructionHandler> {
    let mut handlers = Vec::new();
    
    // Look for instruction dispatch patterns
    for block in blocks {
        // Check if this block contains an instruction dispatch pattern
        let mut has_dispatch = false;
        let mut discriminator = None;
        
        for window in block.instructions.windows(3) {
            // Look for a pattern like:
            // ldxb r0, [r1+0]   // Load discriminator byte
            // jeq r0, <imm>, +12 // Compare and jump if equal
            
            if window[0].is_load() && 
               window[0].mem_size() == Some(1) && 
               window[0].dst_reg == 0 && 
               (window[1].opcode == opcodes::JEQ_IMM || window[1].opcode == opcodes::JNE_IMM) {
                
                has_dispatch = true;
                discriminator = Some(window[1].imm as u8);
                break;
            }
        }
        
        if has_dispatch {
            // Try to find a name for this instruction
            let name = find_instruction_name(block, strings)
                .unwrap_or_else(|| format!("instruction_{}", discriminator.unwrap_or(0)));
            
            let handler = InstructionHandler {
                name,
                entry: block.start,
                discriminator,
                anchor_discriminator: None,
                parameters: infer_parameters(block),
                accounts: infer_accounts(block),
            };
            
            handlers.push(handler);
        }
    }
    
    // If we couldn't find any handlers, create a generic one
    if handlers.is_empty() {
        handlers.push(InstructionHandler {
            name: "process".to_string(),
            entry: 0,
            discriminator: Some(0),
            anchor_discriminator: None,
            parameters: vec!["bytes".to_string()],
            accounts: Vec::new(),
        });
    }
    
    handlers
}

/// Find a name for an instruction handler
fn find_instruction_name(block: &BasicBlock, strings: &[String]) -> Option<String> {
    // Look for log messages that might indicate the instruction name
    for insn in &block.instructions {
        if insn.is_call() && insn.imm as u32 == syscalls::SOL_LOG {
            // This is a call to sol_log, try to find the string being logged
            // This is a simplified approach - in a real implementation, we would
            // track register values to find the string pointer
            
            // Look for common instruction name patterns in strings
            for s in strings {
                let lower = s.to_lowercase();
                for pattern in &[
                    "initialize", "create", "update", "delete", "transfer", "mint", "burn",
                    "approve", "revoke", "freeze", "thaw", "close", "set", "get"
                ] {
                    if lower.contains(pattern) {
                        return Some(s.clone());
                    }
                }
            }
        }
    }
    
    None
}

/// Infer parameter types from a basic block
fn infer_parameters(block: &BasicBlock) -> Vec<String> {
    let mut parameters = Vec::new();
    
    // Look for memory loads that might indicate parameter access
    for window in block.instructions.windows(2) {
        if window[0].is_load() {
            // This is a load instruction, check the size
            if let Some(size) = window[0].mem_size() {
                match size {
                    1 => parameters.push("u8".to_string()),
                    2 => parameters.push("u16".to_string()),
                    4 => parameters.push("u32".to_string()),
                    8 => {
                        // This could be a u64 or a pubkey
                        // Check if it's used in a pubkey-specific way
                        if is_pubkey_usage(&block.instructions, window[0].dst_reg) {
                            parameters.push("pubkey".to_string());
                        } else {
                            parameters.push("u64".to_string());
                        }
                    },
                    _ => {}
                }
            }
        }
    }
    
    // Deduplicate parameters
    parameters.sort();
    parameters.dedup();
    
    // If we couldn't infer any parameters, add a generic one
    if parameters.is_empty() {
        parameters.push("bytes".to_string());
    }
    
    parameters
}

/// Check if a register is used as a pubkey
fn is_pubkey_usage(instructions: &[SbfInstruction], reg: u8) -> bool {
    for insn in instructions {
        if insn.is_call() {
            // Check if this is a call to a pubkey-related syscall
            let syscall_hash = insn.imm as u32;
            if syscall_hash == syscalls::SOL_LOG_PUBKEY ||
               syscall_hash == syscalls::SOL_CREATE_PROGRAM_ADDRESS ||
               syscall_hash == syscalls::SOL_TRY_FIND_PROGRAM_ADDRESS {
                // This is a pubkey-related syscall
                // Check if our register is used as an argument
                // This is a simplified approach - in a real implementation, we would
                // track register values more carefully
                if insn.src_reg == reg || insn.dst_reg == reg {
                    return true;
                }
            }
        }
    }
    
    false
}

/// Infer account usage from a basic block
fn infer_accounts(block: &BasicBlock) -> Vec<(String, bool, bool)> {
    let mut accounts = Vec::new();
    let mut account_constraints = HashMap::new();
    
    // Look for account access patterns
    for (i, window) in block.instructions.windows(3).enumerate() {
        if window[0].is_load() && window[0].mem_size() == Some(8) {
            // This might be loading an account pointer
            let reg = window[0].dst_reg;
            
            // Check if the next instructions access fields of this account
            if i + 3 < block.instructions.len() {
                let next_insn = &block.instructions[i + 3];
                if next_insn.is_load() && next_insn.src_reg == reg {
                    // This is accessing a field of the account
                    // Try to determine if it's checking is_signer or is_writable
                    let is_signer = is_checking_signer(&block.instructions[i+3..]);
                    let is_writable = is_checking_writable(&block.instructions[i+3..]);
                    
                    let account_idx = accounts.len();
                    let account_name = format!("account_{}", account_idx);
                    
                    accounts.push((account_name.clone(), is_signer, is_writable));
                    account_constraints.insert(account_name, detect_constraints(&block.instructions[i+3..]));
                }
            }
        }
    }
    
    // Look for Anchor-specific account validation patterns
    for window in block.instructions.windows(5) {
        // Look for discriminator checks (first 8 bytes of account data)
        if is_checking_discriminator(window) {
            // This is likely an Anchor account validation
            let account_idx = accounts.len();
            let account_name = format!("account_{}", account_idx);
            
            // Anchor accounts are typically required to be mutable
            accounts.push((account_name.clone(), false, true));
            
            let mut constraints = HashSet::new();
            constraints.insert("discriminator".to_string());
            account_constraints.insert(account_name, constraints);
        }
    }
    
    // If we couldn't infer any accounts, add some generic ones
    if accounts.is_empty() {
        accounts.push(("authority".to_string(), true, false));
        accounts.push(("data".to_string(), false, true));
    }
    
    // Update account properties based on constraints
    accounts = accounts.into_iter().map(|(name, is_signer, is_writable)| {
        if let Some(constraints) = account_constraints.get(&name) {
            let is_signer = is_signer || constraints.contains("signer");
            let is_writable = is_writable || constraints.contains("mut");
            (name, is_signer, is_writable)
        } else {
            (name, is_signer, is_writable)
        }
    }).collect();
    
    accounts
}

/// Detect constraints on an account
fn detect_constraints(instructions: &[SbfInstruction]) -> HashSet<String> {
    let mut constraints = HashSet::new();
    
    // Look for common constraint check patterns
    for window in instructions.windows(4) {
        // Check for signer constraint
        if is_checking_signer(window) {
            constraints.insert("signer".to_string());
        }
        
        // Check for mut constraint
        if is_checking_writable(window) {
            constraints.insert("mut".to_string());
        }
        
        // Check for rent-exempt constraint
        if is_checking_rent_exempt(window) {
            constraints.insert("rent-exempt".to_string());
        }
        
        // Check for owner constraint
        if is_checking_owner(window) {
            constraints.insert("owner".to_string());
        }
        
        // Check for initialized constraint
        if is_checking_initialized(window) {
            constraints.insert("initialized".to_string());
        }
    }
    
    constraints
}

/// Check if the instructions are checking a discriminator
fn is_checking_discriminator(instructions: &[SbfInstruction]) -> bool {
    // Look for a pattern that loads 8 bytes and compares them
    if instructions.len() >= 3 {
        if instructions[0].is_load() && 
           instructions[0].mem_size() == Some(8) &&
           (instructions[1].opcode == opcodes::JEQ_REG || 
            instructions[1].opcode == opcodes::JEQ_IMM ||
            instructions[1].opcode == opcodes::JNE_REG ||
            instructions[1].opcode == opcodes::JNE_IMM) {
            return true;
        }
    }
    
    false
}

/// Check if the instructions are checking the rent-exempt status
fn is_checking_rent_exempt(instructions: &[SbfInstruction]) -> bool {
    // This is a simplified check - in reality, we'd need to track
    // the flow of data more carefully to identify rent-exempt checks
    
    // Look for calls to sol_invoke_signed with system program
    for window in instructions.windows(3) {
        if window[0].is_call() && 
           (window[0].imm as u32 == syscalls::SOL_INVOKE_SIGNED_C || 
            window[0].imm as u32 == syscalls::SOL_INVOKE_SIGNED_RUST) {
            // This might be a call to check rent exemption
            return true;
        }
    }
    
    false
}

/// Check if the instructions are checking the owner of an account
fn is_checking_owner(instructions: &[SbfInstruction]) -> bool {
    // Look for a pattern that loads the owner field and compares it
    for window in instructions.windows(4) {
        if window[0].is_load() && 
           window[0].mem_size() == Some(8) && 
           window[0].offset == 8 && // Owner field is typically at offset 8
           (window[1].opcode == opcodes::JEQ_REG || 
            window[1].opcode == opcodes::JEQ_IMM ||
            window[1].opcode == opcodes::JNE_REG ||
            window[1].opcode == opcodes::JNE_IMM) {
            return true;
        }
    }
    
    false
}

/// Check if the instructions are checking if an account is initialized
fn is_checking_initialized(instructions: &[SbfInstruction]) -> bool {
    // Look for a pattern that checks if data size > 0
    for window in instructions.windows(3) {
        if window[0].is_load() && 
           window[0].mem_size() == Some(8) && 
           window[0].offset == 16 && // Data size field is typically at offset 16
           (window[1].opcode == opcodes::JEQ_IMM || 
            window[1].opcode == opcodes::JNE_IMM) &&
           window[1].imm == 0 {
            return true;
        }
    }
    
    false
}

/// Check if the instructions are checking the is_signer flag
fn is_checking_signer(instructions: &[SbfInstruction]) -> bool {
    for window in instructions.windows(3) {
        if window[0].is_load() && window[0].mem_size() == Some(1) {
            // This might be loading the is_signer flag
            // Check if it's followed by a comparison
            if window[1].opcode == opcodes::JEQ_IMM || window[1].opcode == opcodes::JNE_IMM {
                return true;
            }
        }
    }
    
    false
}

/// Check if the instructions are checking the is_writable flag
fn is_checking_writable(instructions: &[SbfInstruction]) -> bool {
    for window in instructions.windows(3) {
        if window[0].is_load() && window[0].mem_size() == Some(1) {
            // This might be loading the is_writable flag
            // Check if it's followed by a comparison
            if window[1].opcode == opcodes::JEQ_IMM || window[1].opcode == opcodes::JNE_IMM {
                return true;
            }
        }
    }
    
    false
}

/// Extract error codes from instructions and strings
fn extract_error_codes(instructions: &[SbfInstruction], strings: &[String]) -> HashMap<u32, String> {
    let mut error_codes = HashMap::new();
    
    // Look for error code patterns in strings
    for s in strings {
        // Check if this string looks like an error message
        if s.contains("Error") || s.contains("Failed") || s.contains("Invalid") {
            // Try to find a nearby error code
            for window in instructions.windows(2) {
                if window[0].opcode == opcodes::MOV_IMM && window[1].is_call() {
                    // This might be setting an error code before calling sol_panic
                    if window[1].imm as u32 == syscalls::SOL_PANIC {
                        let error_code = window[0].imm as u32;
                        error_codes.insert(error_code, s.clone());
                    }
                }
            }
        }
    }
    
    // Look for Anchor error code patterns
    // Anchor error codes are typically defined in a specific range
    for window in instructions.windows(3) {
        if window[0].opcode == opcodes::MOV_IMM && 
           (window[0].imm >= 100 && window[0].imm < 10000) && // Typical Anchor error code range
           window[1].is_call() && 
           window[1].imm as u32 == syscalls::SOL_PANIC {
            
            let error_code = window[0].imm as u32;
            
            // Try to find a matching error message
            let error_message = find_error_message_for_code(error_code, strings)
                .unwrap_or_else(|| format!("Error code {}", error_code));
            
            error_codes.insert(error_code, error_message);
        }
    }
    
    // Add common Anchor error codes if we detect it's an Anchor program
    if strings.iter().any(|s| s.contains("Anchor") || s.contains("anchor")) {
        // Anchor program constraint errors (2000-2999)
        if !error_codes.contains_key(&2000) { error_codes.insert(2000, "ConstraintMut".to_string()); }
        if !error_codes.contains_key(&2001) { error_codes.insert(2001, "ConstraintHasOne".to_string()); }
        if !error_codes.contains_key(&2002) { error_codes.insert(2002, "ConstraintSigner".to_string()); }
        if !error_codes.contains_key(&2003) { error_codes.insert(2003, "ConstraintRaw".to_string()); }
        if !error_codes.contains_key(&2004) { error_codes.insert(2004, "ConstraintOwner".to_string()); }
        if !error_codes.contains_key(&2005) { error_codes.insert(2005, "ConstraintRentExempt".to_string()); }
        if !error_codes.contains_key(&2006) { error_codes.insert(2006, "ConstraintSeeds".to_string()); }
        if !error_codes.contains_key(&2007) { error_codes.insert(2007, "ConstraintExecutable".to_string()); }
        if !error_codes.contains_key(&2008) { error_codes.insert(2008, "ConstraintState".to_string()); }
        if !error_codes.contains_key(&2009) { error_codes.insert(2009, "ConstraintAssociated".to_string()); }
        if !error_codes.contains_key(&2010) { error_codes.insert(2010, "ConstraintAssociatedInit".to_string()); }
        if !error_codes.contains_key(&2011) { error_codes.insert(2011, "ConstraintClose".to_string()); }
        if !error_codes.contains_key(&2012) { error_codes.insert(2012, "ConstraintAddress".to_string()); }
        if !error_codes.contains_key(&2013) { error_codes.insert(2013, "ConstraintZero".to_string()); }
        if !error_codes.contains_key(&2014) { error_codes.insert(2014, "ConstraintTokenMint".to_string()); }
        if !error_codes.contains_key(&2015) { error_codes.insert(2015, "ConstraintTokenOwner".to_string()); }
        if !error_codes.contains_key(&2016) { error_codes.insert(2016, "ConstraintMintMintAuthority".to_string()); }
        if !error_codes.contains_key(&2017) { error_codes.insert(2017, "ConstraintMintFreezeAuthority".to_string()); }
        if !error_codes.contains_key(&2018) { error_codes.insert(2018, "ConstraintMintDecimals".to_string()); }
        if !error_codes.contains_key(&2019) { error_codes.insert(2019, "ConstraintSpace".to_string()); }
        
        // Anchor program account errors (3000-3999)
        if !error_codes.contains_key(&3000) { error_codes.insert(3000, "AccountDiscriminatorAlreadySet".to_string()); }
        if !error_codes.contains_key(&3001) { error_codes.insert(3001, "AccountDiscriminatorNotFound".to_string()); }
        if !error_codes.contains_key(&3002) { error_codes.insert(3002, "AccountDiscriminatorMismatch".to_string()); }
        if !error_codes.contains_key(&3003) { error_codes.insert(3003, "AccountDidNotDeserialize".to_string()); }
        if !error_codes.contains_key(&3004) { error_codes.insert(3004, "AccountDidNotSerialize".to_string()); }
        if !error_codes.contains_key(&3005) { error_codes.insert(3005, "AccountNotEnoughKeys".to_string()); }
        if !error_codes.contains_key(&3006) { error_codes.insert(3006, "AccountNotMutable".to_string()); }
        if !error_codes.contains_key(&3007) { error_codes.insert(3007, "AccountOwnedByWrongProgram".to_string()); }
        if !error_codes.contains_key(&3008) { error_codes.insert(3008, "InvalidProgramId".to_string()); }
        if !error_codes.contains_key(&3009) { error_codes.insert(3009, "InvalidProgramExecutable".to_string()); }
        if !error_codes.contains_key(&3010) { error_codes.insert(3010, "AccountNotSigner".to_string()); }
        if !error_codes.contains_key(&3011) { error_codes.insert(3011, "AccountNotSystemOwned".to_string()); }
        if !error_codes.contains_key(&3012) { error_codes.insert(3012, "AccountNotInitialized".to_string()); }
        if !error_codes.contains_key(&3013) { error_codes.insert(3013, "AccountNotProgramData".to_string()); }
        if !error_codes.contains_key(&3014) { error_codes.insert(3014, "AccountNotAssociatedTokenAccount".to_string()); }
        if !error_codes.contains_key(&3015) { error_codes.insert(3015, "AccountSysvarMismatch".to_string()); }
        if !error_codes.contains_key(&3016) { error_codes.insert(3016, "AccountReallocExceedsLimit".to_string()); }
        if !error_codes.contains_key(&3017) { error_codes.insert(3017, "AccountDuplicateReallocs".to_string()); }
    }
    
    error_codes
}

/// Find an error message for a specific error code
fn find_error_message_for_code(code: u32, strings: &[String]) -> Option<String> {
    // Look for strings that might be error messages for this code
    for s in strings {
        // Check for common error message patterns
        if s.contains(&format!("Error {}", code)) || 
           s.contains(&format!("Error: {}", code)) ||
           s.contains(&format!("Error code {}", code)) {
            return Some(s.clone());
        }
        
        // Check for Anchor-style error messages
        if (code >= 2000 && code < 3000) && s.contains("Constraint") {
            return Some(s.clone());
        }
        
        if (code >= 3000 && code < 4000) && s.contains("Account") {
            return Some(s.clone());
        }
    }
    
    None
}

/// Convert instruction handlers to IDL instructions
fn convert_to_idl_instructions(handlers: &[InstructionHandler], is_anchor: bool) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    
    for handler in handlers {
        let mut instruction = Instruction::new(handler.name.clone(), handler.discriminator.unwrap_or(0));
        
        // Add discriminator for Anchor programs
        if is_anchor {
            instruction.discriminator = handler.anchor_discriminator;
        }
        
        // Add parameters
        for (i, param_type) in handler.parameters.iter().enumerate() {
            instruction.add_arg(format!("arg_{}", i), param_type.clone());
        }
        
        // Add accounts
        for (name, is_signer, is_writable) in &handler.accounts {
            instruction.add_account(name.clone(), *is_signer, *is_writable, false);
        }
        
        instructions.push(instruction);
    }
    
    instructions
}

/// Extract account structures from instructions and strings
fn extract_account_structures(
    instructions: &[SbfInstruction], 
    strings: &[String],
    is_anchor: bool
) -> Vec<Account> {
    let mut accounts = Vec::new();
    
    // Look for account structure patterns in strings
    let account_names: Vec<_> = strings.iter()
        .filter(|s| {
            s.contains("Account") || s.contains("State") || 
            s.contains("Config") || s.contains("Data")
        })
        .cloned()
        .collect();
    
    // Extract discriminators for Anchor accounts
    let discriminators = if is_anchor {
        extract_anchor_discriminators(instructions)
    } else {
        HashMap::new()
    };
    
    for name in account_names {
        let mut account = Account::new(name.clone(), "account".to_string());
        
        // Add discriminator if this is an Anchor account
        if is_anchor {
            if let Some(disc) = discriminators.get(&name) {
                account.set_discriminator(disc.clone());
            }
        }
        
        // Add fields based on common patterns
        if name.to_lowercase().contains("mint") {
            account.add_field("mint_authority".to_string(), "pubkey".to_string(), 0);
            account.add_field("supply".to_string(), "u64".to_string(), 32);
            account.add_field("decimals".to_string(), "u8".to_string(), 40);
        } else if name.to_lowercase().contains("token") {
            account.add_field("mint".to_string(), "pubkey".to_string(), 0);
            account.add_field("owner".to_string(), "pubkey".to_string(), 32);
            account.add_field("amount".to_string(), "u64".to_string(), 64);
        } else {
            // Generic account fields
            account.add_field("owner".to_string(), "pubkey".to_string(), 0);
            account.add_field("data".to_string(), "bytes".to_string(), 32);
        }
        
        accounts.push(account);
    }
    
    // If we couldn't find any accounts, add a generic one
    if accounts.is_empty() {
        let mut account = Account::new("State".to_string(), "state".to_string());
        account.add_field("data".to_string(), "bytes".to_string(), 0);
        accounts.push(account);
    }
    
    accounts
}

/// Extract Anchor account discriminators
fn extract_anchor_discriminators(instructions: &[SbfInstruction]) -> HashMap<String, Vec<u8>> {
    let mut discriminators = HashMap::new();
    
    // Look for discriminator generation patterns
    for window in instructions.windows(8) {
        // Look for a pattern that generates a discriminator
        // This is a simplified approach - in reality, we'd need to track
        // the flow of data more carefully
        
        // Check if this looks like a call to hash("account:<name>")
        if window[0].opcode == opcodes::MOV_IMM && 
           window[1].opcode == opcodes::MOV_IMM && 
           window[2].opcode == opcodes::MOV_IMM && 
           window[3].opcode == opcodes::MOV_IMM {
            
            // This might be loading a string like "account:MyAccount"
            // Extract the bytes and try to form a string
            let bytes = [
                window[0].imm as u8, (window[0].imm >> 8) as u8, (window[0].imm >> 16) as u8, (window[0].imm >> 24) as u8,
                window[1].imm as u8, (window[1].imm >> 8) as u8, (window[1].imm >> 16) as u8, (window[1].imm >> 24) as u8,
                window[2].imm as u8, (window[2].imm >> 8) as u8, (window[2].imm >> 16) as u8, (window[2].imm >> 24) as u8,
                window[3].imm as u8, (window[3].imm >> 8) as u8, (window[3].imm >> 16) as u8, (window[3].imm >> 24) as u8,
            ];
            
            if let Ok(s) = std::str::from_utf8(&bytes) {
                if s.starts_with("account:") {
                    let account_name = s[8..].to_string();
                    
                    // Generate the discriminator using Anchor's algorithm
                    let hash_bytes = hash(s.as_bytes()).to_bytes();
                    let mut discriminator = Vec::new();
                    discriminator.extend_from_slice(&hash_bytes[..8]);
                    
                    discriminators.insert(account_name, discriminator);
                }
            }
        }
    }
    
    discriminators
}

/// Create a minimal analysis when we can't analyze the program
fn create_minimal_analysis() -> Result<BytecodeAnalysis> {
    info!("Creating minimal bytecode analysis");
    
    // Create a generic instruction
    let mut instruction = Instruction::new("process".to_string(), 0);
    instruction.add_arg("data".to_string(), "bytes".to_string());
    
    // Create a generic account
    let mut account = Account::new("State".to_string(), "state".to_string());
    account.add_field("data".to_string(), "bytes".to_string(), 0);
    
    Ok(BytecodeAnalysis {
        instructions: vec![instruction],
        accounts: vec![account],
        is_anchor: false,
        error_codes: HashMap::new(),
    })
}

/// Find instruction dispatch points in the code
fn find_instruction_dispatch(text_section: &[u8]) -> Vec<(usize, u8)> {
    let mut dispatch_points = Vec::new();
    
    // Parse instructions
    let instructions = match parse_instructions(text_section, 0) {
        Ok(insns) => insns,
        Err(_) => return dispatch_points,
    };
    
    // Look for instruction dispatch patterns
    for (i, window) in instructions.windows(3).enumerate() {
        // Look for a pattern like:
        // ldxb r0, [r1+0]   // Load discriminator byte
        // jeq r0, <imm>, +12 // Compare and jump if equal
        
        if window[0].is_load() && 
           window[0].mem_size() == Some(1) && 
           window[0].dst_reg == 0 && 
           (window[1].opcode == opcodes::JEQ_IMM || window[1].opcode == opcodes::JNE_IMM) {
            
            let discriminator = window[1].imm as u8;
            let offset = i;
            
            dispatch_points.push((offset, discriminator));
        }
    }
    
    dispatch_points
}

/// Find byte comparisons in the code
fn find_byte_comparisons(code: &[u8]) -> Vec<(usize, u8)> {
    let mut comparisons = Vec::new();
    
    // Parse instructions
    let instructions = match parse_instructions(code, 0) {
        Ok(insns) => insns,
        Err(_) => return comparisons,
    };
    
    // Look for byte comparison patterns
    for (i, window) in instructions.windows(2).enumerate() {
        // Look for a pattern like:
        // jeq r0, <imm>, +12 // Compare and jump if equal
        
        if (window[0].opcode == opcodes::JEQ_IMM || window[0].opcode == opcodes::JNE_IMM) {
            let value = window[0].imm as u8;
            let offset = i;
            
            comparisons.push((offset, value));
        }
    }
    
    comparisons
}

/// Find pattern in binary data
fn find_pattern(data: &[u8], pattern: &[u8]) -> bool {
    data.windows(pattern.len()).any(|window| window == pattern)
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

/// Represents a relocation entry in an ELF file
#[derive(Debug, Clone)]
pub struct RelocationEntry {
    pub offset: u64,      // Location to apply the relocation
    pub symbol_index: u32, // Symbol table index
    pub r_type: u32,      // Relocation type
    pub addend: i64,      // Optional addend (for RELA type)
}

/// Represents a symbol from the ELF symbol table
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub binding: SymbolBinding,
    pub symbol_type: SymbolType,
    pub section_index: u16,
}

/// Symbol binding (local, global, weak)
#[derive(Debug, Clone, PartialEq)]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
    Unknown(u8),
}

/// Symbol type (object, function, section, etc.)
#[derive(Debug, Clone, PartialEq)]
pub enum SymbolType {
    NoType,
    Object,
    Function,
    Section,
    File,
    Common,
    TLS,
    Unknown(u8),
}

/// Represents a dynamic entry in the ELF file
#[derive(Debug, Clone)]
pub struct DynamicEntry {
    pub tag: DynamicTag,
    pub value: u64,
}

/// Dynamic entry tag types
#[derive(Debug, Clone, PartialEq)]
pub enum DynamicTag {
    Null,
    Needed,
    PltRelSize,
    Hash,
    StrTab,
    SymTab,
    Rela,
    RelaSize,
    RelaEnt,
    StrSize,
    SymEnt,
    Init,
    Fini,
    SoName,
    RPath,
    Symbolic,
    Rel,
    RelSize,
    RelEnt,
    PltRel,
    Debug,
    TextRel,
    JmpRel,
    BindNow,
    InitArray,
    FiniArray,
    InitArraySize,
    FiniArraySize,
    RunPath,
    Flags,
    Other(u64),
}

/// Errors that can occur during ELF analysis
#[derive(Debug, thiserror::Error)]
pub enum ElfError {
    #[error("Failed to open ELF file: {0}")]
    OpenError(String),
    
    #[error("Invalid ELF file: {0}")]
    InvalidElf(String),
    
    #[error("Invalid section: {0}")]
    InvalidSection(String),
    
    #[error("Invalid symbol: {0}")]
    InvalidSymbol(String),
    
    #[error("Invalid relocation: {0}")]
    InvalidRelocation(String),
    
    #[error("Invalid dynamic entry: {0}")]
    InvalidDynamic(String),
    
    #[error("Unsupported ELF format: {0}")]
    UnsupportedFormat(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Add this struct to store section information
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub offset: u64,
    pub section_type: u32,
    pub flags: u64,
}

/// Add this struct to store ELF analysis results
#[derive(Debug)]
pub struct ElfAnalysisResult {
    pub sections: Vec<SectionInfo>,
    pub symbols: Vec<Symbol>,
    pub functions: Vec<Symbol>,
    pub relocations: HashMap<String, Vec<RelocationEntry>>,
    pub dynamic_entries: Vec<DynamicEntry>,
    pub dependencies: Vec<String>,
}

/// Add this struct for the ElfAnalyzer
pub struct ElfAnalyzer<'a> {
    elf_file: Elf<'a>,
    data: &'a [u8],
}

impl<'a> ElfAnalyzer<'a> {
    /// Create a new ELF analyzer from a file path
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, ElfError> {
        let file = File::open(path).map_err(|e| ElfError::OpenError(e.to_string()))?;
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(|e| ElfError::IoError(e))?;
        
        // Create a new owned ElfAnalyzer with the buffer
        Self::from_bytes(&buffer)
    }
    
    /// Create a new ELF analyzer from bytes
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ElfError> {
        if data.len() < 4 {
            return Err(ElfError::InvalidElf("File too small".to_string()));
        }
        
        let elf_file = Elf::parse(data).map_err(|e| ElfError::InvalidElf(format!("Failed to parse ELF file: {}", e)))?;
        
        // Validate architecture
        let arch = match elf_file.header.e_machine {
            EM_BPF => "BPF",
            EM_X86_64 => "x86_64",
            EM_AARCH64 => "AArch64",
            other => return Err(ElfError::UnsupportedFormat(format!("Unsupported architecture: {}", other))),
        };
        
        // Validate ELF class (32-bit or 64-bit)
        let class = match elf_file.header.e_ident[4] { // EI_CLASS is index 4
            1 => "32-bit", // ELFCLASS32 is 1
            2 => "64-bit", // ELFCLASS64 is 2
            other => return Err(ElfError::UnsupportedFormat(format!("Unsupported ELF class: {}", other))),
        };
        
        // Validate ELF data encoding
        let encoding = match elf_file.header.e_ident[5] { // EI_DATA is index 5
            1 => "little-endian", // ELFDATA2LSB is 1
            2 => "big-endian", // ELFDATA2MSB is 2
            other => return Err(ElfError::UnsupportedFormat(format!("Unsupported data encoding: {}", other))),
        };
        
        Ok(Self {
            elf_file,
            data,
        })
    }
    
    /// Parse the symbol table and extract function names and addresses
    pub fn parse_symbols(&self) -> Result<Vec<Symbol>, ElfError> {
        let mut symbols = Vec::new();
        
        // Find the symbol table section
        let symtab_section = self.elf_file.section_headers.iter()
            .find(|&section| section.sh_type == SHT_SYMTAB);
        
        if let Some(symtab) = symtab_section {
            // Use goblin's built-in symbol table parsing
            for sym in self.elf_file.syms.iter() {
                let name = self.elf_file.strtab.get_at(sym.st_name)
                    .unwrap_or_default()
                    .to_string();
                
                // Extract binding and type from st_info
                let binding = match (sym.st_info >> 4) & 0xf {
                    0 => SymbolBinding::Local,
                    1 => SymbolBinding::Global,
                    2 => SymbolBinding::Weak,
                    other => SymbolBinding::Unknown(other),
                };
                
                let symbol_type = match sym.st_info & 0xf {
                    0 => SymbolType::NoType,
                    1 => SymbolType::Object,
                    2 => SymbolType::Function,
                    3 => SymbolType::Section,
                    4 => SymbolType::File,
                    5 => SymbolType::Common,
                    6 => SymbolType::TLS,
                    other => SymbolType::Unknown(other),
                };
                
                symbols.push(Symbol {
                    name,
                    address: sym.st_value,
                    size: sym.st_size,
                    binding,
                    symbol_type,
                    section_index: sym.st_shndx as u16,
                });
            }
        }
        
        Ok(symbols)
    }
    
    /// Get all functions from the symbol table
    pub fn get_functions(&self) -> Result<Vec<Symbol>, ElfError> {
        let symbols = self.parse_symbols()?;
        Ok(symbols.into_iter()
            .filter(|sym| sym.symbol_type == SymbolType::Function)
            .collect())
    }
    
    /// Parse relocation sections (.rel and .rela)
    pub fn parse_relocations(&self) -> Result<HashMap<String, Vec<RelocationEntry>>, ElfError> {
        let mut relocations = HashMap::new();
        
        // Use goblin's built-in relocation parsing
        for (section_name, rel_entries) in &self.elf_file.shdr_relocs {
            let mut entries = Vec::new();
            
            for rel in rel_entries {
                entries.push(RelocationEntry {
                    offset: rel.r_offset,
                    symbol_index: rel.r_sym as u32,
                    r_type: rel.r_type,
                    addend: rel.r_addend.unwrap_or(0),
                });
            }
            
            relocations.insert(section_name.to_string(), entries);
        }
        
        Ok(relocations)
    }
    
    /// Parse the dynamic section
    pub fn parse_dynamic_section(&self) -> Result<Vec<DynamicEntry>, ElfError> {
        let mut dynamic_entries = Vec::new();
        
        // Use goblin's built-in dynamic section parsing
        for dyn_entry_opt in &self.elf_file.dynamic {
            if let Some(dyn_entry) = dyn_entry_opt {
                // Map tag to enum
                let tag = match dyn_entry.d_tag {
                    DT_NULL => DynamicTag::Null,
                    // ... other tags
                    _ => DynamicTag::Other(dyn_entry.d_tag),
                };
                
                dynamic_entries.push(DynamicEntry {
                    tag,
                    value: dyn_entry.d_val,
                });
                
                // Stop at the end of the dynamic section (DT_NULL)
                if tag == DynamicTag::Null {
                    break;
                }
            }
        }
        
        Ok(dynamic_entries)
    }
    
    /// Get shared library dependencies
    pub fn get_dependencies(&self) -> Result<Vec<String>, ElfError> {
        let mut dependencies = Vec::new();
        
        // Use goblin's built-in library parsing
        for lib in &self.elf_file.libraries {
            dependencies.push(lib.to_string());
        }
        
        Ok(dependencies)
    }
    
    /// Parse all sections in the ELF file
    pub fn parse_sections(&self) -> Result<Vec<SectionInfo>, ElfError> {
        let mut sections = Vec::new();
        
        for (i, section_header) in self.elf_file.section_headers.iter().enumerate() {
            let name = self.elf_file.shdr_strtab.get_at(section_header.sh_name)
                .unwrap_or_default()
                .to_string();
            
            sections.push(SectionInfo {
                name,
                address: section_header.sh_addr,
                size: section_header.sh_size,
                offset: section_header.sh_offset,
                section_type: section_header.sh_type,
                flags: section_header.sh_flags,
            });
        }
        
        Ok(sections)
    }
    
    /// Perform a comprehensive analysis of the ELF file
    pub fn analyze(&self) -> Result<ElfAnalysisResult, ElfError> {
        // Validate the ELF file first
        self.validate()?;
        
        // Parse all relevant sections
        let sections = self.parse_sections()?;
        let symbols = self.parse_symbols()?;
        let relocations = self.parse_relocations()?;
        let dynamic_entries = self.parse_dynamic_section()?;
        let dependencies = self.get_dependencies().unwrap_or_default();
        
        // Extract functions
        let functions = symbols.iter()
            .filter(|sym| sym.symbol_type == SymbolType::Function)
            .cloned()
            .collect();
        
        Ok(ElfAnalysisResult {
            sections,
            symbols,
            functions,
            relocations,
            dynamic_entries,
            dependencies,
        })
    }

    /// Validate the ELF file structure
    pub fn validate(&self) -> Result<(), ElfError> {
        // Validate architecture
        let arch = match self.elf_file.header.e_machine {
            EM_BPF => "BPF",
            EM_X86_64 => "x86_64",
            EM_AARCH64 => "AArch64",
            other => return Err(ElfError::UnsupportedFormat(format!("Unsupported architecture: {}", other))),
        };
        
        // Validate ELF class (32-bit or 64-bit)
        let class = match self.elf_file.header.e_ident[4] { // EI_CLASS is index 4
            1 => "32-bit", // ELFCLASS32 is 1
            2 => "64-bit", // ELFCLASS64 is 2
            other => return Err(ElfError::UnsupportedFormat(format!("Unsupported ELF class: {}", other))),
        };
        
        // Validate ELF data encoding
        let encoding = match self.elf_file.header.e_ident[5] { // EI_DATA is index 5
            1 => "little-endian", // ELFDATA2LSB is 1
            2 => "big-endian", // ELFDATA2MSB is 2
            other => return Err(ElfError::UnsupportedFormat(format!("Unsupported data encoding: {}", other))),
        };
        
        // Check for section headers
        if self.elf_file.section_headers.is_empty() {
            return Err(ElfError::InvalidElf("No section headers found".to_string()));
        }
        
        // Check for program headers if it's an executable
        if self.elf_file.header.e_type == elf::header::ET_EXEC && self.elf_file.program_headers.is_empty() {
            return Err(ElfError::InvalidElf("No program headers found for executable".to_string()));
        }
        
        // Validate section header string table
        if self.elf_file.header.e_shstrndx as usize >= self.elf_file.section_headers.len() {
            return Err(ElfError::InvalidElf("Invalid section header string table index".to_string()));
        }
        
        // Validate section sizes and offsets
        for (i, section) in self.elf_file.section_headers.iter().enumerate() {
            if section.sh_offset as usize + section.sh_size as usize > self.data.len() {
                return Err(ElfError::InvalidSection(format!(
                    "Section {} extends beyond file size (offset: {}, size: {})",
                    i, section.sh_offset, section.sh_size
                )));
            }
        }
        
        Ok(())
    }
}

/// Recognize common instruction patterns in SBF bytecode
fn recognize_instruction_patterns(instructions: &[SbfInstruction]) -> Vec<RecognizedPattern> {
    let mut patterns = Vec::new();
    
    // Scan for instruction windows to identify patterns
    for window in instructions.windows(5) {
        // Check for syscall patterns
        if let Some(pattern) = identify_syscall_pattern(window) {
            patterns.push(pattern);
            continue;
        }
        
        // Check for account validation patterns
        if let Some(pattern) = identify_account_validation_pattern(window) {
            patterns.push(pattern);
            continue;
        }
        
        // Check for data serialization/deserialization patterns
        if let Some(pattern) = identify_serialization_pattern(window) {
            patterns.push(pattern);
            continue;
        }
        
        // Check for PDA derivation patterns
        if let Some(pattern) = identify_pda_pattern(window) {
            patterns.push(pattern);
            continue;
        }
    }
    
    patterns
}

/// Identify syscall patterns
fn identify_syscall_pattern(window: &[SbfInstruction]) -> Option<RecognizedPattern> {
    // Look for call instruction with syscall hash
    if window[0].opcode == opcodes::CALL {
        match window[0].imm as u32 {
            // Account-related syscalls
            syscalls::SOL_INVOKE_SIGNED_C | syscalls::SOL_INVOKE_SIGNED_RUST => {
                return Some(RecognizedPattern::CrossProgramInvocation);
            },
            
            // PDA-related syscalls
            syscalls::SOL_CREATE_PROGRAM_ADDRESS => {
                return Some(RecognizedPattern::PdaVerification);
            },
            syscalls::SOL_TRY_FIND_PROGRAM_ADDRESS => {
                return Some(RecognizedPattern::PdaDerivation);
            },
            
            // Logging syscalls
            syscalls::SOL_LOG | syscalls::SOL_LOG_64_ => {
                return Some(RecognizedPattern::Logging);
            },
            
            // Crypto syscalls
            syscalls::SOL_SHA256 | syscalls::SOL_KECCAK256 | syscalls::SOL_BLAKE3 => {
                return Some(RecognizedPattern::Hashing);
            },
            syscalls::SOL_SECP256K1_RECOVER => {
                return Some(RecognizedPattern::Signature);
            },
            
            // Return data syscalls
            syscalls::SOL_SET_RETURN_DATA => {
                return Some(RecognizedPattern::ReturnData);
            },
            
            // Panic syscall
            syscalls::SOL_PANIC => {
                return Some(RecognizedPattern::ErrorHandling);
            },
            
            _ => {}
        }
    }
    
    None
}

/// Identify account validation patterns
fn identify_account_validation_pattern(window: &[SbfInstruction]) -> Option<RecognizedPattern> {
    // Check for owner validation pattern
    // Typically: load account owner -> compare with expected owner -> jump if not equal
    if window[0].is_load() && 
       (window[1].opcode == opcodes::JEQ_IMM || window[1].opcode == opcodes::JNE_IMM) {
        return Some(RecognizedPattern::OwnerValidation);
    }
    
    // Check for signer check pattern
    // Typically: load is_signer flag -> compare with 1 -> jump if not equal
    if window[0].is_load() && window[0].mem_size() == Some(1) &&
       (window[1].opcode == opcodes::JEQ_IMM || window[1].opcode == opcodes::JNE_IMM) &&
       window[1].imm == 0 {
        return Some(RecognizedPattern::SignerCheck);
    }
    
    // Check for account data size validation
    // Typically: load data_len -> compare with expected size -> jump if less than
    if window[0].is_load() && 
       (window[1].opcode == opcodes::JLT_IMM || window[1].opcode == opcodes::JGE_IMM) {
        return Some(RecognizedPattern::DataSizeValidation);
    }
    
    None
}

/// Identify data serialization/deserialization patterns
fn identify_serialization_pattern(window: &[SbfInstruction]) -> Option<RecognizedPattern> {
    // Check for Borsh deserialization pattern
    // Typically: sequential loads of different sizes from an offset that increases
    let mut load_count = 0;
    let mut last_offset = -1;
    
    for insn in window {
        if insn.is_load() {
            load_count += 1;
            if last_offset != -1 && insn.offset > last_offset {
                last_offset = insn.offset;
            } else if last_offset == -1 {
                last_offset = insn.offset;
            } else {
                break;
            }
        } else if !insn.is_alu() {
            break;
        }
    }
    
    if load_count >= 3 {
        return Some(RecognizedPattern::BorshDeserialization);
    }
    
    // Check for Borsh serialization pattern
    // Typically: sequential stores of different sizes to an offset that increases
    let mut store_count = 0;
    let mut last_offset = -1;
    
    for insn in window {
        if insn.is_store() {
            store_count += 1;
            if last_offset != -1 && insn.offset > last_offset {
                last_offset = insn.offset;
            } else if last_offset == -1 {
                last_offset = insn.offset;
            } else {
                break;
            }
        } else if !insn.is_alu() {
            break;
        }
    }
    
    if store_count >= 3 {
        return Some(RecognizedPattern::BorshSerialization);
    }
    
    None
}

/// Identify PDA derivation patterns
fn identify_pda_pattern(window: &[SbfInstruction]) -> Option<RecognizedPattern> {
    // Look for PDA derivation syscalls
    for (i, insn) in window.iter().enumerate() {
        if insn.opcode == opcodes::CALL && 
           (insn.imm as u32 == syscalls::SOL_CREATE_PROGRAM_ADDRESS || 
            insn.imm as u32 == syscalls::SOL_TRY_FIND_PROGRAM_ADDRESS) {
            
            // Check if seeds are being prepared before the call
            let mut seed_preparation = false;
            if i >= 2 {
                // Look for store operations that might be preparing seeds
                for j in 0..i {
                    if window[j].is_store() {
                        seed_preparation = true;
                        break;
                    }
                }
            }
            
            if seed_preparation {
                return Some(RecognizedPattern::PdaDerivation);
            } else {
                return Some(RecognizedPattern::PdaVerification);
            }
        }
    }
    
    None
}

/// Recognized instruction patterns
#[derive(Debug, Clone, PartialEq)]
pub enum RecognizedPattern {
    /// Cross-program invocation
    CrossProgramInvocation,
    /// PDA verification
    PdaVerification,
    /// PDA derivation
    PdaDerivation,
    /// Account owner validation
    OwnerValidation,
    /// Signer check
    SignerCheck,
    /// Data size validation
    DataSizeValidation,
    /// Borsh deserialization
    BorshDeserialization,
    /// Borsh serialization
    BorshSerialization,
    /// Logging
    Logging,
    /// Hashing operation
    Hashing,
    /// Signature verification
    Signature,
    /// Return data handling
    ReturnData,
    /// Error handling
    ErrorHandling,
}

/// Enhance IDL with recognized instruction patterns
pub fn enhance_idl_with_patterns(idl: &mut IDL, instructions: &[SbfInstruction]) {
    let patterns = recognize_instruction_patterns(instructions);
    
    // Group patterns by instruction
    let mut instruction_patterns: HashMap<usize, Vec<RecognizedPattern>> = HashMap::new();
    
    // Analyze patterns to determine instruction boundaries and associate patterns with instructions
    // This is a simplified approach - you'd need to map patterns to actual instruction handlers
    
    // Enhance IDL instructions with pattern information
    for (i, idl_instruction) in idl.instructions.iter_mut().enumerate() {
        if let Some(patterns) = instruction_patterns.get(&i) {
            // Add metadata based on patterns
            for pattern in patterns {
                match pattern {
                    RecognizedPattern::CrossProgramInvocation => {
                        idl_instruction.metadata.insert("uses_cpi".to_string(), "true".to_string());
                    },
                    RecognizedPattern::PdaDerivation => {
                        idl_instruction.metadata.insert("derives_pda".to_string(), "true".to_string());
                    },
                    RecognizedPattern::SignerCheck => {
                        // Mark accounts that require signing
                        for account in &mut idl_instruction.accounts {
                            if account.name.contains("authority") || account.name.contains("owner") {
                                account.is_signer = true;
                            }
                        }
                    },
                    RecognizedPattern::BorshDeserialization => {
                        idl_instruction.metadata.insert("serialization".to_string(), "borsh".to_string());
                    },
                    _ => {}
                }
            }
        }
    }
}

/// Identify Anchor-specific patterns
fn identify_anchor_patterns(instructions: &[SbfInstruction]) -> Vec<AnchorPattern> {
    let mut patterns = Vec::new();
    
    // Look for Anchor account discriminator checks
    // Typically: load first 8 bytes -> compare with discriminator -> jump if not equal
    for window in instructions.windows(4) {
        if window[0].is_load() && window[0].mem_size() == Some(8) &&
           (window[1].opcode == opcodes::JEQ_IMM || window[1].opcode == opcodes::JNE_IMM) {
            patterns.push(AnchorPattern::DiscriminatorCheck);
        }
    }
    
    // Look for Anchor constraint checks
    // These often involve specific error codes in the 2000-3000 range
    for window in instructions.windows(3) {
        if window[0].opcode == opcodes::MOV_IMM && 
           (window[0].imm >= 2000 && window[0].imm < 4000) && 
           window[1].is_call() && 
           window[1].imm as u32 == syscalls::SOL_PANIC {
            
            // Map error code to constraint type
            let constraint = match window[0].imm {
                2000 => AnchorPattern::ConstraintMut,
                2002 => AnchorPattern::ConstraintSigner,
                2005 => AnchorPattern::ConstraintRentExempt,
                2006 => AnchorPattern::ConstraintSeeds,
                3001 => AnchorPattern::AccountDiscriminatorNotFound,
                3005 => AnchorPattern::AccountNotEnoughKeys,
                3010 => AnchorPattern::AccountNotSigner,
                _ => AnchorPattern::OtherConstraint,
            };
            
            patterns.push(constraint);
        }
    }
    
    patterns
}

/// Anchor-specific patterns
#[derive(Debug, Clone, PartialEq)]
pub enum AnchorPattern {
    /// Account discriminator check
    DiscriminatorCheck,
    /// Constraint: Mut
    ConstraintMut,
    /// Constraint: Signer
    ConstraintSigner,
    /// Constraint: RentExempt
    ConstraintRentExempt,
    /// Constraint: Seeds
    ConstraintSeeds,
    /// Account discriminator not found
    AccountDiscriminatorNotFound,
    /// Account not enough keys
    AccountNotEnoughKeys,
    /// Account not signer
    AccountNotSigner,
    /// Other constraint
    OtherConstraint,
}