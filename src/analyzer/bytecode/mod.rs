//! Bytecode analysis for Solana programs

pub mod parser;
pub mod elf;
pub mod pattern;
pub mod account_analyzer;
pub mod cfg;
pub mod discriminator_detection;
pub mod dynamic_analysis;
pub mod disassembler;
pub mod instruction_analyzer;
pub mod error_analyzer;

// Re-export key components
pub use parser::parse_instructions;
pub use elf::ElfAnalyzer;
pub use account_analyzer::extract_account_structures;
pub use cfg::{BasicBlock, Function, build_cfg, analyze_instruction_parameters};
pub use discriminator_detection::{AnchorDiscriminator, DiscriminatorKind, extract_discriminators};
pub use disassembler::{disassemble_program, DisassembledProgram};

use anyhow::{Result, Context, anyhow};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::collections::HashSet;

use crate::models::instruction::Instruction;
use crate::models::account::Account;
use crate::analyzer::bytecode::disassembler::AccessType;
use crate::analyzer::anchor::is_anchor_program;


/// Results of bytecode analysis
///
/// This struct contains all information extracted from a Solana program's bytecode,
/// including instructions, accounts, and error codes.
///
/// # Examples
///
/// ```
/// # use solana_idl_extractor::analyzer::bytecode::BytecodeAnalysis;
/// # let analysis = BytecodeAnalysis::default();
/// println!("Found {} instructions", analysis.instructions.len());
/// ```
#[derive(Debug, Clone)]
pub struct BytecodeAnalysis {
    /// Extracted instructions
    pub instructions: Vec<Instruction>,
    /// Extracted accounts
    pub accounts: Vec<Account>,
    /// Error codes
    pub error_codes: HashMap<u32, String>,
    /// Is this an Anchor program?
    pub is_anchor: bool,
    /// Disassembled program (if available)
    pub disassembled: Option<DisassembledProgram>,
}

impl Clone for DisassembledProgram {
    fn clone(&self) -> Self {
        Self {
            instructions: self.instructions.clone(),
            functions: self.functions.clone(),
            cfg: self.cfg.clone(),
            memory_accesses: self.memory_accesses.clone(),
        }
    }
}

impl Default for BytecodeAnalysis {
    fn default() -> Self {
        Self {
            instructions: Vec::new(),
            accounts: Vec::new(),
            error_codes: HashMap::new(),
            is_anchor: false,
            disassembled: None,
        }
    }
}

/// Analyze program bytecode
pub fn analyze(program_data: &[u8], program_id: &str) -> anyhow::Result<BytecodeAnalysis> {
    info!("Analyzing program bytecode for {}", program_id);
    
    // Check if this looks like valid ELF data
    if program_data.len() < 4 || program_data[0] != 0x7F || program_data[1] != b'E' || program_data[2] != b'L' || program_data[3] != b'F' {
        // Check if this might be a BPF upgradeable loader account (36 bytes)
        if program_data.len() == 36 {
            return Err(anyhow::anyhow!(
                "This appears to be a BPF upgradeable loader account (36 bytes), not the actual program binary. \
                The program data account address is contained in bytes 4-36. \
                The Monitor should have automatically handled this, but if you're seeing this error, \
                there might have been an issue fetching the actual program data."
            ));
        }
        
        return Err(anyhow::anyhow!(
            "Invalid program data: Not a valid ELF file. Data size: {} bytes. \
            This could be a BPF upgradeable loader account or a proxy. \
            The first few bytes: {:?}", 
            program_data.len(),
            &program_data.iter().take(10).map(|b| format!("{:02x}", b)).collect::<Vec<_>>()
        ));
    }
    
    // Create ELF analyzer
    let elf_analyzer = elf::ElfAnalyzer::from_bytes(program_data.to_vec())
        .map_err(|e| anyhow::anyhow!("Failed to parse ELF file: {}", e))?;
    
    // Get text section
    let text_section = elf_analyzer.get_text_section()
        .map_err(|e| anyhow::anyhow!("Failed to get text section: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("No text section found in ELF file"))?;
    
    // Parse instructions
    let instructions = parser::parse_instructions(&text_section.data, text_section.address as usize)
        .map_err(|e| anyhow::anyhow!("Failed to parse instructions: {}", e))?;
    
    // Build CFG for more advanced analysis
    let (blocks, functions) = cfg::build_cfg(&instructions)
        .map_err(|e| anyhow::anyhow!("Failed to build CFG: {}", e))?;
    
    // Check if this is an Anchor program
    let is_anchor = is_anchor_program(program_data);
    
    // Use the appropriate analysis method
    if is_anchor {
        info!("Detected Anchor program, using Anchor-specific analysis");
        analyze_anchor_program(program_data, program_id, &instructions, &blocks, &functions)
    } else {
        info!("Detected native Solana program, using general analysis");
        analyze_native_program(program_data, program_id, &instructions, &blocks, &functions)
    }
}

/// Analyze an Anchor program
fn analyze_anchor_program(
    program_data: &[u8],
    program_id: &str,
    parsed_instructions: &[parser::SbfInstruction],
    blocks: &[cfg::BasicBlock],
    functions: &[cfg::Function],
) -> Result<BytecodeAnalysis> {
    // Extract Anchor-specific instructions
    let mut instructions = Vec::new();
    
    // Extract discriminators
    let discriminators = discriminator_detection::extract_discriminators(program_data)?;
    
    // For each discriminator, create an instruction
    for (i, disc) in discriminators.iter().enumerate() {
        let name = disc.name.clone().unwrap_or_else(|| format!("instruction_{}", disc.code.unwrap_or(i as u8)));
        let mut instruction = Instruction::new(name.clone(), i as u8);
        
        // Set the discriminator bytes
        instruction.discriminator = Some(disc.bytes.clone());
        
        // Add standard Anchor accounts
        instruction.add_account("authority".to_string(), true, false, false);
        instruction.add_account("systemProgram".to_string(), false, false, false);
        
        // Add instruction to list
        instructions.push(instruction);
    }
    
    // If we didn't find any discriminators, try to extract instructions from functions
    if instructions.is_empty() {
        info!("No discriminators found, extracting instructions from functions");
        // Limit to the first 20 functions to avoid overwhelming the IDL
        for (i, function) in functions.iter().take(20).enumerate() {
            if blocks[function.entry_block].is_function_entry() {
                let name = function.name.clone().unwrap_or_else(|| format!("function_{}", function.id));
                let mut instruction = Instruction::new(name, i as u8);
                
                // Add generic arguments
                instruction.add_arg("data".to_string(), "bytes".to_string());
                
                // Add standard accounts
                instruction.add_account("authority".to_string(), true, false, false);
                instruction.add_account("data".to_string(), false, true, false);
                
                // Add instruction to list
                instructions.push(instruction);
            }
        }
    }
    
    // Extract accounts
    let accounts = account_analyzer::extract_account_structures(
        program_data,
        parsed_instructions,
        &[]  // Empty discriminator list for non-Anchor programs
    )?;
    
    // Extract error codes (using Anchor-specific method)
    let error_codes = crate::analyzer::anchor::extract_custom_error_codes(program_data)
        .unwrap_or_default();
    
    Ok(BytecodeAnalysis {
        instructions,
        accounts,
        error_codes,
        is_anchor: true,
        disassembled: None,
    })
}

/// Analyze a native (non-Anchor) program
fn analyze_native_program(
    program_data: &[u8],
    program_id: &str,
    parsed_instructions: &[parser::SbfInstruction],
    blocks: &[cfg::BasicBlock],
    functions: &[cfg::Function],
) -> Result<BytecodeAnalysis> {
    // Find instruction entry points
    let instruction_entries = identify_instruction_boundaries(parsed_instructions, blocks, program_data);
    
    // Create instructions based on entry points
    let mut program_instructions = Vec::new();
    
    for (i, &entry_point) in instruction_entries.iter().enumerate() {
        // Try to infer a meaningful name for this instruction
        let name = infer_instruction_name(parsed_instructions, entry_point, program_data)
            .unwrap_or_else(|| format!("instruction_{}", i));
        
        let mut instruction = Instruction::new(name, i as u8);
        
        // Add generic arguments
        instruction.add_arg("data".to_string(), "bytes".to_string());
        
        // Add standard accounts
        instruction.add_account("authority".to_string(), true, false, false);
        instruction.add_account("data".to_string(), false, true, false);
        
        program_instructions.push(instruction);
    }
    
    // If we couldn't find any instructions, add a generic one
    if program_instructions.is_empty() {
        let mut instruction = Instruction::new("process".to_string(), 0);
        instruction.add_arg("data".to_string(), "bytes".to_string());
        instruction.add_account("authority".to_string(), true, false, false);
        instruction.add_account("data".to_string(), false, true, false);
        program_instructions.push(instruction);
    }
    
    // Extract accounts
    let accounts = account_analyzer::extract_account_structures(
        program_data,
        parsed_instructions,
        &[]  // Empty discriminator list for non-Anchor programs
    )?;
    
    // Extract error codes
    let error_codes = error_analyzer::extract_error_codes(parsed_instructions)
        .unwrap_or_default();
    
    // Create analysis result
    let analysis = BytecodeAnalysis {
        instructions: program_instructions,
        accounts,
        error_codes,
        is_anchor: false,
        disassembled: None,
    };
    
    info!("Bytecode analysis complete, found {} instructions, {} accounts, {} error codes",
        analysis.instructions.len(),
        analysis.accounts.len(),
        analysis.error_codes.len()
    );
    
    Ok(analysis)
}

/// Enhanced instruction boundary identification with more sophisticated heuristics
fn identify_instruction_boundaries(
    parsed_instructions: &[parser::SbfInstruction],
    blocks: &[cfg::BasicBlock],
    program_data: &[u8]
) -> Vec<usize> {
    let mut instruction_entries = Vec::new();
    
    // 1. BPF Specific Patterns - Look for function prologues
    for (i, insn) in parsed_instructions.iter().enumerate() {
        // Check for common BPF function prologue pattern
        if insn.opcode == 0x0f && // ALU64_REG 
           insn.dst_reg == 11 && 
           insn.src_reg == 11 && 
           insn.imm < 0 {
            instruction_entries.push(i);
        }
        
        // Check for register r0 being set
        if i > 0 && 
           insn.dst_reg == 0 && 
           (insn.opcode == 0xb7 || // MOV_IMM
            insn.opcode == 0xbf) { // MOV_REG
            instruction_entries.push(i - 1);
        }
        
        // Look for instruction discriminator checks
        // Anchor programs use 8-byte discriminators at the start
        if i + 8 < parsed_instructions.len() {
            // Check for loading bytes from instruction data
            if insn.is_load() && i > 0 {
                // Check if the next few instructions compare these bytes
                let mut is_discriminator_check = false;
                for j in 1..4 {
                    if i + j < parsed_instructions.len() {
                        let next_insn = &parsed_instructions[i + j];
                        if next_insn.opcode == 0x55 || // JNE_IMM
                           next_insn.opcode == 0x15 {  // JEQ_IMM
                            is_discriminator_check = true;
                            break;
                        }
                    }
                }
                
                if is_discriminator_check {
                    // This is likely checking a discriminator
                    instruction_entries.push(i - 1);
                }
            }
        }
    }
    
    // 2. Control Flow Analysis - Look for "islands" in the code
    // Identify blocks that have no predecessors (except the entry block)
    for (i, block) in blocks.iter().enumerate() {
        if i > 0 && block.predecessors.is_empty() && !block.instructions.is_empty() {
            instruction_entries.push(i);
        }
        
        // Look for blocks that end with a return (setting r0 and then exit)
        if !block.instructions.is_empty() {
            let last_idx = block.instructions.len() - 1;
            let last_insn = &block.instructions[last_idx];
            
            if last_insn.opcode == 0x95 { // EXIT opcode
                // Check if r0 was set just before exit (common pattern for returns)
                if last_idx > 0 {
                    let prev_insn = &block.instructions[last_idx - 1];
                    if prev_insn.dst_reg == 0 {
                        // Found a function that sets return value and exits
                        if last_idx + 1 < parsed_instructions.len() {
                            instruction_entries.push(last_idx + 1);
                        }
                    }
                }
            }
        }
    }
    
    // 3. Syscall Analysis - Look for common instruction patterns
    for (i, insn) in parsed_instructions.iter().enumerate() {
        if insn.opcode == 0x85 { // CALL opcode
            // Check if this is a syscall to sol_invoke or sol_invoke_signed
            let syscall_hash = insn.imm as u32;
            if syscall_hash == crate::constants::syscalls::hashes::SOL_INVOKE ||
               syscall_hash == crate::constants::syscalls::hashes::SOL_INVOKE_SIGNED {
                // This is likely a CPI instruction
                instruction_entries.push(i);
            }
        }
    }
    
    // Remove duplicates and sort
    instruction_entries.sort();
    instruction_entries.dedup();
    
    instruction_entries
}

/// Improved instruction name inference using multiple heuristics
fn infer_instruction_name(
    instructions: &[parser::SbfInstruction],
    entry_point: usize,
    program_data: &[u8]
) -> Option<String> {
    // 1. Symbol Recovery - Look for string references near the entry point
    let window_size = 50.min(instructions.len() - entry_point);
    let instruction_window = &instructions[entry_point..entry_point + window_size];
    
    // Look for string loading patterns
    for (_i, insn) in instruction_window.iter().enumerate() {
        if insn.is_load_imm() && insn.imm > 0 {
            // This might be loading a string pointer
            let potential_str_addr = insn.imm as usize;
            
            // Try to extract a string from this address in the program data
            if potential_str_addr < program_data.len() {
                let max_len = 30.min(program_data.len() - potential_str_addr);
                let potential_str = &program_data[potential_str_addr..potential_str_addr + max_len];
                
                // Check if this looks like a valid string
                if let Ok(s) = std::str::from_utf8(potential_str) {
                    let s = s.split('\0').next().unwrap_or("").trim();
                    if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                        // This looks like a valid instruction name
                        return Some(s.to_string());
                    }
                }
            }
        }
    }
    
    // 2. Syscall Analysis - Infer purpose from syscall usage
    for (i, insn) in instruction_window.iter().enumerate() {
        if insn.opcode == 0x85 && insn.imm > 0 { // CALL opcode
            let syscall_hash = insn.imm as u32;
            
            // Map common syscalls to likely instruction names
            match syscall_hash {
                hash if hash == crate::constants::syscalls::hashes::SOL_INVOKE => {
                    return Some("invoke".to_string());
                },
                hash if hash == crate::constants::syscalls::hashes::SOL_INVOKE_SIGNED => {
                    return Some("invoke_signed".to_string());
                },
                hash if hash == crate::constants::syscalls::hashes::SOL_CREATE_PROGRAM_ADDRESS => {
                    return Some("create_address".to_string());
                },
                hash if hash == crate::constants::syscalls::hashes::SOL_TRY_FIND_PROGRAM_ADDRESS => {
                    return Some("find_address".to_string());
                },
                hash if hash == crate::constants::syscalls::hashes::SOL_SHA256 => {
                    return Some("hash".to_string());
                },
                _ => {}
            }
        }
    }
    
    // 3. Pattern-Based Naming - Look for common instruction patterns
    
    // Check for token transfer patterns (loading accounts, then invoking)
    let mut has_account_loading = false;
    let mut has_invoke = false;
    
    for insn in instruction_window.iter() {
        if insn.is_load() {
            has_account_loading = true;
        }
        
        if insn.opcode == 0x85 && // CALL
           insn.imm as u32 == crate::constants::syscalls::hashes::SOL_INVOKE {
            has_invoke = true;
        }
    }
    
    if has_account_loading && has_invoke {
        return Some("transfer".to_string());
    }
    
    // Check for account initialization patterns
    let mut has_memset = false;
    for insn in instruction_window.iter() {
        if insn.opcode == 0x85 && // CALL
           insn.imm as u32 == crate::constants::syscalls::hashes::SOL_MEMSET {
            has_memset = true;
            break;
        }
    }
    
    if has_memset {
        return Some("initialize".to_string());
    }
    
    // 4. Fallback - Use a generic name with the entry point address
    Some(format!("instruction_{:x}", entry_point))
}

/// Extract accounts from bytecode
pub fn extract_accounts(
    disassembled: &DisassembledProgram,
    program_id: &str,
) -> Vec<Account> {
    let mut accounts = Vec::new();
    
    // Look for account structure patterns
    let mut account_fields = HashMap::new();
    
    // Analyze memory access patterns to identify account fields
    for access in &disassembled.memory_accesses {
        if matches!(access.access_type, AccessType::Read) {
            // This might be a field access
            account_fields.entry(access.address)
                .or_insert_with(Vec::new)
                .push((access.size, access.offset));
        }
    }
    
    // Create accounts based on field patterns
    let mut account_addresses = HashSet::new();
    for (addr, accesses) in &account_fields {
        // Skip if this doesn't look like an account (too few accesses)
        if accesses.len() < 2 {
            continue;
        }
        
        // Create a new account
        let account_name = format!("Account_{:x}", addr);
        if account_addresses.contains(&account_name) {
            continue;
        }
        account_addresses.insert(account_name.clone());
        
        let mut account = Account::new(account_name, "account".to_string());
        
        // Add fields based on access patterns
        let mut field_offsets = HashSet::new();
        for (size, _) in accesses {
            field_offsets.insert(*size);
        }
        
        for (i, size) in field_offsets.iter().enumerate() {
            let field_type = match size {
                1 => "u8".to_string(),
                2 => "u16".to_string(),
                4 => "u32".to_string(),
                8 => "u64".to_string(),
                _ => "bytes".to_string(),
            };
            
            account.add_field(format!("field_{}", i), field_type, *addr);
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