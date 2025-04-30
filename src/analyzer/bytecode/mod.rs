//! Bytecode analysis for Solana programs

pub mod parser;
pub mod elf;
pub mod pattern;
pub mod account_analyzer;
pub mod cfg;
pub mod discriminator_detection;
pub mod dynamic_analysis;
pub mod disassembler;

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
use crate::analyzer::anchor::is_anchor_program;
use crate::analyzer::bytecode::pattern::extract_error_codes;
use crate::analyzer::bytecode::disassembler::AccessType;

/// Results of bytecode analysis
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

/// Analyze program bytecode
pub fn analyze(program_data: &[u8], program_id: &str) -> Result<BytecodeAnalysis> {
    info!("Analyzing program bytecode for {}", program_id);
    
    // Check if this is an Anchor program
    let is_anchor = is_anchor_program(program_data);
    
    // Create ELF analyzer
    let elf_analyzer = elf::ElfAnalyzer::from_bytes(program_data.to_vec())?;
    
    // Try to disassemble the program first
    let disassembled = match disassembler::disassemble_program(program_data) {
        Ok(disassembled) => {
            info!("Successfully disassembled program");
            Some(disassembled)
        },
        Err(e) => {
            warn!("Failed to disassemble program: {}", e);
            None
        }
    };
    
    // Extract instructions using disassembler if available, otherwise fall back to parser
    let mut instructions = if let Some(disassembled) = &disassembled {
        info!("Extracting instructions from disassembled program");
        disassembler::extract_instructions(disassembled, program_id)
    } else {
        info!("Falling back to instruction parser");
        // Parse instructions from text section
        if let Ok(Some(text)) = elf_analyzer.get_text_section() {
            let parsed_instructions = parser::parse_instructions(&text.data, text.address as usize)?;
            let (blocks, functions) = cfg::build_cfg(&parsed_instructions)?;
            
            if is_anchor {
                info!("Detected Anchor program, using Anchor-specific analysis");
                analyze_anchor_program(program_data, program_id, &parsed_instructions, &blocks, &functions)?
                    .instructions
            } else {
                info!("Using native program analysis");
                analyze_native_program(program_data, program_id, &parsed_instructions, &blocks, &functions)?
                    .instructions
            }
        } else {
            warn!("Failed to get text section, using fallback analysis");
            // Fallback: create a generic instruction
            let mut instruction = Instruction::new("process".to_string(), 0);
            instruction.add_arg("data".to_string(), "bytes".to_string());
            instruction.add_account("authority".to_string(), true, false, false);
            instruction.add_account("data".to_string(), false, true, false);
            vec![instruction]
        }
    };
    
    // Extract accounts using disassembler if available, otherwise fall back to account_analyzer
    let accounts = if let Some(disassembled) = &disassembled {
        info!("Extracting accounts from disassembled program");
        disassembler::extract_accounts(disassembled, program_id)
    } else {
        info!("Falling back to account analyzer");
        // Extract accounts using traditional methods
        if let Ok(Some(text)) = elf_analyzer.get_text_section() {
            let parsed_instructions = parser::parse_instructions(&text.data, text.address as usize)?;
            let discriminators = discriminator_detection::extract_discriminators(program_data)?;
            account_analyzer::extract_account_structures(program_data, &parsed_instructions, &discriminators)?
        } else {
            warn!("Failed to get text section, using fallback account analysis");
            // Fallback: create a generic account
            let mut account = Account::new("State".to_string(), "state".to_string());
            account.add_field("data".to_string(), "bytes".to_string(), 0);
            vec![account]
        }
    };
    
    // Extract error codes
    let error_codes = if is_anchor {
        // Use Anchor-specific error code extraction
        crate::analyzer::anchor::extract_custom_error_codes(program_data)
            .unwrap_or_default()
    } else {
        // Extract error codes from strings in the program
        let mut codes = HashMap::new();
        
        // Try to extract error strings from the program
        if let Ok(Some(rodata)) = elf_analyzer.get_rodata_section() {
            let strings = pattern::extract_strings(&rodata.data);
            for (i, string) in strings.iter().enumerate() {
                if string.contains("error") || string.contains("Error") {
                    codes.insert(6000 + i as u32, string.clone());
                }
            }
        }
        
        codes
    };
    
    // Extract arguments for each instruction
    for instruction in &mut instructions {
        // Use the instruction index as the entrypoint
        let args = dynamic_analysis::extract_args(program_data, instruction.index as usize);
        instruction.args = args;
    }
    
    Ok(BytecodeAnalysis {
        instructions,
        accounts,
        error_codes,
        is_anchor,
        disassembled,
    })
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
    for disc in &discriminators {
        let name = disc.name.clone().unwrap_or_else(|| format!("instruction_{}", disc.code));
        let mut instruction = Instruction::new(name, 0);
        
        // Add standard Anchor accounts
        instruction.add_account("authority".to_string(), true, false, false);
        instruction.add_account("systemProgram".to_string(), false, false, false);
        
        // Add instruction to list
        instructions.push(instruction);
    }
    
    // Extract accounts
    let accounts = account_analyzer::extract_account_structures(
        program_data, 
        parsed_instructions, 
        &discriminators
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
    // Extract native program instructions
    let mut instructions = Vec::new();
    
    // For each function that looks like an entry point, create an instruction
    for function in functions {
        // Check if this is likely an entry point function
        if blocks[function.entry_block].is_function_entry() {
            let name = function.name.clone().unwrap_or_else(|| format!("function_{}", function.id));
            let mut instruction = Instruction::new(name, 0);
            
            // Add generic arguments
            instruction.add_arg("data".to_string(), "bytes".to_string());
            
            // Add standard accounts
            instruction.add_account("authority".to_string(), true, false, false);
            instruction.add_account("data".to_string(), false, true, false);
            
            // Add instruction to list
            instructions.push(instruction);
        }
    }
    
    // If no instructions found, add a generic one
    if instructions.is_empty() {
        let mut instruction = Instruction::new("process".to_string(), 0);
        instruction.add_arg("data".to_string(), "bytes".to_string());
        instruction.add_account("authority".to_string(), true, false, false);
        instruction.add_account("data".to_string(), false, true, false);
        instructions.push(instruction);
    }
    
    // Extract accounts
    let accounts = account_analyzer::extract_account_structures(
        program_data, 
        parsed_instructions, 
        &[]
    )?;
    
    // Extract error codes
    let mut error_codes = HashMap::new();
    
    // Try to extract error strings from the program
    if let Ok(Some(rodata)) = elf::ElfAnalyzer::from_bytes(program_data.to_vec())?.get_rodata_section() {
        let strings = pattern::extract_strings(&rodata.data);
        for (i, string) in strings.iter().enumerate() {
            if string.contains("error") || string.contains("Error") {
                error_codes.insert(6000 + i as u32, string.clone());
            }
        }
    }
    
    Ok(BytecodeAnalysis {
        instructions,
        accounts,
        error_codes,
        is_anchor: false,
        disassembled: None,
    })
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