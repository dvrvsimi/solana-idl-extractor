//! Bytecode analysis for Solana programs

pub mod parser;
pub mod elf;
pub mod pattern;
pub mod account_analyzer;
pub mod cfg;
pub mod discriminator_detection;

// Re-export key components
pub use parser::parse_instructions;
pub use elf::ElfAnalyzer;
pub use account_analyzer::extract_account_structures;
pub use cfg::{BasicBlock, Function, build_cfg, analyze_instruction_parameters};
pub use discriminator_detection::{AnchorDiscriminator, DiscriminatorKind, extract_discriminators};

use anyhow::{Result, Context, anyhow};
use log::{debug, info, warn};
use std::collections::HashMap;

use crate::models::instruction::Instruction;
use crate::models::account::Account;

/// Bytecode analysis results
pub struct BytecodeAnalysis {
    /// Extracted instructions
    pub instructions: Vec<Instruction>,
    /// Extracted accounts
    pub accounts: Vec<Account>,
    /// Is this an Anchor program?
    pub is_anchor: bool,
    /// Error codes
    pub error_codes: HashMap<u32, String>,
}

/// Check if data is an ELF file
fn is_elf_file(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x7F && data[1] == b'E' && data[2] == b'L' && data[3] == b'F'
}

/// Create a minimal analysis result
fn create_minimal_analysis() -> Result<BytecodeAnalysis> {
    let mut instruction = Instruction::new("process".to_string(), 0);
    instruction.add_arg("data".to_string(), "bytes".to_string());
    
    let mut account = Account::new("State".to_string(), "state".to_string());
    account.add_field("data".to_string(), "bytes".to_string(), 0);
    
    Ok(BytecodeAnalysis {
        instructions: vec![instruction],
        accounts: vec![account],
        is_anchor: false,
        error_codes: HashMap::new(),
    })
}

/// Analyze program bytecode
pub fn analyze(program_data: &[u8], program_id: &str) -> Result<BytecodeAnalysis> {
    info!("Analyzing program bytecode, size: {} bytes", program_data.len());
    
    // Check if valid ELF file
    if program_data.len() < 8 || !is_elf_file(program_data) {
        return create_minimal_analysis();
    }
    
    // Parse ELF file
    let elf_analyzer = elf::ElfAnalyzer::from_bytes(program_data)
        .context("Failed to parse ELF file")?;
    
    // Get the text section
    let text_section = match elf_analyzer.get_text_section()? {
        Some(section) => section,
        None => return create_minimal_analysis(),
    };
    
    // Parse instructions with enhanced SBPF version support
    let instructions = parser::parse_instructions(&text_section.data, text_section.address as usize)
        .context("Failed to parse instructions")?;
    
    // Build control flow graph
    let (blocks, functions) = cfg::build_cfg(&instructions)
        .context("Failed to build control flow graph")?;
    
    // Extract Anchor discriminators with improved detection
    let discriminators = discriminator_detection::extract_discriminators(program_data)
        .context("Failed to extract discriminators")?;
    
    // Extract strings
    let strings = elf::extract_strings(program_data);
    
    // Determine if this is an Anchor program
    let is_anchor = !discriminators.is_empty() || 
                   crate::analyzer::anchor::is_anchor_program(program_data);
    
    // Extract accounts with enhanced detection
    let accounts = account_analyzer::extract_account_structures(program_data)
        .context("Failed to extract account structures")?;
    
    // Extract error codes
    let error_codes = if is_anchor {
        crate::analyzer::anchor::extract_custom_error_codes(program_data)
            .context("Failed to extract error codes")?
    } else {
        pattern::extract_error_codes(&instructions, &strings)
    };
    
    // Convert functions to instructions
    let mut idl_instructions = Vec::new();
    
    for function in functions {
        if let Some(name) = function.name {
            if name.starts_with("process_instruction_") {
                // This is an instruction handler
                let mut instruction = Instruction::new(
                    name.trim_start_matches("process_instruction_").to_string(),
                    idl_instructions.len() as u8
                );
                
                // Add parameters from analysis
                let params = cfg::analyze_instruction_parameters(&blocks, &function);
                for (name, type_name) in params {
                    instruction.add_arg(name, type_name);
                }
                
                idl_instructions.push(instruction);
            }
        }
    }
    
    // If we found discriminators but no instructions, create instructions from discriminators
    if idl_instructions.is_empty() && is_anchor {
        for (i, disc) in discriminators.iter().enumerate() {
            if disc.kind == discriminator_detection::DiscriminatorKind::Instruction {
                let name = disc.name.clone().unwrap_or_else(|| format!("instruction_{}", i));
                let code = disc.code.unwrap_or(i as u8);
                
                let mut instruction = Instruction::new(name, code);
                instruction.add_arg("data".to_string(), "bytes".to_string());
                
                idl_instructions.push(instruction);
            }
        }
    }
    
    Ok(BytecodeAnalysis {
        instructions: idl_instructions,
        accounts,
        is_anchor,
        error_codes,
    })
}