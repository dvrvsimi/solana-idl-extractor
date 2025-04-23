//! Bytecode analysis for Solana programs

mod parser;
mod cfg;
mod patterns;
mod elf;

use anyhow::{Result, anyhow, Context};
use log::{debug, info, warn};
use std::collections::HashMap;

use crate::constants::{opcodes, syscalls, discriminators};
use crate::models::{instruction::Instruction, account::Account};

pub use parser::SbfInstruction;
pub use cfg::{BasicBlock, Function};

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
pub fn analyze(program_data: &[u8], program_id: &str) -> Result<BytecodeAnalysis> {
    info!("Analyzing program bytecode, size: {} bytes", program_data.len());
    
    // Check if valid ELF file
    if program_data.len() < 8 || !is_elf_file(program_data) {
        return create_minimal_analysis();
    }
    
    // Parse ELF sections
    let sections = elf::parse_elf_sections(program_data)
        .context("Failed to parse ELF sections")?;
    
    // Find .text section for code analysis
    let text_section = sections.iter()
        .find(|s| s.name == ".text")
        .ok_or_else(|| anyhow!("No .text section found"))?;
    
    // Find .rodata section for string analysis
    let rodata_section = sections.iter()
        .find(|s| s.name == ".rodata")
        .or_else(|| sections.iter().find(|s| s.name == ".data"));
    
    // Parse instructions from .text section
    let instructions = parser::parse_instructions(&text_section.data, text_section.address)
        .context("Failed to parse instructions")?;
    
    // Build control flow graph
    let (blocks, functions) = cfg::build_control_flow_graph(&instructions)
        .context("Failed to build control flow graph")?;
    
    // Extract strings from .rodata section
    let strings = if let Some(rodata) = rodata_section {
        patterns::extract_strings(&rodata.data)
    } else {
        Vec::new()
    };
    
    // Check if this is an Anchor program
    let is_anchor = patterns::detect_anchor_program(&instructions, &strings);
    
    // Find instruction handlers
    let handlers = if is_anchor {
        patterns::find_anchor_instruction_handlers(&instructions, &blocks, &strings)
    } else {
        patterns::find_instruction_handlers(&instructions, &blocks, &functions, &strings)
    };
    
    // Extract error codes
    let error_codes = patterns::extract_error_codes(&instructions, &strings);
    
    // Convert to IDL instructions
    let idl_instructions = patterns::convert_to_idl_instructions(&handlers, is_anchor);
    
    // Extract account structures
    let accounts = patterns::extract_account_structures(&instructions, &strings, is_anchor);
    
    Ok(BytecodeAnalysis {
        instructions: idl_instructions,
        accounts,
        is_anchor,
        error_codes,
    })
}

/// Check if data is an ELF file
fn is_elf_file(data: &[u8]) -> bool {
    data.len() >= 4 && 
    data[0] == 0x7F && 
    data[1] == b'E' && 
    data[2] == b'L' && 
    data[3] == b'F'
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