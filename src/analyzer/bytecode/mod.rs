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

/// Analyze program bytecode with program-specific optimizations
pub fn analyze(program_data: &[u8], program_id: &str) -> Result<BytecodeAnalysis> {
    info!("Analyzing program bytecode for {}, size: {} bytes", program_id, program_data.len());
    
    // Check if valid ELF file
    if program_data.len() < 8 || !is_elf_file(program_data) {
        info!("Not a valid ELF file for program {}, creating minimal analysis", program_id);
        return create_minimal_analysis();
    }
    
    // Determine program family based on program ID
    let program_family = determine_program_family(program_id);
    info!("Detected program family: {} for program {}", program_family, program_id);
    
    // Parse ELF file with program-specific optimizations
    info!("Parsing ELF file for program {}", program_id);
    let elf_analyzer = elf::ElfAnalyzer::from_bytes(program_data.to_vec())
        .context(format!("Failed to parse ELF file for program {}", program_id))?;
    
    // Get relevant sections based on program family
    let sections_to_analyze = get_relevant_sections_for_program(&elf_analyzer, program_id, &program_family)?;
    info!("Found {} relevant sections for program {}", sections_to_analyze.len(), program_id);
    
    // Get the text section with program-specific handling
    info!("Getting text section for program {}", program_id);
    let text_section = match get_program_text_section(&elf_analyzer, program_id, &program_family)? {
        Some(section) => {
            info!("Found text section for program {}, size: {} bytes", program_id, section.data.len());
            section
        },
        None => {
            warn!("No text section found for program {}", program_id);
            return create_minimal_analysis();
        }
    };
    
    // Parse instructions with enhanced SBPF version support
    info!("Parsing instructions for program {}", program_id);
    let instructions = parser::parse_instructions(&text_section.data, text_section.address as usize)
        .context(format!("Failed to parse instructions for program {}", program_id))?;
    info!("Parsed {} instructions for program {}", instructions.len(), program_id);
    
    // Build control flow graph
    info!("Building control flow graph for program {}", program_id);
    let (blocks, functions) = cfg::build_cfg(&instructions)
        .context(format!("Failed to build control flow graph for program {}", program_id))?;
    info!("Built control flow graph with {} blocks and {} functions for program {}", 
          blocks.len(), functions.len(), program_id);
    
    // Extract Anchor discriminators with improved detection
    info!("Extracting discriminators for program {}", program_id);
    let discriminators = discriminator_detection::extract_discriminators(program_data)
        .context(format!("Failed to extract discriminators for program {}", program_id))?;
    info!("Extracted {} discriminators for program {}", discriminators.len(), program_id);
    
    // Extract strings
    let strings = match elf_analyzer.extract_strings() {
        Ok(s) => {
            info!("Extracted {} strings from program {}", s.len(), program_id);
            s
        },
        Err(_) => Vec::new(),
    };
    
    // Determine if this is an Anchor program
    let is_anchor = !discriminators.is_empty() || 
                   crate::analyzer::anchor::is_anchor_program(program_data);
    
    if is_anchor {
        info!("Program {} appears to be an Anchor program", program_id);
    }
    
    // Extract accounts with enhanced detection
    info!("Extracting account structures for program {}", program_id);
    let accounts = account_analyzer::extract_account_structures(program_data)
        .context(format!("Failed to extract account structures for program {}", program_id))?;
    info!("Extracted {} account structures for program {}", accounts.len(), program_id);
    
    // Extract error codes
    info!("Extracting error codes for program {}", program_id);
    let error_codes = if is_anchor {
        crate::analyzer::anchor::extract_custom_error_codes(program_data)
            .context(format!("Failed to extract Anchor error codes for program {}", program_id))?
    } else {
        pattern::extract_error_codes(&instructions, &strings)
    };
    info!("Extracted {} error codes for program {}", error_codes.len(), program_id);
    
    // Convert functions to instructions
    let mut idl_instructions = Vec::new();
    
    info!("Converting functions to instructions for program {}", program_id);
    for function in functions {
        if let Some(ref name) = function.name {
            if name.starts_with("process_instruction_") {
                // This is an instruction handler
                let mut instruction = Instruction::new(
                    name.trim_start_matches("process_instruction_").to_string(),
                    idl_instructions.len() as u8
                );
                
                // Add parameters from analysis
                let params = cfg::analyze_instruction_parameters(&blocks, &function);
                for (name, type_name) in params {
                    instruction.add_arg(name.clone(), type_name);
                }
                
                idl_instructions.push(instruction);
            }
        }
    }
    
    // If we found discriminators but no instructions, create instructions from discriminators
    if idl_instructions.is_empty() && is_anchor {
        info!("Creating instructions from discriminators for program {}", program_id);
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
    
    info!("Analysis complete for program {}: found {} instructions, {} accounts, {} error codes",
          program_id, idl_instructions.len(), accounts.len(), error_codes.len());
    
    Ok(BytecodeAnalysis {
        instructions: idl_instructions,
        accounts,
        is_anchor,
        error_codes,
    })
}

/// Determine the program family based on program ID
fn determine_program_family(program_id: &str) -> String {
    // Check for SPL Token program family
    if program_id == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" || 
       program_id == "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" {
        return "spl_token".to_string();
    }
    
    // Check for SPL Associated Token program family
    if program_id == "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" {
        return "spl_associated_token".to_string();
    }
    
    // Check for Metaplex program family
    if program_id.starts_with("metaqbxxUerdq") {
        return "metaplex".to_string();
    }
    
    // Default to generic
    "generic".to_string()
}

/// Get relevant sections for a specific program
fn get_relevant_sections_for_program(
    elf_analyzer: &elf::ElfAnalyzer, 
    program_id: &str,
    program_family: &str
) -> Result<Vec<elf::ElfSection>> {
    let mut sections = Vec::new();
    
    // Always include text section
    if let Ok(Some(text)) = elf_analyzer.get_text_section() {
        sections.push(text);
    }
    
    // Always include rodata section
    if let Ok(Some(rodata)) = elf_analyzer.get_rodata_section() {
        sections.push(rodata);
    }
    
    // For SPL Token programs, also look for specific sections
    if program_family == "spl_token" {
        // SPL Token programs might have specific sections
        if let Ok(Some(section)) = elf_analyzer.get_section(".spl.token.instructions") {
            sections.push(section);
        }
    }
    
    // For Metaplex programs, look for metadata sections
    if program_family == "metaplex" {
        if let Ok(Some(section)) = elf_analyzer.get_section(".metadata") {
            sections.push(section);
        }
    }
    
    Ok(sections)
}

/// Get the text section with program-specific handling
fn get_program_text_section(
    elf_analyzer: &elf::ElfAnalyzer, 
    program_id: &str,
) -> Result<Option<elf::ElfSection>> {
    
    // Standard text section
    if let Ok(Some(text)) = elf_analyzer.get_text_section() {
        return Ok(Some(text));
    }
    
    Ok(None)
}