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
    let instructions = match parser::parse_instructions(&text_section.data, text_section.address as usize) {
        Ok(insns) => {
            info!("Parsed {} instructions for program {}", insns.len(), program_id);
            insns
        },
        Err(e) => {
            warn!("Failed to parse instructions for program {}: {}", program_id, e);
            // Try alternative parsing approaches
            info!("Trying alternative parsing approaches");
            match alternative_parse_instructions(&text_section.data, text_section.address as usize) {
                Ok(alt_insns) => {
                    info!("Alternative parsing found {} instructions", alt_insns.len());
                    alt_insns
                },
                Err(_) => {
                    warn!("All parsing approaches failed, creating minimal analysis");
                    return create_minimal_analysis();
                }
            }
        }
    };
    
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
    
    // Extract instructions with improved native program support
    info!("Extracting instructions for program {}", program_id);
    let mut instructions = Vec::new();

    // First try to convert functions to instructions (for Anchor programs)
    info!("Converting functions to instructions for program {}", program_id);
    if let Ok(mut func_instructions) = convert_functions_to_instructions(&functions) {
        instructions.append(&mut func_instructions);
    }

    // Then try to create instructions from discriminators (for Anchor programs)
    info!("Creating instructions from discriminators for program {}", program_id);
    if let Ok(mut disc_instructions) = create_instructions_from_discriminators(&discriminators) {
        instructions.append(&mut disc_instructions);
    }

    // If we still don't have instructions, try native program extraction
    if instructions.is_empty() {
        info!("No instructions found through standard methods, trying native program extraction");
        if let Ok(mut native_instructions) = extract_native_program_instructions(
            program_id, 
            &program_family, 
            &functions,
            &transactions
        ) {
            instructions.append(&mut native_instructions);
        }
    }
    
    info!("Analysis complete for program {}: found {} instructions, {} accounts, {} error codes",
          program_id, instructions.len(), accounts.len(), error_codes.len());
    
    Ok(BytecodeAnalysis {
        instructions,
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
    program_family: &str
) -> Result<Option<elf::ElfSection>> {
    // Dump all section names for debugging
    info!("Sections in program {}:", program_id);
    for section in elf_analyzer.get_all_sections()? {
        info!("  Section: {} (size: {} bytes, flags: 0x{:x})", 
              section.name, section.size, section.flags);
    }
    
    // Standard text section
    if let Ok(Some(text)) = elf_analyzer.get_text_section() {
        info!("Found standard text section: {}", text.name);
        return Ok(Some(text));
    }
    
    // For some program families, the text section might have a different name
    if program_family == "spl_token" {
        // Try alternative section names
        for name in &[".text.spl.token", ".text.main", ".text.solana"] {
            if let Ok(Some(section)) = elf_analyzer.get_section(name) {
                info!("Found alternative text section: {}", name);
                return Ok(Some(section));
            }
        }
    }
    
    // Look for any executable section as a fallback
    for section in elf_analyzer.get_all_sections()? {
        if section.flags & 0x4 != 0 {  // Check for executable flag
            info!("Found executable section as fallback: {}", section.name);
            return Ok(Some(section));
        }
    }
    
    // No text section found
    warn!("No suitable text section found for program {}", program_id);
    Ok(None)
}

/// Add this helper function:
fn alternative_parse_instructions(data: &[u8], base_address: usize) -> Result<Vec<parser::SbfInstruction>> {
    // Try parsing with different offsets
    for offset in [0, 8, 16, 32] {
        if data.len() > offset {
            if let Ok(insns) = parser::parse_instructions(&data[offset..], base_address + offset) {
                if !insns.is_empty() {
                    info!("Found instructions with offset {}", offset);
                    return Ok(insns);
                }
            }
        }
    }
    
    // Try parsing smaller chunks
    for chunk_size in [1024, 2048, 4096] {
        if data.len() > chunk_size {
            if let Ok(insns) = parser::parse_instructions(&data[0..chunk_size], base_address) {
                if !insns.is_empty() {
                    info!("Found instructions in first {} bytes", chunk_size);
                    return Ok(insns);
                }
            }
        }
    }
    
    Err(anyhow!("Could not parse instructions with any alternative approach"))
}

// extract instructions from native programs
fn extract_native_program_instructions(
    program_id: &str,
    program_family: &str,
    functions: &[cfg::Function],
    transactions: &[EncodedTransaction]
) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::new();
    
    // For SPL Token program, we can hardcode the known instructions
    if program_family == "spl_token" {
        info!("Using predefined instruction set for SPL Token program");
        
        // Initialize instruction
        instructions.push(Instruction {
            name: "initialize".to_string(),
            accounts: vec![
                AccountMeta {
                    name: "mint".to_string(),
                    is_signer: true,
                    is_writable: true,
                    is_optional: false,
                    docs: Some("The mint to initialize".to_string()),
                },
                AccountMeta {
                    name: "rent".to_string(),
                    is_signer: false,
                    is_writable: false,
                    is_optional: false,
                    docs: Some("Rent sysvar".to_string()),
                },
            ],
            args: vec![
                Argument {
                    name: "decimals".to_string(),
                    ty: "u8".to_string(),
                    docs: Some("Number of decimals in token amount".to_string()),
                },
            ],
            discriminator: vec![0],
            docs: Some("Initializes a new mint".to_string()),
        });
        
        // InitializeAccount instruction
        instructions.push(Instruction {
            name: "initializeAccount".to_string(),
            accounts: vec![
                AccountMeta {
                    name: "account".to_string(),
                    is_signer: true,
                    is_writable: true,
                    is_optional: false,
                    docs: Some("The account to initialize".to_string()),
                },
                AccountMeta {
                    name: "mint".to_string(),
                    is_signer: false,
                    is_writable: false,
                    is_optional: false,
                    docs: Some("The mint this account will be associated with".to_string()),
                },
                AccountMeta {
                    name: "owner".to_string(),
                    is_signer: false,
                    is_writable: false,
                    is_optional: false,
                    docs: Some("The new account's owner".to_string()),
                },
                AccountMeta {
                    name: "rent".to_string(),
                    is_signer: false,
                    is_writable: false,
                    is_optional: false,
                    docs: Some("Rent sysvar".to_string()),
                },
            ],
            args: vec![],
            discriminator: vec![1],
            docs: Some("Initializes a new account to hold tokens".to_string()),
        });
        
        // Transfer instruction
        instructions.push(Instruction {
            name: "transfer".to_string(),
            accounts: vec![
                AccountMeta {
                    name: "source".to_string(),
                    is_signer: false,
                    is_writable: true,
                    is_optional: false,
                    docs: Some("Source account".to_string()),
                },
                AccountMeta {
                    name: "destination".to_string(),
                    is_signer: false,
                    is_writable: true,
                    is_optional: false,
                    docs: Some("Destination account".to_string()),
                },
                AccountMeta {
                    name: "authority".to_string(),
                    is_signer: true,
                    is_writable: false,
                    is_optional: false,
                    docs: Some("Owner of the source account".to_string()),
                },
            ],
            args: vec![
                Argument {
                    name: "amount".to_string(),
                    ty: "u64".to_string(),
                    docs: Some("Amount to transfer".to_string()),
                },
            ],
            discriminator: vec![3],
            docs: Some("Transfers tokens from one account to another".to_string()),
        });
        
        // Add more SPL Token instructions here...
        
        // MintTo instruction
        instructions.push(Instruction {
            name: "mintTo".to_string(),
            accounts: vec![
                AccountMeta {
                    name: "mint".to_string(),
                    is_signer: false,
                    is_writable: true,
                    is_optional: false,
                    docs: Some("The mint".to_string()),
                },
                AccountMeta {
                    name: "destination".to_string(),
                    is_signer: false,
                    is_writable: true,
                    is_optional: false,
                    docs: Some("The account to mint tokens to".to_string()),
                },
                AccountMeta {
                    name: "authority".to_string(),
                    is_signer: true,
                    is_writable: false,
                    is_optional: false,
                    docs: Some("The mint's minting authority".to_string()),
                },
            ],
            args: vec![
                Argument {
                    name: "amount".to_string(),
                    ty: "u64".to_string(),
                    docs: Some("Amount to mint".to_string()),
                },
            ],
            discriminator: vec![7],
            docs: Some("Mints new tokens to an account".to_string()),
        });
        
        // Burn instruction
        instructions.push(Instruction {
            name: "burn".to_string(),
            accounts: vec![
                AccountMeta {
                    name: "account".to_string(),
                    is_signer: false,
                    is_writable: true,
                    is_optional: false,
                    docs: Some("The account to burn from".to_string()),
                },
                AccountMeta {
                    name: "mint".to_string(),
                    is_signer: false,
                    is_writable: true,
                    is_optional: false,
                    docs: Some("The token mint".to_string()),
                },
                AccountMeta {
                    name: "authority".to_string(),
                    is_signer: true,
                    is_writable: false,
                    is_optional: false,
                    docs: Some("Owner of the account".to_string()),
                },
            ],
            args: vec![
                Argument {
                    name: "amount".to_string(),
                    ty: "u64".to_string(),
                    docs: Some("Amount to burn".to_string()),
                },
            ],
            discriminator: vec![8],
            docs: Some("Burns tokens from an account".to_string()),
        });
    }
    
    // For other program families, try to extract instructions from transactions
    if instructions.is_empty() && !transactions.is_empty() {
        info!("Attempting to extract instructions from transactions for program {}", program_id);
        // Implementation for extracting from transactions would go here
    }
    
    // If we still don't have instructions, try to infer from function analysis
    if instructions.is_empty() && !functions.is_empty() {
        info!("Attempting to infer instructions from function analysis for program {}", program_id);
        // Implementation for inferring from functions would go here
    }
    
    Ok(instructions)
}