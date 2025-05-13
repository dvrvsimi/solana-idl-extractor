//! Anchor program analysis for Solana programs

use anyhow::{Result, anyhow, Context};
use log::{info, debug};
use solana_pubkey::Pubkey;
use crate::analyzer::bytecode::parser::SimpleContextObject;
use crate::models::instruction::Instruction;
use crate::models::account::Account;
use crate::models::idl::IDL;
use crate::constants::anchor::{ANCHOR_VERSION_PREFIX};
use crate::utils::pattern::find_pattern;
use crate::utils::hash::generate_anchor_discriminator;
use crate::utils::anchor::{extract_anchor_version, find_string, extract_instruction_handlers};
use std::collections::{HashMap, BTreeMap};
use std::sync::Arc;
use solana_sbpf::{elf::Executable, program::BuiltinProgram, static_analysis::Analysis};
use crate::analyzer::bytecode::extract_program_name;

/// Anchor program analysis results
pub struct AnchorAnalysis {
    /// Extracted instructions
    pub instructions: Vec<Instruction>,
    /// Extracted accounts
    pub accounts: Vec<Account>,
    /// Error codes
    pub error_codes: HashMap<u32, String>,
    /// Is this an Anchor program?
    pub is_anchor: bool,
    /// Anchor version if detected
    pub anchor_version: Option<String>,
    /// Metadata for extensibility
    pub metadata: BTreeMap<String, String>,
    /// Raw handler names found in binary
    pub handler_names: Vec<String>,
    /// Diagnostics or warnings
    pub diagnostics: Vec<String>,
}

/// Check if a program is an Anchor program by examining various indicators
pub fn is_anchor_program(program_data: &[u8]) -> bool {
    // Method 1: Check for Anchor's characteristic string patterns
    if let Some(version) = extract_anchor_version(program_data, ANCHOR_VERSION_PREFIX) {
        info!("Detected Anchor program with version: {}", version);
        return true;
    }
    
    // Method 2: Look for Anchor discriminator patterns in the code
    // This looks for code that checks the first 8 bytes of an account or instruction
    let discriminator_check_pattern = [
        // Load 8 bytes (discriminator length)
        0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    
    // we need additional confirmation
    if find_pattern(program_data, &discriminator_check_pattern) {
        // Only consider it Anchor if we also find Anchor-specific error codes
        let anchor_error_patterns: [&[u8]; 3] = [
            // ConstraintMut (2000)
            &[0xd0, 0x07, 0x00, 0x00],
            // AccountDiscriminatorNotFound (3001)
            &[0xb9, 0x0b, 0x00, 0x00],
            // AccountDiscriminatorMismatch (3002)
            &[0xba, 0x0b, 0x00, 0x00],
        ];
        
        let has_anchor_errors = anchor_error_patterns.iter()
            .any(|pattern| find_pattern(program_data, pattern));
            
        if has_anchor_errors {
            debug!("Detected Anchor program based on error codes");
            return true;
        }
    }
    
    // Method 3: Check for Anchor string literals
    const ANCHOR_STRINGS: [&[u8]; 6] = [
    b"anchor",
    b"Anchor",
    b"#[account]",
    b"#[program]",
    b"#[instruction]",
    b"#[error]",
];
    
    for &pattern in &ANCHOR_STRINGS {
        if find_string(program_data, pattern) {
            debug!("Detected Anchor program based on string literals");
            return true;
        }
    }
    
    false
}

/// Analyze an Anchor program
pub fn analyze(program_id: &Pubkey, program_data: &[u8]) -> Result<AnchorAnalysis> {
    info!("Analyzing Anchor program: {}", program_id);
    
    if !is_anchor_program(program_data) {
        return Err(anyhow!("Not an Anchor program"));
    }
    
    // Extract instruction handlers
    let handler_names = extract_instruction_handlers(program_data)
        .context("Failed to extract instruction handlers")?;
    
    let mut instructions = Vec::new();
    
    // Create instructions from handler names
    for (i, name) in handler_names.iter().enumerate() {
        let mut instruction = Instruction::new(name.clone(), i as u8);
        
        // Add discriminator
        let discriminator = generate_anchor_discriminator(name);
        instruction.discriminator = Some(discriminator);
        
        // Add generic arguments and accounts
        // These will be refined later through transaction analysis
        instruction.add_arg("data".to_string(), "bytes".to_string());
        instruction.add_account("authority".to_string(), true, false, false);
        
        instructions.push(instruction);
    }
    
    // --- Create SBPF analysis (mirroring bytecode/mod.rs) ---
    let elf_bytes = crate::analyzer::bytecode::extract_elf_bytes(program_data)?;

    let loader = Arc::new(BuiltinProgram::new_mock());

    let executable = Executable::<SimpleContextObject>::from_elf(elf_bytes, loader.clone())
        .map_err(|e| anyhow!("Failed to create executable: {}", e))?;

    let analysis = Analysis::from_executable(&executable)
        .map_err(|e| anyhow!("Failed to analyze executable: {}", e))?;
    // --------------------------------------------------------
    
    // Extract account structures
    let accounts = crate::analyzer::bytecode::account_analyzer::extract_account_structures(
        program_data,
        &analysis,
    )
    .map_err(|e| anyhow!("Failed to extract account structures: {}", e))?;
    
    // Extract custom error codes
    let error_codes = extract_custom_error_codes(program_data)
        .context("Failed to extract error codes")?;
    
    // Anchor version
    let anchor_version = extract_anchor_version(program_data, ANCHOR_VERSION_PREFIX);

    // Metadata
    let mut metadata = BTreeMap::new();
    if let Some(ref v) = anchor_version {
        metadata.insert("anchor_version".to_string(), v.clone());
    }
    metadata.insert("program_id".to_string(), program_id.to_string());

    // Diagnostics (TODO: add proper diagnostics)
    let diagnostics = Vec::new();

    Ok(AnchorAnalysis {
        instructions,
        accounts,
        error_codes,
        is_anchor: true,
        anchor_version,
        metadata,
        handler_names,
        diagnostics,
    })
}

/// Enhance IDL with Anchor-specific information
pub fn enhance_idl(idl: &mut IDL, program_data: &[u8]) -> Result<()> {
    if !is_anchor_program(program_data) {
        return Ok(());
    }
    
    // Set Anchor-specific metadata
    idl.metadata.origin = "anchor".to_string();
    
    // Try to extract Anchor version
    if let Some(version) = extract_anchor_version(program_data, ANCHOR_VERSION_PREFIX) {
        idl.metadata.framework_version = Some(version);
    }
    
    // Set metadata name and notes
    let program_name = extract_program_name(program_data)
        .unwrap_or_else(|_| "Unknown Program".to_string());
    idl.metadata.metadata_name = program_name;
    idl.metadata.notes = Some("Extracted from Anchor program".to_string());
    
    // Extract custom error codes
    let error_codes = extract_custom_error_codes(program_data)
        .context("Failed to extract error codes")?;
    
    // Add error codes to IDL
    for (code, name) in error_codes {
        idl.add_error(code, name.clone(), name);
    }
    
    Ok(())
}

/// Extract custom error codes from program data
pub fn extract_custom_error_codes(program_data: &[u8]) -> Result<HashMap<u32, String>> {
    // Start with standard Anchor error codes
    let mut error_codes = crate::constants::anchor::error_codes();
    
    // Try to parse the ELF file
    let elf_analyzer = crate::analyzer::bytecode::elf::ElfAnalyzer::from_bytes(program_data.to_vec())?;
    
    // Extract strings from the rodata section
    if let Ok(Some(_rodata)) = elf_analyzer.get_rodata_section() {
        // Look for error message patterns
        let error_patterns = [
            "Error: ",
            "error: ",
            "ERROR: ",
            "#[error(",
            "pub enum Error",
            "enum Error",
        ];
        
        let strings = elf_analyzer.extract_strings()?;
        
        // Track custom error codes we find
        let mut custom_error_code = 6000; // Anchor custom errors typically start at 6000
        
        for string in strings {
            // Check for error definition patterns
            for pattern in &error_patterns {
                if string.contains(pattern) {
                    // Extract error name
                    let error_name = if string.contains("#[error(") {
                        // Parse error attribute format: #[error("error message")]
                        if let Some(start) = string.find("#[error(\"") {
                            if let Some(end) = string[start + 9..].find("\"") {
                                string[start + 9..start + 9 + end].to_string()
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    } else if string.starts_with("Error: ") || string.starts_with("error: ") || string.starts_with("ERROR: ") {
                        // Simple error message format
                        let prefix_len = if string.starts_with("ERROR: ") { 7 } else { 7 };
                        string[prefix_len..].trim().to_string()
                    } else if string.contains("enum Error") {
                        // This is likely an error enum definition
                        // We'd need to parse the enum variants, but for now just note it
                        "CustomError".to_string()
                    } else {
                        continue;
                    };
                    
                    // Add to our error codes if not already present
                    if !error_name.is_empty() && !error_codes.values().any(|v| v == &error_name) {
                        error_codes.insert(custom_error_code, error_name);
                        custom_error_code += 1;
                    }
                    
                    break;
                }
            }
        }
    }
    
    // Look for error code constants in the text section
    if let Ok(Some(text)) = elf_analyzer.get_text_section() {
        // Parse instructions to find error code loading
        if let Ok(instructions) = crate::analyzer::bytecode::parser::parse_instructions(&text.data, text.address as usize) {
            for window in instructions.windows(2) {
                // Look for pattern: load immediate value followed by comparison or function call
                // This often indicates an error code being used
                if window[0].is_mov_imm() && window[0].imm >= 6000 && window[0].imm < 7000 {
                    // This is likely a custom error code in the Anchor range
                    let error_code = window[0].imm as u32;
                    
                    // If we don't already have this code, add it with a generic name
                    if !error_codes.contains_key(&error_code) {
                        error_codes.insert(error_code, format!("CustomError{}", error_code - 6000));
                    }
                }
            }
        }
    }
    
    Ok(error_codes)
} 