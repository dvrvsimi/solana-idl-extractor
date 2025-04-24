//! Anchor program analysis for Solana programs

use anyhow::{Result, anyhow, Context};
use log::{info, debug, warn};
use solana_pubkey::Pubkey;
use crate::models::instruction::Instruction;
use crate::models::account::Account;
use crate::models::idl::IDL;
use crate::constants::anchor::{INSTRUCTION_PREFIX, ANCHOR_VERSION_PREFIX, ANCHOR_PATTERNS};
use crate::utils::pattern::{find_pattern, extract_after_pattern};
use crate::utils::hash::generate_anchor_discriminator;
use std::collections::{HashMap, HashSet};

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
}

/// Check if a program is an Anchor program by examining various indicators
pub fn is_anchor_program(program_data: &[u8]) -> bool {
    // Method 1: Check for Anchor's characteristic string patterns
    if ANCHOR_PATTERNS.iter().any(|pattern| find_pattern(program_data, pattern)) {
        return true;
    }
    
    // Method 2: Look for Anchor version string
    if extract_anchor_version(program_data).is_some() {
        return true;
    }
    
    // Method 3: Check for Anchor discriminator patterns in the code
    // This looks for code that checks the first 8 bytes of an account or instruction
    let discriminator_check_pattern = [
        // Load 8 bytes (discriminator length)
        0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    
    if find_pattern(program_data, &discriminator_check_pattern) {
        return true;
    }
    
    // Method 4: Check for Anchor error codes
    // Many Anchor programs contain these specific error codes
    let error_code_patterns = [
        // ConstraintMut (2000)
        0xd0, 0x07, 0x00, 0x00,
        // AccountDiscriminatorNotFound (3001)
        0xb9, 0x0b, 0x00, 0x00,
    ];
    
    for pattern in &error_code_patterns {
        if find_pattern(program_data, pattern) {
            return true;
        }
    }
    
    false
}

/// Extract instruction handlers from an Anchor program
pub fn extract_instruction_handlers(program_data: &[u8]) -> Result<Vec<String>> {
    let mut handlers = Vec::new();
    
    // Find all occurrences of "Instruction: X" in the program data
    for (i, window) in program_data.windows(INSTRUCTION_PREFIX.len()).enumerate() {
        if window == INSTRUCTION_PREFIX {
            // Extract the instruction name
            let start = i + INSTRUCTION_PREFIX.len();
            let mut end = start;
            while end < program_data.len() && program_data[end] != 0 && program_data[end] != b'\n' {
                end += 1;
            }
            
            if let Ok(name) = std::str::from_utf8(&program_data[start..end]) {
                if !name.is_empty() && !handlers.contains(&name.to_string()) {
                    handlers.push(name.to_string());
                }
            }
        }
    }
    
    debug!("Found {} instruction handlers", handlers.len());
    Ok(handlers)
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
    let mut accounts = Vec::new();
    
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
    
    // Get common Anchor error codes
    let error_codes = crate::constants::anchor::error_codes();
    
    Ok(AnchorAnalysis {
        instructions,
        accounts,
        error_codes,
        is_anchor: true,
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
    if let Some(version) = extract_anchor_version(program_data) {
        idl.metadata.framework_version = Some(version);
    }
    
    // Add error codes
    let error_codes = crate::constants::anchor::error_codes();
    for (code, name) in error_codes {
        idl.add_error(code, name.clone(), name);
    }
    
    Ok(())
}

/// Extract Anchor version from program data
fn extract_anchor_version(program_data: &[u8]) -> Option<String> {
    // Look for version pattern in rodata section
    extract_after_pattern(program_data, ANCHOR_VERSION_PREFIX, &[0, b'\n', b' '])
} 