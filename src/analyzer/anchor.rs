//! Anchor program analysis for Solana programs

use anyhow::{Result, anyhow, Context};
use log::{info, debug, warn};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::hash::hash;
use crate::models::instruction::Instruction;
use crate::models::account::Account;
use crate::models::idl::IDL;
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

/// Check if a program is an Anchor program
pub fn is_anchor_program(program_data: &[u8]) -> bool {
    // Check for Anchor's characteristic log message pattern
    // Anchor inserts "Instruction: X" log messages at the start of handlers
    let pattern = b"Instruction: ";
    program_data.windows(pattern.len()).any(|window| window == pattern)
}

/// Generate an Anchor instruction discriminator
pub fn generate_discriminator(name: &str) -> [u8; 8] {
    let mut result = [0u8; 8];
    let hash_bytes = hash(format!("global:{}", name).as_bytes()).to_bytes();
    result.copy_from_slice(&hash_bytes[..8]);
    result
}

/// Extract instruction handlers from an Anchor program
pub fn extract_instruction_handlers(program_data: &[u8]) -> Result<Vec<String>> {
    let mut handlers = Vec::new();
    let pattern = b"Instruction: ";
    
    // Find all occurrences of "Instruction: X" in the program data
    for (i, window) in program_data.windows(pattern.len()).enumerate() {
        if window == pattern {
            // Extract the instruction name
            let start = i + pattern.len();
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
    let mut error_codes = HashMap::new();
    
    // Create instructions from handler names
    for (i, name) in handler_names.iter().enumerate() {
        let mut instruction = Instruction::new(name.clone(), i as u8);
        
        // Add discriminator
        let discriminator = generate_discriminator(name);
        instruction.discriminator = Some(discriminator);
        
        // Add generic arguments and accounts
        // These will be refined later through transaction analysis
        instruction.add_arg("data".to_string(), "bytes".to_string());
        instruction.add_account("authority".to_string(), true, false, false);
        
        instructions.push(instruction);
    }
    
    // Add common Anchor error codes
    error_codes.insert(2000, "ConstraintMut".to_string());
    error_codes.insert(2002, "ConstraintSigner".to_string());
    error_codes.insert(2005, "ConstraintRentExempt".to_string());
    error_codes.insert(2006, "ConstraintSeeds".to_string());
    error_codes.insert(3001, "AccountDiscriminatorNotFound".to_string());
    error_codes.insert(3005, "AccountNotEnoughKeys".to_string());
    error_codes.insert(3010, "AccountNotSigner".to_string());
    
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
    let error_codes = extract_error_codes(program_data);
    for (code, name) in error_codes {
        idl.add_error(code, name.clone(), name);
    }
    
    Ok(())
}

/// Extract Anchor version from program data
fn extract_anchor_version(program_data: &[u8]) -> Option<String> {
    // Look for version pattern in rodata section
    let pattern = b"anchor-";
    for (i, window) in program_data.windows(pattern.len()).enumerate() {
        if window == pattern {
            let start = i + pattern.len();
            let mut end = start;
            while end < program_data.len() && 
                  (program_data[end].is_ascii_digit() || program_data[end] == b'.') {
                end += 1;
            }
            
            if let Ok(version) = std::str::from_utf8(&program_data[start..end]) {
                if !version.is_empty() {
                    return Some(version.to_string());
                }
            }
        }
    }
    
    None
}

/// Extract error codes from program data
fn extract_error_codes(program_data: &[u8]) -> HashMap<u32, String> {
    let mut error_codes = HashMap::new();
    
    // Add common Anchor error codes
    error_codes.insert(2000, "ConstraintMut".to_string());
    error_codes.insert(2002, "ConstraintSigner".to_string());
    error_codes.insert(2005, "ConstraintRentExempt".to_string());
    error_codes.insert(2006, "ConstraintSeeds".to_string());
    error_codes.insert(3001, "AccountDiscriminatorNotFound".to_string());
    error_codes.insert(3005, "AccountNotEnoughKeys".to_string());
    error_codes.insert(3010, "AccountNotSigner".to_string());
    
    // Look for custom error codes in the program data
    // This is a simplified approach - a more robust implementation would parse the ELF sections
    
    error_codes
} 