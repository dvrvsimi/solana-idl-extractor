//! Error code analyzer for Solana programs

use anyhow::Result;
use std::collections::HashMap;
use super::parser::SbfInstruction;

/// Extract error codes from program instructions
pub fn extract_error_codes(instructions: &[SbfInstruction]) -> Result<HashMap<u32, String>> {
    let mut error_codes = HashMap::new();
    
    // Look for error code patterns in the instructions
    for window in instructions.windows(2) {
        // Common pattern: Load immediate value followed by comparison or return
        // This often indicates an error code being used
        if window[0].is_mov_imm() && window[0].imm > 0 {
            let potential_error_code = window[0].imm as u32;
            
            // Check if this looks like an error code (typically in certain ranges)
            if (potential_error_code >= 100 && potential_error_code < 10000) || 
               (potential_error_code >= 0x100 && potential_error_code <= 0xFFFF) {
                
                // Add to our map with a generic name
                if !error_codes.contains_key(&potential_error_code) {
                    error_codes.insert(
                        potential_error_code, 
                        format!("Error{}", potential_error_code)
                    );
                }
            }
        }
    }
    
    // Add standard Solana error codes
    add_standard_error_codes(&mut error_codes);
    
    Ok(error_codes)
}

/// Add standard Solana error codes to the map
fn add_standard_error_codes(error_codes: &mut HashMap<u32, String>) {
    // Common Solana program error codes
    let standard_errors = [
        (1, "NotRentExempt"),
        (2, "InsufficientFunds"),
        (3, "InvalidArgument"),
        (4, "InvalidInstructionData"),
        (5, "InvalidAccountData"),
        (6, "AccountDataTooSmall"),
        (7, "InsufficientFunds"),
        (8, "IncorrectProgramId"),
        (9, "MissingRequiredSignature"),
        (10, "AccountAlreadyInitialized"),
        (11, "UninitializedAccount"),
        (12, "InvalidProgramId"),
    ];
    
    for (code, name) in standard_errors.iter() {
        if !error_codes.contains_key(code) {
            error_codes.insert(*code, name.to_string());
        }
    }
} 