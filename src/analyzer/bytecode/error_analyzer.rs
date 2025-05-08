//! Error code analyzer for Solana programs

use anyhow::Result;
use std::collections::HashMap;
use super::parser::SbfInstruction;

/// Extract error codes from program instructions
pub fn extract_error_codes(instructions: &[SbfInstruction]) -> Result<HashMap<u32, String>> {
    let mut error_codes = HashMap::new();
    
    // Add standard Solana error codes
    add_standard_error_codes(&mut error_codes);
    
    // Look for error code patterns in the instructions
    for window in instructions.windows(2) {
        // Common pattern: Load immediate value followed by comparison or return
        // This often indicates an error code being used
        if window[0].is_mov_imm() && window[0].imm > 0 {
            let potential_error_code = window[0].imm as u32;
            
            // Check if this looks like an error code (typically in certain ranges)
            if (potential_error_code >= 100 && potential_error_code < 10000) || 
               (potential_error_code >= 0x100 && potential_error_code <= 0xFFFF) {
                
                // Try to find a meaningful name for this error code
                let name = infer_error_name(potential_error_code, instructions);
                
                // Add to our map with the inferred name
                if !error_codes.contains_key(&potential_error_code) {
                    error_codes.insert(potential_error_code, name);
                }
            }
        }
    }
    
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

/// Try to infer a meaningful name for an error code
fn infer_error_name(code: u32, instructions: &[SbfInstruction]) -> String {
    // Look for error handling patterns in instructions
    let has_error_check = instructions.iter().any(|insn| 
        insn.is_mov_imm() && insn.imm == code as i64
    );

    // Common error name patterns
    let patterns = [
        (100..1000, "ValidationError"),
        (1000..2000, "StateError"),
        (2000..3000, "ConstraintError"),
        (3000..4000, "AccountError"),
        (4000..5000, "InstructionError"),
        (5000..6000, "ProgramError"),
        (6000..7000, "CustomError"),
    ];
    
    // Find matching pattern
    for (range, prefix) in patterns.iter() {
        if range.contains(&code) {
            return format!("{}{}{}", prefix, code - range.start, 
                if has_error_check { "_used" } else { "" });
        }
    }
    
    // Default name
    format!("Error{}{}", code, if has_error_check { "_used" } else { "" })
} 