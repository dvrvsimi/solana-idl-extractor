//! Error code analysis utilities for Solana programs

use anyhow::Result;
use std::collections::HashMap;
use crate::analyzer::bytecode::parser::SbfInstruction;
use solana_sbpf::{
    static_analysis::Analysis,
    program::SBPFVersion,
};

/// Extract error codes from program instructions
pub fn extract_error_codes(instructions: &[SbfInstruction], analysis: &Analysis) -> Result<HashMap<u32, String>> {
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
                let name = infer_error_name(potential_error_code, instructions, analysis);
                
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
fn infer_error_name(code: u32, instructions: &[SbfInstruction], analysis: &Analysis) -> String {
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

/// Add native program error codes
fn add_native_error_codes(error_codes: &mut HashMap<u32, String>) {
    // Native program error codes (non-Anchor)
    let native_errors = [
        // System program errors
        (1, "SystemError"),
        (2, "InsufficientFunds"),
        (3, "InvalidArgument"),
        
        // Token program errors
        (100, "TokenError"),
        (101, "InsufficientFunds"),
        (102, "InvalidMint"),
        (103, "InvalidOwner"),
        
        // Common native program errors
        (1000, "InvalidInstruction"),
        (1001, "InvalidAccount"),
        (1002, "InvalidData"),
        (1003, "InvalidOwner"),
        (1004, "InvalidSigner"),
        (1005, "InvalidProgramId"),
        (1006, "InvalidAccountData"),
        (1007, "InvalidAccountOwner"),
        (1008, "InvalidAccountSize"),
        (1009, "InvalidAccountType"),
        (1010, "InvalidAccountState"),
    ];
    
    for (code, name) in native_errors.iter() {
        if !error_codes.contains_key(code) {
            error_codes.insert(*code, name.to_string());
        }
    }
}

/// Add native program error patterns
fn is_native_error_handler(window: &[SbfInstruction]) -> bool {
    // Native programs often use simpler error patterns:
    // 1. Load error code
    // 2. Return/exit
    // Or:
    // 1. Compare
    // 2. Branch to error handler
    // 3. Return/exit
    
    (window[0].is_mov_imm() && window[1].is_exit()) ||
    (window[0].is_branch() && window[1].is_mov_imm() && window[2].is_exit())
}

/// Add native program error context analysis
fn analyze_native_error_context(
    instructions: &[SbfInstruction],
    handler_idx: usize,
    analysis: &Analysis
) -> Option<ErrorContext> {
    let mut context = ErrorContext {
        error_code: None,
        error_type: None,
        error_message: None,
        stack_trace: None,
        affected_accounts: Vec::new(),
        error_chain: Vec::new(),
    };
    
    // Look for native program error patterns
    let start = handler_idx.saturating_sub(10);
    let end = (handler_idx + 10).min(instructions.len());
    
    // Find error code and affected accounts
    for i in start..end {
        let insn = &instructions[i];
        
        // Check for error code
        if insn.is_mov_imm() {
            context.error_code = Some(insn.imm as u32);
        }
        
        // Check for account references
        if insn.is_load() && insn.src_reg == 2 { // r2 typically holds accounts array
            context.affected_accounts.push(format!("account_{}", insn.offset));
        }
    }
    
    // Try to infer error type
    if let Some(code) = context.error_code {
        context.error_type = infer_native_error_type(code);
    }
    
    Some(context)
}

/// Add native program error type inference
fn infer_native_error_type(code: u32) -> Option<String> {
    match code {
        // System program errors
        1..=99 => Some("SystemError".to_string()),
        
        // Token program errors
        100..=199 => Some("TokenError".to_string()),
        
        // Common native program errors
        1000..=1999 => Some("ProgramError".to_string()),
        2000..=2999 => Some("AccountError".to_string()),
        3000..=3999 => Some("DataError".to_string()),
        4000..=4999 => Some("StateError".to_string()),
        5000..=5999 => Some("ValidationError".to_string()),
        6000..=6999 => Some("CustomError".to_string()),
        _ => None,
    }
}

/// Analyze error handling patterns in the program
pub fn analyze_error_handling(
    instructions: &[SbfInstruction], 
    analysis: &Analysis,
    version: SBPFVersion
) -> Result<ErrorAnalysis> {
    let mut result = ErrorAnalysis {
        error_codes: HashMap::new(),
        error_handlers: Vec::new(),
        error_contexts: HashMap::new(),
    };
    
    // Add native error codes
    add_native_error_codes(&mut result.error_codes);
    
    // Find error handlers using native patterns
    for (i, window) in instructions.windows(3).enumerate() {
        if is_native_error_handler(window) {
            result.error_handlers.push(i);
        }
    }
    
    // Analyze error contexts
    for &handler_idx in &result.error_handlers {
        if let Some(context) = analyze_native_error_context(instructions, handler_idx, analysis) {
            result.error_contexts.insert(handler_idx, context);
        }
    }
    
    // Verify error handling
    verify_error_handling(instructions, &result.error_codes)?;
    
    Ok(result)
}

/// Add verification
///
/// error_codes: HashMap of error codes to check for usage in the instructions.
fn verify_error_handling(
    instructions: &[SbfInstruction],
    error_codes: &std::collections::HashMap<u32, String>,
) -> Result<()> {
    // TODO: Advanced: Analyze control flow to find error handler blocks
    // For now, only verify that error codes are properly handled
    for code in error_codes.keys() {
        if !instructions.iter().any(|insn| insn.is_mov_imm() && insn.imm == *code as i64) {
            return Err(anyhow::anyhow!("Error code {} is defined but never used", code));
        }
    }
    Ok(())
}

/// Results of error analysis
#[derive(Debug)]
pub struct ErrorAnalysis {
    /// Extracted error codes
    pub error_codes: HashMap<u32, String>,
    /// Indices of error handlers
    pub error_handlers: Vec<usize>,
    /// Context for each error handler
    pub error_contexts: HashMap<usize, ErrorContext>,
}

/// Context information for an error handler
#[derive(Debug)]
pub struct ErrorContext {
    /// Error code being handled
    pub error_code: Option<u32>,
    /// Type of error
    pub error_type: Option<String>,
    /// Error message if available
    pub error_message: Option<String>,
    /// Stack trace if available
    pub stack_trace: Option<String>,
    /// Affected accounts if available
    pub affected_accounts: Vec<String>,
    /// Error chain if available
    pub error_chain: Vec<String>,
} 