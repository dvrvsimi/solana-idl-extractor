//! Error code analyzer for Solana programs

use anyhow::Result;
use std::collections::HashMap;
use super::parser::SbfInstruction;
use crate::utils::error_analysis::{
    extract_error_codes as utils_extract_error_codes,
    analyze_error_handling, 
    ErrorAnalysis,
    ErrorContext
};
use solana_sbpf::{
    static_analysis::Analysis,
    program::SBPFVersion,
};

/// Extract error codes from program instructions
pub fn extract_error_codes(instructions: &[SbfInstruction], analysis: &Analysis) -> Result<HashMap<u32, String>> {
    utils_extract_error_codes(instructions, analysis)
}

/// Analyze error handling in the program
pub fn analyze_errors(
    instructions: &[SbfInstruction], 
    analysis: &Analysis,
    version: SBPFVersion
) -> Result<ErrorAnalysis> {
    crate::utils::error_analysis::analyze_error_handling(instructions, analysis, version)
}

/// Get error context for a specific handler
pub fn get_error_context(
    instructions: &[SbfInstruction],
    handler_idx: usize,
    analysis: &Analysis
) -> Option<ErrorContext> {
    // Extract error context from the handler
    let mut context = ErrorContext {
        error_code: None,
        error_type: None,
        error_message: None,
        stack_trace: None,
        affected_accounts: Vec::new(),
        error_chain: Vec::new(),
    };

    // Look at instructions around the handler
    let start = handler_idx.saturating_sub(5);
    let end = (handler_idx + 5).min(instructions.len());

    for i in start..end {
        let insn = &instructions[i];
        
        // Check for error code
        if insn.is_mov_imm() {
            context.error_code = Some(insn.imm as u32);
        }
        
        // Check for account references
        if insn.is_load() && insn.src_reg == 2 {
            context.affected_accounts.push(format!("account_{}", insn.offset));
        }
    }

    Some(context)
}

/// Check if an instruction is part of an error handler
pub fn is_error_handler_instruction(instruction: &SbfInstruction) -> bool {
    // Check for common error handler instruction patterns
    instruction.is_mov_imm() || 
    instruction.is_branch() || 
    instruction.is_exit()
}

/// Get error type from error code
pub fn get_error_type(code: u32) -> Option<String> {
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