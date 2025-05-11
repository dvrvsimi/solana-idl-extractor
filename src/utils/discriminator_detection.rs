//! Utility functions for detecting and analyzing discriminators in Solana programs

use crate::analyzer::bytecode::parser::SbfInstruction;
use crate::constants::opcodes::opcodes;
use crate::utils::hash::generate_anchor_discriminator;
use std::collections::HashMap;

/// Check if an instruction sequence is validating an Anchor account
pub fn is_anchor_account_validation(instructions: &[SbfInstruction], idx: usize) -> bool {
    // Need at least 3 instructions to check
    if idx + 3 >= instructions.len() {
        return false;
    }
    
    // Pattern 1: Load 8 bytes from account data (discriminator)
    let is_loading_discriminator = instructions[idx].is_load() && 
                                  instructions[idx].size == 8 && 
                                  instructions[idx].offset == 0;
    
    // Pattern 2: Compare loaded bytes with expected discriminator
    let is_comparing = instructions[idx + 1].is_branch() && 
                      (instructions[idx + 1].opcode == opcodes::JEQ_IMM || 
                       instructions[idx + 1].opcode == opcodes::JEQ_REG ||
                       instructions[idx + 1].opcode == opcodes::JNE_IMM ||
                       instructions[idx + 1].opcode == opcodes::JNE_REG);
    
    // Pattern 3: Branch to error handler if comparison fails
    let is_branching_to_error = instructions[idx + 2].is_branch() || 
                               instructions[idx + 2].is_exit();
    
    // All patterns must match
    is_loading_discriminator && is_comparing && is_branching_to_error
}

/// Check if an instruction sequence is validating an Anchor instruction
pub fn is_anchor_instruction_validation(instructions: &[SbfInstruction], idx: usize) -> bool {
    // Need at least 3 instructions to check
    if idx + 3 >= instructions.len() {
        return false;
    }
    
    // Pattern 1: Load 8 bytes from instruction data (discriminator)
    let is_loading_discriminator = instructions[idx].is_load() && 
                                  instructions[idx].size == 8 && 
                                  instructions[idx].src_reg == 1; // r1 typically holds instruction data
    
    // Pattern 2: Compare loaded bytes with expected discriminator
    let is_comparing = instructions[idx + 1].is_branch() && 
                      (instructions[idx + 1].opcode == opcodes::JEQ_IMM || 
                       instructions[idx + 1].opcode == opcodes::JEQ_REG ||
                       instructions[idx + 1].opcode == opcodes::JNE_IMM ||
                       instructions[idx + 1].opcode == opcodes::JNE_REG);
    
    // Pattern 3: Branch to handler or error if comparison matches/fails
    let is_branching = instructions[idx + 2].is_branch();
    
    // All patterns must match
    is_loading_discriminator && is_comparing && is_branching
}

/// Extract potential discriminator values from instructions
pub fn extract_discriminator_values(instructions: &[SbfInstruction]) -> Vec<[u8; 8]> {
    let mut discriminators = Vec::new();
    
    for window in instructions.windows(3) {
        // Look for comparison with immediate value after loading
        if window[0].is_load() && window[1].is_branch() && 
           (window[1].opcode == opcodes::JEQ_IMM || window[1].opcode == opcodes::JNE_IMM) {
            
            // The immediate value might be part of a discriminator
            let imm_value = window[1].imm as u64;
            let bytes = imm_value.to_le_bytes();
            
            // Check if this looks like a discriminator (non-zero, not all ASCII)
            let is_nonzero = bytes.iter().any(|&b| b != 0);
            let is_not_ascii = bytes.iter().any(|&b| b > 127);
            
            if is_nonzero && is_not_ascii {
                // This might be a discriminator
                let mut discriminator = [0u8; 8];
                discriminator.copy_from_slice(&bytes);
                discriminators.push(discriminator);
            }
        }
    }
    
    discriminators
}

/// Try to match discriminators with common Anchor instruction names
pub fn match_discriminators_with_names(discriminators: &[[u8; 8]]) -> HashMap<[u8; 8], String> {
    let mut matches = HashMap::new();
    
    // Common Anchor instruction names to try
    let common_instructions = [
        "initialize", "update", "create", "delete", "transfer", "mint", "burn",
        "set_authority", "close", "deposit", "withdraw", "swap", "stake", "unstake",
        "claim", "vote", "propose", "execute", "cancel", "approve", "revoke",
    ];
    
    for &discriminator in discriminators {
        for name in &common_instructions {
            let generated = generate_anchor_discriminator(name);
            if generated == discriminator {
                matches.insert(discriminator, name.to_string());
                break;
            }
        }
    }
    
    matches
}

/// Check if bytes are likely an Anchor discriminator
pub fn is_likely_anchor_discriminator(bytes: &[u8; 8]) -> bool {
    // Anchor discriminators are SHA256 hashes, so they should look random
    // But we can check for some patterns that are unlikely in real discriminators
    
    // Check if all bytes are ASCII
    let all_ascii = bytes.iter().all(|&b| b < 128);
    if all_ascii {
        return false;
    }
    
    // Check if bytes are all zeros or all ones
    let all_zeros = bytes.iter().all(|&b| b == 0);
    let all_ones = bytes.iter().all(|&b| b == 0xFF);
    if all_zeros || all_ones {
        return false;
    }
    
    // Check for simple patterns
    let is_simple_pattern = bytes.windows(2).all(|w| w[0] == w[1]) ||
                           bytes.windows(2).all(|w| w[0] + 1 == w[1]);
    if is_simple_pattern {
        return false;
    }
    
    // It's likely a discriminator
    true
} 