//! Anchor discriminator detection

use anyhow::{Result, Context};
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use sha2::{Sha256, Digest};

use crate::constants::discriminator::ANCHOR_DISCRIMINATOR_LENGTH;
use crate::utils::hash::generate_anchor_discriminator;
use super::parser::{SbfInstruction, parse_instructions};

/// Anchor discriminator information
#[derive(Debug, Clone)]
pub struct AnchorDiscriminator {
    /// Raw discriminator bytes
    pub bytes: [u8; 8],
    /// Discriminator type (instruction or account)
    pub kind: DiscriminatorKind,
    /// Associated name (if known)
    pub name: Option<String>,
    /// Instruction code (if applicable)
    pub code: Option<u8>,
}

/// Discriminator type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscriminatorKind {
    /// Instruction discriminator
    Instruction,
    /// Account discriminator
    Account,
}

/// Extract Anchor discriminators from bytecode
pub fn extract_discriminators(program_data: &[u8]) -> Result<Vec<AnchorDiscriminator>> {
    let mut discriminators = Vec::new();
    
    // Try to parse the ELF file
    let elf_analyzer = crate::analyzer::bytecode::elf::ElfAnalyzer::from_bytes(program_data)?;
    
    // Get the text section (code)
    if let Ok(Some(text_section)) = elf_analyzer.get_text_section() {
        // Parse instructions
        let instructions = parse_instructions(&text_section.data, text_section.address as usize)?;
        
        // Extract discriminators from instruction patterns
        extract_from_instruction_patterns(&instructions, &mut discriminators);
    }
    
    // Get the rodata section (read-only data)
    if let Ok(Some(rodata_section)) = elf_analyzer.get_rodata_section() {
        // Extract discriminators from data patterns
        extract_from_data_patterns(&rodata_section.data, &mut discriminators);
    }
    
    // Try to match discriminators with known names
    match_discriminators_with_names(&mut discriminators);
    
    Ok(discriminators)
}

/// Extract discriminators from instruction patterns
fn extract_from_instruction_patterns(instructions: &[SbfInstruction], discriminators: &mut Vec<AnchorDiscriminator>) {
    // Look for discriminator loading and comparison patterns
    for window in instructions.windows(5) {
        // Pattern 1: Load 8-byte discriminator and compare
        // ldxdw r0, [r2+0]    // Load first 8 bytes from instruction data
        // mov r1, <imm>       // Load immediate value (part of discriminator)
        // mov r3, <imm>       // Load immediate value (part of discriminator)
        // jeq r0, r1, +offset // Compare and jump if equal
        
        if window[0].is_load() && window[0].size == 8 && window[0].offset == 0 &&
           window[0].src_reg == 2 && // r2 often holds instruction data pointer
           (window[1].is_mov_imm() || window[2].is_mov_imm()) &&
           (window[3].is_cmp() || window[3].is_branch()) {
            
            // This is likely a discriminator check
            // Try to reconstruct the discriminator from the immediate values
            
            let mut discriminator = [0u8; 8];
            let mut found = false;
            
            if window[1].is_mov_imm() && window[2].is_mov_imm() {
                // Two 32-bit parts of the discriminator
                let low_bytes = (window[1].imm as u32).to_le_bytes();
                let high_bytes = (window[2].imm as u32).to_le_bytes();
                
                discriminator[0..4].copy_from_slice(&low_bytes);
                discriminator[4..8].copy_from_slice(&high_bytes);
                found = true;
            } else if window[1].is_mov_imm() && window[1].imm > 0 {
                // Single immediate might be a pointer to the discriminator
                // In a real implementation, we'd try to resolve this
                // For now, just note that we found a pattern
                found = true;
            }
            
            if found {
                discriminators.push(AnchorDiscriminator {
                    bytes: discriminator,
                    kind: DiscriminatorKind::Instruction,
                    name: None,
                    code: None,
                });
            }
        }
        
        // Pattern 2: Load discriminator in parts and compare
        // ldxw r0, [r2+0]     // Load first 4 bytes
        // ldxw r1, [r2+4]     // Load next 4 bytes
        // jeq r0, <imm>, +fail // Compare first part
        // jeq r1, <imm>, +next // Compare second part
        
        if window[0].is_load() && window[0].size == 4 && window[0].offset == 0 &&
           window[1].is_load() && window[1].size == 4 && window[1].offset == 4 &&
           window[2].is_branch() && window[3].is_branch() {
            
            // Try to extract discriminator from the comparison values
            if window[2].is_cmp_imm() && window[3].is_cmp_imm() {
                let low_bytes = (window[2].imm as u32).to_le_bytes();
                let high_bytes = (window[3].imm as u32).to_le_bytes();
                
                let mut discriminator = [0u8; 8];
                discriminator[0..4].copy_from_slice(&low_bytes);
                discriminator[4..8].copy_from_slice(&high_bytes);
                
                discriminators.push(AnchorDiscriminator {
                    bytes: discriminator,
                    kind: DiscriminatorKind::Instruction,
                    name: None,
                    code: None,
                });
            }
        }
        
        // Pattern 3: Account discriminator check
        // ldxdw r0, [r3+0]    // Load first 8 bytes from account data
        // mov r1, <imm>       // Load immediate value (part of discriminator)
        // jne r0, r1, +fail   // Compare and jump if not equal
        
        if window[0].is_load() && window[0].size == 8 && window[0].offset == 0 &&
           window[1].is_mov_imm() && window[2].is_branch() {
            
            // This might be an account discriminator check
            let discriminator_imm = window[1].imm;
            let discriminator_bytes = discriminator_imm.to_le_bytes();
            
            // Only use the first 8 bytes
            let mut discriminator = [0u8; 8];
            discriminator.copy_from_slice(&discriminator_bytes[0..8]);
            
            discriminators.push(AnchorDiscriminator {
                bytes: discriminator,
                kind: DiscriminatorKind::Account,
                name: None,
                code: None,
            });
        }
    }
}

/// Extract discriminators from data patterns
fn extract_from_data_patterns(data: &[u8], discriminators: &mut Vec<AnchorDiscriminator>) {
    // Scan for 8-byte patterns that might be discriminators
    for window in data.windows(8) {
        // Check if this looks like a discriminator (non-zero, not all ASCII)
        let is_nonzero = window.iter().any(|&b| b != 0);
        let is_not_ascii = window.iter().any(|&b| b > 127);
        
        if is_nonzero && is_not_ascii {
            // This might be a discriminator
            let mut discriminator = [0u8; 8];
            discriminator.copy_from_slice(window);
            
            // Check if it matches known Anchor discriminator patterns
            if is_likely_anchor_discriminator(&discriminator) {
                discriminators.push(AnchorDiscriminator {
                    bytes: discriminator,
                    kind: DiscriminatorKind::Account, // Default to Account, will refine later
                    name: None,
                    code: None,
                });
            }
        }
    }
}

/// Check if bytes are likely an Anchor discriminator
fn is_likely_anchor_discriminator(bytes: &[u8; 8]) -> bool {
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

/// Try to match discriminators with known names
fn match_discriminators_with_names(discriminators: &mut Vec<AnchorDiscriminator>) {
    // Common Anchor instruction names to try
    let common_instructions = [
        "initialize", "update", "create", "delete", "transfer", "mint", "burn",
        "set_authority", "close", "deposit", "withdraw", "swap", "stake", "unstake",
        "claim", "vote", "propose", "execute", "cancel", "approve", "revoke",
    ];
    
    // Common Anchor account names to try
    let common_accounts = [
        "State", "Config", "User", "Pool", "Vault", "Token", "Mint", "Authority",
        "Escrow", "Stake", "Vote", "Proposal", "Transaction", "Metadata", "Settings",
    ];
    
    // Try to match instruction discriminators
    for discriminator in discriminators.iter_mut() {
        if discriminator.kind == DiscriminatorKind::Instruction {
            for (i, name) in common_instructions.iter().enumerate() {
                let generated = generate_anchor_discriminator(name);
                if generated == discriminator.bytes {
                    discriminator.name = Some(name.to_string());
                    discriminator.code = Some(i as u8);
                    break;
                }
            }
        } else {
            // Try to match account discriminators
            for name in &common_accounts {
                let generated = crate::utils::hash::generate_anchor_account_discriminator(name);
                if generated == discriminator.bytes {
                    discriminator.name = Some(name.to_string());
                    break;
                }
            }
        }
    }
} 