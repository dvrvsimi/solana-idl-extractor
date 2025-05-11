//! Anchor discriminator detection

use anyhow::Result;
use log::{debug, info, warn};

use crate::utils::hash::generate_anchor_discriminator;
use super::parser::{SbfInstruction, parse_instructions};
use crate::constants::discriminator::{
    anchor, spl_token, system_program, program_ids,
    ANCHOR_DISCRIMINATOR_LENGTH, ANCHOR_DISCRIMINATOR_NAMESPACE,
    ANCHOR_ACCOUNT_NAMESPACE
};
use crate::utils::discriminator_detection::{
    is_anchor_account_validation,
    is_anchor_instruction_validation,
    extract_discriminator_values,
    match_discriminators_with_names,
    is_likely_anchor_discriminator
};
use crate::constants::opcodes::opcodes;

/// A Solana program instruction discriminator
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discriminator(pub [u8; 8]);

impl Discriminator {
    /// Create a new discriminator from bytes
    pub fn new(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }
    
    /// Get the underlying bytes
    pub fn bytes(&self) -> &[u8; 8] {
        &self.0
    }
    
    /// Convert to a vector of bytes
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Add new types for native program support
#[derive(Debug, Clone)]
pub struct NativeInstructionCode {
    pub code: u8,
    pub name: String,
    pub program_id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum DiscriminatorType {
    Anchor([u8; 8]),
    Native(u8),
    Custom(Vec<u8>),
}

/// Update AnchorDiscriminator to support native programs
#[derive(Debug, Clone)]
pub struct AnchorDiscriminator {
    pub bytes: [u8; 8],
    pub kind: DiscriminatorKind,
    pub name: Option<String>,
    pub code: Option<u8>,
    pub discriminator_type: DiscriminatorType,
    pub program_id: Option<String>,
}

/// Discriminator type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscriminatorKind {
    /// Instruction discriminator
    Instruction,
    /// Account discriminator
    Account,
}

/// Extract discriminators from bytecode with native program support
pub fn extract_discriminators(program_data: &[u8]) -> Result<Vec<AnchorDiscriminator>> {
    let mut discriminators = Vec::new();
    
    // Try to parse the ELF file
    let elf_analyzer = crate::analyzer::bytecode::elf::ElfAnalyzer::from_bytes(program_data.to_vec())?;
    
    // Get the text section (code)
    if let Ok(Some(text_section)) = elf_analyzer.get_text_section() {
        let instructions = parse_instructions(&text_section.data, text_section.address as usize)?;
        
        // First try to detect if this is an Anchor program
        let is_anchor = detect_anchor_program(&instructions);
        
        if is_anchor {
            // Extract Anchor-style discriminators
            extract_from_instruction_patterns(&instructions, &mut discriminators);
        } else {
            // Extract native program instruction codes
            let native_codes = extract_native_instruction_codes(&instructions);
            for code in native_codes {
                discriminators.push(AnchorDiscriminator {
                    bytes: [0; 8], // Not used for native programs
                    kind: DiscriminatorKind::Instruction,
                    name: Some(code.name),
                    code: Some(code.code),
                    discriminator_type: DiscriminatorType::Native(code.code),
                    program_id: code.program_id,
                });
            }
        }
        
        // Extract syscall patterns (works for both Anchor and native)
        extract_from_syscall_patterns(&instructions, &mut discriminators);
    }
    
    // Get the rodata section
    if let Ok(Some(rodata_section)) = elf_analyzer.get_rodata_section() {
        extract_from_data_patterns(&rodata_section.data, &mut discriminators);
    }
    
    // Convert the Vec<AnchorDiscriminator> to a Vec<[u8; 8]> first
    let discriminator_bytes: Vec<[u8; 8]> = discriminators.iter().map(|d| d.bytes).collect();
    let matches = match_discriminators_with_names(&discriminator_bytes);

    // Then update the discriminators with the matched names
    for discriminator in discriminators.iter_mut() {
        if let Some(name) = matches.get(&discriminator.bytes) {
            discriminator.name = Some(name.clone());
        }
    }
    
    Ok(discriminators)
}

/// Detect if program is using Anchor framework
fn detect_anchor_program(instructions: &[SbfInstruction]) -> bool {
    // Look for Anchor-specific patterns:
    // 1. Anchor discriminator loading
    // 2. Anchor account validation
    // 3. Anchor-specific syscalls
    
    for window in instructions.windows(5) {
        // Check for Anchor discriminator pattern
        if is_anchor_discriminator_pattern(window) {
            return true;
        }
        
        // Check for Anchor account validation pattern
        if is_anchor_account_validation(instructions, 0) {
            return true;
        }
        
        // Check for Anchor-specific syscalls
        if window[0].is_syscall() {
            let syscall_id = window[0].imm;
            if syscall_id >= 0x100000 && syscall_id <= 0x1FFFFFF {
                return true;
            }
        }
    }
    
    false
}

/// Extract native instruction codes
fn extract_native_instruction_codes(instructions: &[SbfInstruction]) -> Vec<NativeInstructionCode> {
    let mut codes = Vec::new();
    
    for window in instructions.windows(3) {
        // Pattern: Load 1-byte instruction code
        if window[0].is_load() && window[0].size == 1 && window[0].src_reg == 2 {
            let code = window[0].imm as u8;
            
            // Check for known program patterns
            if let Some(program_id) = detect_program_id(window) {
                match program_id.as_str() {
                    program_ids::TOKEN_PROGRAM => {
                        if let Some(name) = match_token_instruction(code) {
                            codes.push(NativeInstructionCode {
                                code,
                                name,
                                program_id: Some(program_id),
                            });
                        }
                    }
                    program_ids::SYSTEM_PROGRAM => {
                        if let Some(name) = match_system_instruction(code) {
                            codes.push(NativeInstructionCode {
                                code,
                                name,
                                program_id: Some(program_id),
                            });
                        }
                    }
                    _ => {
                        // Unknown program, but still record the code
                        codes.push(NativeInstructionCode {
                            code,
                            name: format!("instruction_{}", code),
                            program_id: Some(program_id),
                        });
                    }
                }
            }
        }
    }
    codes
}

/// Match SPL Token program instruction codes
fn match_token_instruction(code: u8) -> Option<String> {
    match code {
        spl_token::INITIALIZE_MINT => Some("initialize_mint".to_string()),
        spl_token::INITIALIZE_ACCOUNT => Some("initialize_account".to_string()),
        spl_token::TRANSFER => Some("transfer".to_string()),
        spl_token::APPROVE => Some("approve".to_string()),
        spl_token::REVOKE => Some("revoke".to_string()),
        spl_token::MINT_TO => Some("mint_to".to_string()),
        spl_token::BURN => Some("burn".to_string()),
        spl_token::CLOSE_ACCOUNT => Some("close_account".to_string()),
        _ => None,
    }
}

/// Match System Program instruction codes
fn match_system_instruction(code: u8) -> Option<String> {
    match code {
        x if x == system_program::CREATE_ACCOUNT as u8 => Some("create_account".to_string()),
        x if x == system_program::ASSIGN as u8 => Some("assign".to_string()),
        x if x == system_program::TRANSFER as u8 => Some("transfer".to_string()),
        x if x == system_program::CREATE_ACCOUNT_WITH_SEED as u8 => Some("create_account_with_seed".to_string()),
        x if x == system_program::ADVANCE_NONCE_ACCOUNT as u8 => Some("advance_nonce_account".to_string()),
        x if x == system_program::WITHDRAW_NONCE_ACCOUNT as u8 => Some("withdraw_nonce_account".to_string()),
        x if x == system_program::INITIALIZE_NONCE_ACCOUNT as u8 => Some("initialize_nonce_account".to_string()),
        x if x == system_program::AUTHORIZE_NONCE_ACCOUNT as u8 => Some("authorize_nonce_account".to_string()),
        x if x == system_program::ALLOCATE as u8 => Some("allocate".to_string()),
        x if x == system_program::ALLOCATE_WITH_SEED as u8 => Some("allocate_with_seed".to_string()),
        x if x == system_program::ASSIGN_WITH_SEED as u8 => Some("assign_with_seed".to_string()),
        x if x == system_program::TRANSFER_WITH_SEED as u8 => Some("transfer_with_seed".to_string()),
        x if x == system_program::UPGRADE_NONCE_ACCOUNT as u8 => Some("upgrade_nonce_account".to_string()),
        _ => None,
    }
}

/// Extract discriminators from syscall patterns
fn extract_from_syscall_patterns(instructions: &[SbfInstruction], discriminators: &mut Vec<AnchorDiscriminator>) {
    // Look for syscall patterns that indicate instruction codes
    for window in instructions.windows(3) {
        // Pattern: syscall with immediate value
        if window[0].is_syscall() {
            let syscall_id = window[0].imm;
            
            // Check for known syscall patterns
            match syscall_id {
                // System Program
                x if x == system_program::CREATE_ACCOUNT as i64 => {
                    add_syscall_discriminator(discriminators, "create_account", 0);
                }
                x if x == system_program::TRANSFER as i64 => {
                    add_syscall_discriminator(discriminators, "transfer", 2);
                }
                // SPL Token Program
                x if x == spl_token::INITIALIZE_MINT as i64 => {
                    add_syscall_discriminator(discriminators, "initialize_mint", 0);
                }
                x if x == spl_token::TRANSFER as i64 => {
                    add_syscall_discriminator(discriminators, "transfer", 3);
                }
                _ => {}
            }
        }
    }
}

/// Add a syscall-based discriminator
fn add_syscall_discriminator(discriminators: &mut Vec<AnchorDiscriminator>, name: &str, code: u8) {
    let discriminator = generate_anchor_discriminator(name);
    discriminators.push(AnchorDiscriminator {
        bytes: discriminator,
        kind: DiscriminatorKind::Instruction,
        name: Some(name.to_string()),
        code: Some(code),
        discriminator_type: DiscriminatorType::Anchor(discriminator),
        program_id: None,
    });
}

/// Extract discriminators from instruction patterns with improved detection
fn extract_from_instruction_patterns(instructions: &[SbfInstruction], discriminators: &mut Vec<AnchorDiscriminator>) {
    // Look for discriminator loading and comparison patterns
    for window in instructions.windows(5) {
        // Pattern 1: Load 8-byte discriminator and compare (Anchor style)
        if is_anchor_discriminator_pattern(window) {
            extract_anchor_discriminator(window, discriminators);
        }
        
        // Pattern 2: Load 1-byte instruction code and compare (Native style)
        if is_native_discriminator_pattern(window) {
            extract_native_discriminator(window, discriminators);
        }
        
        // Pattern 3: Account discriminator check
        if is_account_discriminator_pattern(window) {
            extract_account_discriminator(window, discriminators);
        }
    }
}

/// Check if instruction window matches Anchor discriminator pattern
fn is_anchor_discriminator_pattern(window: &[SbfInstruction]) -> bool {
    window[0].is_load() && 
    window[0].size == 8 && 
    window[0].offset == 0 &&
    window[0].src_reg == 2 && // r2 often holds instruction data pointer
    (window[1].is_mov_imm() || window[2].is_mov_imm()) &&
    (window[3].is_cmp() || window[3].is_branch())
}

/// Check if instruction window matches native discriminator pattern
fn is_native_discriminator_pattern(window: &[SbfInstruction]) -> bool {
    window[0].is_load() && 
    window[0].size == 1 && 
    window[0].offset == 0 &&
    window[0].src_reg == 2 &&
    window[1].is_cmp_imm() &&
    window[2].is_branch()
}

/// Check if instruction window matches account discriminator pattern
fn is_account_discriminator_pattern(window: &[SbfInstruction]) -> bool {
    window[0].is_load() && 
    window[0].size == 8 && 
    window[0].offset == 0 &&
    window[1].is_mov_imm() && 
    window[2].is_branch()
}

/// Extract Anchor-style discriminator
fn extract_anchor_discriminator(window: &[SbfInstruction], discriminators: &mut Vec<AnchorDiscriminator>) {
    let mut discriminator = [0u8; 8];
    
    if window[1].is_mov_imm() && window[2].is_mov_imm() {
        // Two 32-bit parts of the discriminator
        let low_bytes = (window[1].imm as u32).to_le_bytes();
        let high_bytes = (window[2].imm as u32).to_le_bytes();
        
        discriminator[0..4].copy_from_slice(&low_bytes);
        discriminator[4..8].copy_from_slice(&high_bytes);
        
        discriminators.push(AnchorDiscriminator {
            bytes: discriminator,
            kind: DiscriminatorKind::Instruction,
            name: None,
            code: None,
            discriminator_type: DiscriminatorType::Anchor(discriminator),
            program_id: None,
        });
    }
}

/// Extract native-style discriminator
fn extract_native_discriminator(window: &[SbfInstruction], discriminators: &mut Vec<AnchorDiscriminator>) {
    let code = window[1].imm as u8;
    
    // Check against known instruction codes
    let name = match code {
        x if x == spl_token::INITIALIZE_MINT => Some("initialize_mint"),
        x if x == spl_token::TRANSFER => Some("transfer"),
        x if x == system_program::CREATE_ACCOUNT as u8 => Some("create_account"),
        _ => None,
    };
    
    if let Some(name) = name {
        let discriminator = generate_anchor_discriminator(name);
        discriminators.push(AnchorDiscriminator {
            bytes: discriminator,
            kind: DiscriminatorKind::Instruction,
            name: Some(name.to_string()),
            code: Some(code),
            discriminator_type: DiscriminatorType::Native(code),
            program_id: None,
        });
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
                    discriminator_type: DiscriminatorType::Custom(discriminator.to_vec()),
                    program_id: None,
                });
            }
        }
    }
}

/// Detect program ID from instruction patterns
fn detect_program_id(window: &[SbfInstruction]) -> Option<String> {
    // Check for program ID loading pattern
    if window.len() >= 3 && window[0].is_load() && window[1].is_cmp_imm() {
        // Common program IDs
        match window[1].imm {
            // Token program ID pattern
            0x06ddf6e1 => Some(program_ids::TOKEN_PROGRAM.to_string()),
            // System program ID pattern
            0x00000000 => Some(program_ids::SYSTEM_PROGRAM.to_string()),
            // Associated token program pattern
            0x8c97258f => Some(program_ids::ASSOCIATED_TOKEN_PROGRAM.to_string()),
            _ => None,
        }
    } else {
        None
    }
}

/// Extract account discriminator from instruction window
fn extract_account_discriminator(window: &[SbfInstruction], discriminators: &mut Vec<AnchorDiscriminator>) {
    // Check if we have enough instructions
    if window.len() < 2 {
        return;
    }
    
    // Extract discriminator from comparison instruction
    if window[1].is_branch() && (window[1].opcode == opcodes::JEQ_IMM || window[1].opcode == opcodes::JNE_IMM) {
        let imm_value = window[1].imm as u64;
        let bytes = imm_value.to_le_bytes();
        
        // Create discriminator from immediate value
        let mut discriminator = [0u8; 8];
        discriminator[0..std::cmp::min(8, bytes.len())].copy_from_slice(&bytes[0..std::cmp::min(8, bytes.len())]);
        
        // Only add if it looks like a valid discriminator
        if is_likely_anchor_discriminator(&discriminator) {
            discriminators.push(AnchorDiscriminator {
                bytes: discriminator,
                kind: DiscriminatorKind::Account,
                name: None,
                code: None,
                discriminator_type: DiscriminatorType::Anchor(discriminator),
                program_id: None,
            });
        }
    }
} 