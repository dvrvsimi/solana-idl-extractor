//! Account structure analysis from bytecode

use anyhow::{Result, anyhow, Context};
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet, BTreeMap};
use crate::models::account::Account;
use super::parser::{SbfInstruction, parse_instructions};
use super::elf::ElfAnalyzer;
use super::discriminator_detection::{AnchorDiscriminator, DiscriminatorKind};
use crate::utils::hash::generate_anchor_account_discriminator;
use crate::utils::account_analysis::{
    is_account_validation,
    is_account_ownership_check,
    is_account_data_access,
    get_account_size,
    is_account_constraint_check,
};
use solana_sbpf::{
    elf::Executable,
    program::{BuiltinProgram, FunctionRegistry, SBPFVersion},
    static_analysis::Analysis,
    test_utils::TestContextObject,
};
use std::sync::Arc;

/// Field access information
#[derive(Debug, Clone)]
struct FieldAccess {
    /// Offset from the start of the account
    offset: usize,
    /// Size of the access (1, 2, 4, or 8 bytes)
    size: usize,
    /// Is this a write access?
    is_write: bool,
    /// Frequency of access
    frequency: usize,
    /// Instruction context where this access occurs
    context: Option<String>,
}

/// Memory access pattern
#[derive(Debug, Clone)]
struct MemoryAccessPattern {
    /// Base register
    base_reg: u8,
    /// Accesses using this base register
    accesses: Vec<FieldAccess>,
    /// Is this likely an account?
    is_account: bool,
}

/// Enhanced account structure extraction using SBPF analysis
pub fn extract_account_structures(
    program_data: &[u8],
    instructions: &[SbfInstruction],
    discriminators: &[AnchorDiscriminator]
) -> Result<Vec<Account>> {
    info!("Performing enhanced account structure extraction with SBPF analysis");
    
    // Create SBPF executable for better analysis
    let executable = Executable::<TestContextObject>::from_text_bytes(
        program_data,
        Arc::new(BuiltinProgram::new_mock()),
        SBPFVersion::V3,
        FunctionRegistry::default(),
    ).map_err(|e| anyhow!("Failed to create executable: {}", e))?;

    let analysis = Analysis::from_executable(&executable)
        .map_err(|e| anyhow!("Failed to analyze executable: {}", e))?;
    
    // First try to extract from discriminators (for Anchor programs)
    let mut accounts = extract_accounts_from_discriminators(discriminators);
    
    // If we found accounts from discriminators, enhance them with SBPF analysis
    if !accounts.is_empty() {
        enhance_accounts_with_sbpf_analysis(&mut accounts, &analysis, instructions);
    } else {
        // If no accounts from discriminators, try SBPF memory analysis
        accounts = extract_accounts_from_sbpf_analysis(&analysis, instructions)?;
    }
    
    // Analyze account relationships using SBPF analysis
    analyze_account_relationships(&mut accounts, &analysis, instructions);
    
    // If we still don't have accounts, add a generic one
    if accounts.is_empty() {
        let mut account = Account::new("State".to_string(), "state".to_string());
        account.add_field("data".to_string(), "bytes".to_string(), 0);
        accounts.push(account);
    }
    
    Ok(accounts)
}

/// Extract accounts from SBPF analysis
fn extract_accounts_from_sbpf_analysis(
    analysis: &Analysis,
    instructions: &[SbfInstruction]
) -> Result<Vec<Account>> {
    let mut accounts = Vec::new();
    let mut memory_patterns = HashMap::new();
    
    // Track memory access patterns using SBPF analysis
    for (pc, insn) in analysis.instructions.iter().enumerate() {
        let instruction = &instructions[pc];
        
        // Use our utility functions for better account detection
        if is_account_data_access(instruction) {
            let base_reg = instruction.src_reg;
            let offset = instruction.offset as usize;
            let size = get_account_size(instruction).unwrap_or(0);
            
            // Skip small offsets which are likely instruction data
            if offset < 8 && base_reg == 2 {
                continue;
            }
            
            // Record this memory access
            let pattern = memory_patterns.entry(base_reg).or_insert_with(Vec::new);
            pattern.push((offset, size, instruction.is_store(), pc));
        }
    }
    
    // Analyze patterns to identify accounts
    for (reg, accesses) in memory_patterns {
        // Sort by offset
        let mut sorted_accesses = accesses.clone();
        sorted_accesses.sort_by_key(|a| a.0);
        
        // Check if this looks like an account using SBPF analysis
        if is_likely_account_pattern(&sorted_accesses, analysis) {
            let account_name = determine_account_name(reg, &sorted_accesses, instructions, analysis);
            let mut account = Account::new(account_name, "account".to_string());
            
            // Add fields based on access patterns
            let fields = extract_fields_from_accesses(&sorted_accesses, analysis);
            for (name, ty, offset) in fields {
                account.add_field(name, ty, offset);
            }
            
            accounts.push(account);
        }
    }
    
    Ok(accounts)
}

/// Check if a memory access pattern is likely an account using SBPF analysis
fn is_likely_account_pattern(
    accesses: &[(usize, usize, bool, usize)],
    analysis: &Analysis
) -> bool {
    // Use SBPF analysis to improve account detection
    
    // 1. Check for syscall-based account operations
    let has_syscalls = accesses.iter().any(|(_, _, _, pc)| {
        let insn = &analysis.instructions[*pc];
        insn.opc == 0x85 && insn.imm >= 0x100000
    });
    
    // 2. Check for account validation patterns
    let has_validation = accesses.iter().any(|(_, _, _, pc)| {
        let insn = &analysis.instructions[*pc];
        is_account_validation(&SbfInstruction::from_sbpf(insn))
    });
    
    // 3. Check for ownership checks
    let has_ownership = accesses.iter().any(|(_, _, _, pc)| {
        let insn = &analysis.instructions[*pc];
        is_account_ownership_check(&SbfInstruction::from_sbpf(insn))
    });
    
    // 4. Check for constraint validation
    let has_constraints = accesses.iter().any(|(_, _, _, pc)| {
        let insn = &analysis.instructions[*pc];
        is_account_constraint_check(&SbfInstruction::from_sbpf(insn))
    });
    
    // Return true if it matches enough SBPF-based heuristics
    has_syscalls || has_validation || (has_ownership && has_constraints) || accesses.len() >= 5
}

/// Extract accounts from Anchor discriminators
fn extract_accounts_from_discriminators(discriminators: &[AnchorDiscriminator]) -> Vec<Account> {
    let mut accounts = Vec::new();
    
    for discriminator in discriminators {
        if discriminator.kind == DiscriminatorKind::Account {
            if let Some(name) = &discriminator.name {
                let mut account = Account::new(name.clone(), "account".to_string());
                
                // Convert discriminator to Vec<u8>
                let disc_vec = discriminator.bytes.to_vec();
                account.set_discriminator(disc_vec);
                
                // Add basic fields that most Anchor accounts have
                account.add_field("authority".to_string(), "pubkey".to_string(), 8);
                
                accounts.push(account);
            }
        }
    }
    
    accounts
}

/// Determine account name from access pattern
fn determine_account_name(
    reg: u8,
    accesses: &[(usize, usize, bool, usize)],
    instructions: &[SbfInstruction],
    analysis: &Analysis
) -> String {
    // Try to find nearby string references that might indicate the account name
    for &(_, _, _, insn_idx) in accesses {
        // Look at nearby instructions for string loading
        let start = insn_idx.saturating_sub(10);
        let end = (insn_idx + 10).min(instructions.len());
        
        for i in start..end {
            let insn = &instructions[i];
            if insn.is_load() && insn.is_mov_imm() && insn.imm > 1000 {
                // This might be loading a string pointer
                // In a real implementation, we'd try to resolve this to a string
                return format!("Account_{}", reg);
            }
        }
    }
    
    // Default name based on register
    format!("Account_{}", reg)
}

/// Extract fields from memory accesses
fn extract_fields_from_accesses(accesses: &[(usize, usize, bool, usize)], analysis: &Analysis) -> Vec<(String, String, usize)> {
    let mut fields = Vec::new();
    let mut current_offset = 0;
    
    // Skip discriminator (first 8 bytes) for Anchor accounts
    let start_idx = if accesses[0].0 == 0 && accesses[0].1 == 8 { 1 } else { 0 };
    
    for (i, &(offset, size, _, _)) in accesses[start_idx..].iter().enumerate() {
        // Skip if this is part of a previous field
        if i > 0 && offset < current_offset {
            continue;
        }
        
        // Determine field type based on size
        let field_type = match size {
            1 => "u8".to_string(),
            2 => "u16".to_string(),
            4 => "u32".to_string(),
            8 => "u64".to_string(),
            32 => "pubkey".to_string(),
            _ => format!("[u8; {}]", size),
        };
        
        // Generate field name
        let field_name = if field_type == "pubkey" {
            if offset == 8 {
                "authority".to_string()
            } else {
                format!("pubkey_at_{}", offset)
            }
        } else {
            format!("field_at_{}", offset)
        };
        
        fields.push((field_name, field_type, offset));
        current_offset = offset + size;
    }
    
    fields
}

/// Enhance accounts with SBPF analysis
fn enhance_accounts_with_sbpf_analysis(accounts: &mut Vec<Account>, analysis: &Analysis, instructions: &[SbfInstruction]) {
    for account in accounts.iter_mut() {
        // Skip if account already has fields
        if !account.fields.is_empty() {
            continue;
        }
        
        // Add standard fields based on account name
        if account.name.to_lowercase().contains("mint") {
            account.add_field("mint_authority".to_string(), "pubkey".to_string(), 8);
            account.add_field("supply".to_string(), "u64".to_string(), 40);
            account.add_field("decimals".to_string(), "u8".to_string(), 48);
            account.add_field("is_initialized".to_string(), "bool".to_string(), 49);
            account.add_field("freeze_authority".to_string(), "pubkey".to_string(), 50);
        } else if account.name.to_lowercase().contains("token") {
            account.add_field("mint".to_string(), "pubkey".to_string(), 8);
            account.add_field("owner".to_string(), "pubkey".to_string(), 40);
            account.add_field("amount".to_string(), "u64".to_string(), 72);
            account.add_field("delegate".to_string(), "pubkey".to_string(), 80);
            account.add_field("state".to_string(), "u8".to_string(), 112);
            account.add_field("is_native".to_string(), "u64".to_string(), 113);
            account.add_field("delegated_amount".to_string(), "u64".to_string(), 121);
            account.add_field("close_authority".to_string(), "pubkey".to_string(), 129);
        } else {
            // Generic account structure
            account.add_field("authority".to_string(), "pubkey".to_string(), 8);
            account.add_field("data".to_string(), "bytes".to_string(), 40);
        }
    }
}

/// Analyze relationships between accounts using SBPF analysis
fn analyze_account_relationships(accounts: &mut Vec<Account>, analysis: &Analysis, instructions: &[SbfInstruction]) {
    // Create a list of mint accounts first
    let mint_accounts: Vec<String> = accounts.iter()
        .filter(|a| a.name.to_lowercase().contains("mint"))
        .map(|a| a.name.clone())
        .collect();
    
    // Then update token accounts
    for account in accounts.iter_mut() {
        if account.name.to_lowercase().contains("token") {
            // Token accounts are related to mints
            if !mint_accounts.is_empty() {
                account.add_field("related_mint".to_string(), "pubkey".to_string(), 8);
            }
        }
    }
}

/// Infer account relationships from instructions and transactions
pub fn infer_account_relationships(
    accounts: &[Account],
    instructions: &[crate::models::instruction::Instruction]
) -> HashMap<String, Vec<String>> {
    let mut relationships = HashMap::new();
    
    // Analyze instruction account usage patterns
    for instruction in instructions {
        let mut related_accounts = Vec::new();
        
        for account in &instruction.accounts {
            related_accounts.push(account.name.clone());
        }
        
        // Record relationships for each account in this instruction
        for account in &related_accounts {
            let entry = relationships.entry(account.clone()).or_insert_with(Vec::new);
            
            for related in &related_accounts {
                if related != account && !entry.contains(related) {
                    entry.push(related.clone());
                }
            }
        }
    }
    
    relationships
}

/// Detect account hierarchies
pub fn detect_account_hierarchies(
    accounts: &[Account],
    relationships: &HashMap<String, Vec<String>>
) -> HashMap<String, Vec<String>> {
    let mut hierarchies = HashMap::new();
    
    // Identify potential parent accounts
    for account in accounts {
        // Accounts with many relationships are likely parent accounts
        if let Some(related) = relationships.get(&account.name) {
            if related.len() >= 2 {
                hierarchies.insert(account.name.clone(), related.clone());
            }
        }
    }
    
    hierarchies
} 