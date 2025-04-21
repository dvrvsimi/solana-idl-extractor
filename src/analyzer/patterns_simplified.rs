//! Simplified pattern analysis for Solana programs

use anyhow::Result;
use log::{info, debug};
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::EncodedTransaction;
use crate::models::instruction::Instruction;
use std::collections::{HashMap, HashSet};

/// Pattern analysis results
#[derive(Debug)]
pub struct PatternAnalysis {
    /// Instruction patterns
    pub instruction_patterns: Vec<InstructionPattern>,
    /// Account patterns
    pub account_patterns: Vec<AccountPattern>,
    /// Error codes
    pub error_codes: HashMap<u32, String>,
}

/// Instruction pattern
#[derive(Debug)]
pub struct InstructionPattern {
    /// Instruction index
    pub index: u8,
    /// Instruction name
    pub name: String,
    /// Instruction discriminator (for Anchor programs)
    pub discriminator: Option<[u8; 8]>,
    /// Instruction frequency
    pub frequency: usize,
    /// Instruction arguments
    pub args: Vec<ArgPattern>,
    /// Instruction accounts
    pub accounts: Vec<AccountUsage>,
}

/// Argument pattern
#[derive(Debug)]
pub struct ArgPattern {
    /// Argument name
    pub name: String,
    /// Argument type
    pub ty: String,
    /// Argument size in bytes
    pub size: usize,
    /// Argument frequency
    pub frequency: usize,
}

/// Account usage pattern
#[derive(Debug)]
pub struct AccountUsage {
    /// Account name
    pub name: String,
    /// Whether the account is a signer
    pub is_signer: bool,
    /// Whether the account is writable
    pub is_writable: bool,
    /// Account frequency
    pub frequency: usize,
}

/// Account pattern
#[derive(Debug)]
pub struct AccountPattern {
    /// Instruction index
    pub instruction_index: u8,
    /// Account index
    pub account_index: usize,
    /// Account name
    pub name: String,
    /// Whether the account is a signer
    pub is_signer: bool,
    /// Whether the account is writable
    pub is_writable: bool,
    /// Account frequency
    pub frequency: usize,
    /// Account discriminator (for Anchor accounts)
    pub discriminator: Option<[u8; 8]>,
}

/// Analyze transaction patterns
pub fn analyze(program_id: &Pubkey, transactions: &[EncodedTransaction]) -> Result<PatternAnalysis> {
    info!("Analyzing transaction patterns for program: {}", program_id);
    
    // Create empty pattern analysis
    let mut analysis = PatternAnalysis {
        instruction_patterns: Vec::new(),
        account_patterns: Vec::new(),
        error_codes: HashMap::new(),
    };
    
    // Track instruction frequencies
    let mut instruction_frequencies: HashMap<u8, usize> = HashMap::new();
    let mut instruction_args: HashMap<u8, Vec<Vec<u8>>> = HashMap::new();
    let mut instruction_accounts: HashMap<u8, Vec<Vec<(String, bool, bool)>>> = HashMap::new();
    
    // Process transactions
    for transaction in transactions {
        if let Some(decoded) = transaction.decode() {
            for (i, instruction) in decoded.message.instructions().iter().enumerate() {
                if *instruction.program_id(decoded.message.static_account_keys()) == *program_id {
                    // Extract instruction index (first byte for Anchor programs)
                    if instruction.data.is_empty() {
                        continue;
                    }
                    
                    let ix_index = instruction.data[0];
                    *instruction_frequencies.entry(ix_index).or_insert(0) += 1;
                    
                    // Extract instruction arguments
                    if instruction.data.len() > 8 {
                        instruction_args
                            .entry(ix_index)
                            .or_default()
                            .push(instruction.data[8..].to_vec());
                    }
                    
                    // Extract account information
                    let mut accounts = Vec::new();
                    for (j, account_idx) in instruction.accounts.iter().enumerate() {
                        let account_idx = *account_idx as usize;
                        if account_idx < decoded.message.static_account_keys().len() {
                            let account_key = &decoded.message.static_account_keys()[account_idx];
                            let is_signer = decoded.message.is_signer(account_idx);
                            let is_writable = decoded.message.is_maybe_writable(account_idx);
                            
                            accounts.push((account_key.to_string(), is_signer, is_writable));
                            
                            // Add to account patterns
                            analysis.account_patterns.push(AccountPattern {
                                instruction_index: ix_index,
                                account_index: j,
                                name: format!("account_{}", j),
                                is_signer,
                                is_writable,
                                frequency: 1,
                                discriminator: None,
                            });
                        }
                    }
                    
                    instruction_accounts.entry(ix_index).or_default().push(accounts);
                }
            }
        }
    }
    
    // Analyze instruction arguments to determine types
    for (ix_index, args_list) in instruction_args {
        if args_list.is_empty() {
            continue;
        }
        
        // Find common argument sizes
        let mut arg_sizes = Vec::new();
        let first_args = &args_list[0];
        let mut offset = 0;
        
        // Simple heuristic: try to identify common Solana types by size
        while offset < first_args.len() {
            let remaining = first_args.len() - offset;
            
            let size = match remaining {
                s if s >= 32 => 32, // Pubkey
                s if s >= 16 => 16, // u128
                s if s >= 8 => 8,   // u64
                s if s >= 4 => 4,   // u32
                s if s >= 2 => 2,   // u16
                _ => 1,             // u8
            };
            
            arg_sizes.push(size);
            offset += size;
        }
        
        // Create instruction pattern
        let mut instruction_pattern = InstructionPattern {
            index: ix_index,
            name: format!("instruction_{}", ix_index),
            discriminator: if args_list[0].len() >= 8 {
                let mut disc = [0u8; 8];
                disc.copy_from_slice(&args_list[0][0..8]);
                Some(disc)
            } else {
                None
            },
            frequency: *instruction_frequencies.get(&ix_index).unwrap_or(&0),
            args: Vec::new(),
            accounts: Vec::new(),
        };
        
        // Add arguments
        let mut offset = 0;
        for (i, size) in arg_sizes.iter().enumerate() {
            let ty = match size {
                32 => "pubkey",
                16 => "u128",
                8 => "u64",
                4 => "u32",
                2 => "u16",
                _ => "u8",
            };
            
            instruction_pattern.args.push(ArgPattern {
                name: format!("arg_{}", i),
                ty: ty.to_string(),
                size: *size,
                frequency: args_list.len(),
            });
            
            offset += size;
        }
        
        // Add accounts
        if let Some(accounts_list) = instruction_accounts.get(&ix_index) {
            if !accounts_list.is_empty() {
                let accounts = &accounts_list[0];
                for (i, (_, is_signer, is_writable)) in accounts.iter().enumerate() {
                    instruction_pattern.accounts.push(AccountUsage {
                        name: format!("account_{}", i),
                        is_signer: *is_signer,
                        is_writable: *is_writable,
                        frequency: accounts_list.len(),
                    });
                }
            }
        }
        
        analysis.instruction_patterns.push(instruction_pattern);
    }
    
    // Consolidate account patterns
    let mut account_map: HashMap<(u8, usize), AccountPattern> = HashMap::new();
    for pattern in analysis.account_patterns.drain(..) {
        let key = (pattern.instruction_index, pattern.account_index);
        match account_map.get_mut(&key) {
            Some(existing) => {
                existing.frequency += pattern.frequency;
            }
            None => {
                account_map.insert(key, pattern);
            }
        }
    }
    analysis.account_patterns = account_map.into_values().collect();
    
    // Add common error codes for Anchor programs
    analysis.error_codes.insert(2000, "ConstraintMut".to_string());
    analysis.error_codes.insert(2002, "ConstraintSigner".to_string());
    analysis.error_codes.insert(2005, "ConstraintRentExempt".to_string());
    analysis.error_codes.insert(2006, "ConstraintSeeds".to_string());
    analysis.error_codes.insert(3001, "AccountDiscriminatorNotFound".to_string());
    analysis.error_codes.insert(3005, "AccountNotEnoughKeys".to_string());
    analysis.error_codes.insert(3010, "AccountNotSigner".to_string());
    
    debug!("Found {} instruction patterns", analysis.instruction_patterns.len());
    debug!("Found {} account patterns", analysis.account_patterns.len());
    
    Ok(analysis)
} 