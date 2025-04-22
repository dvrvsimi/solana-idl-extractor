//! Transaction parsing for Solana programs

use anyhow::Result;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::EncodedTransaction;
use crate::models::instruction::Instruction;
use std::collections::HashMap;

/// Results of transaction analysis
pub struct TransactionAnalysis {
    /// Detected instructions
    pub instructions: Vec<Instruction>,
    /// Instruction frequencies
    pub frequencies: Vec<(u8, usize)>,
}

/// Analyze transactions to extract instruction and account information
pub fn analyze(
    program_id: &Pubkey,
    transactions: &[EncodedTransaction],
) -> Result<TransactionAnalysis> {
    let mut instructions = Vec::new();
    let mut frequency_map: HashMap<u8, usize> = HashMap::new();
    
    // Extract instruction data from transactions
    let instruction_data = extract_instruction_data(program_id, transactions);
    
    // Group instruction data by discriminator (first byte)
    let mut grouped_data: HashMap<u8, Vec<Vec<u8>>> = HashMap::new();
    for data in &instruction_data {
        if !data.is_empty() {
            let discriminator = data[0];
            grouped_data.entry(discriminator)
                .or_insert_with(Vec::new)
                .push(data.clone());
            
            // Count frequency
            *frequency_map.entry(discriminator).or_insert(0) += 1;
        }
    }
    
    // Analyze each instruction type
    for (discriminator, data_group) in grouped_data {
        // Skip if we don't have enough samples
        if data_group.len() < 2 {
            continue;
        }
        
        // Create a new instruction
        let mut instruction = Instruction::new(
            format!("instruction_{}", discriminator),
            discriminator
        );
        
        // Infer parameter types
        if data_group[0].len() > 1 {
            let param_data: Vec<_> = data_group.iter()
                .map(|data| &data[1..])
                .collect();
            
            let param_types = infer_parameter_types(&param_data);
            for (i, param_type) in param_types.iter().enumerate() {
                instruction.add_arg(format!("arg_{}", i), param_type.clone());
            }
        }
        
        // Add accounts based on transaction analysis
        let accounts = analyze_account_usage(program_id, transactions, discriminator);
        for (i, (is_signer, is_writable, frequency)) in accounts.iter().enumerate() {
            instruction.add_account(
                format!("account_{}", i),
                *is_signer,
                *is_writable,
                false
            );
        }
        
        instructions.push(instruction);
    }
    
    // Convert frequency map to vector
    let frequencies: Vec<(u8, usize)> = frequency_map.into_iter().collect();
    
    Ok(TransactionAnalysis {
        instructions,
        frequencies,
    })
}

/// Extract instruction data from transactions
pub fn extract_instruction_data(
    program_id: &Pubkey,
    transactions: &[EncodedTransaction],
) -> Vec<Vec<u8>> {
    let mut instruction_data = Vec::new();
    
    for transaction in transactions {
        if let Some(decoded) = transaction.decode() {
            for instruction in decoded.message.instructions() {
                if *instruction.program_id(decoded.message.static_account_keys()) == *program_id {
                    instruction_data.push(instruction.data.clone());
                }
            }
        }
    }
    
    instruction_data
}

/// Infer parameter types from instruction data
fn infer_parameter_types(param_data: &[&[u8]]) -> Vec<String> {
    if param_data.is_empty() || param_data[0].is_empty() {
        return Vec::new();
    }
    
    let first_sample = param_data[0];
    let mut types = Vec::new();
    let mut offset = 0;
    
    // Process the data in chunks
    while offset < first_sample.len() {
        // Check for consistent patterns across all samples
        
        // Check for Pubkey (32 bytes)
        if offset + 32 <= first_sample.len() {
            let is_pubkey = param_data.iter().all(|sample| {
                if sample.len() < offset + 32 {
                    return false;
                }
                let slice = &sample[offset..offset + 32];
                // Pubkeys are unlikely to be all zeros or all ones
                let zeros = slice.iter().filter(|&&b| b == 0).count();
                let ones = slice.iter().filter(|&&b| b == 1).count();
                zeros < 30 && ones < 30
            });
            
            if is_pubkey {
                types.push("pubkey".to_string());
                offset += 32;
                continue;
            }
        }
        
        // Check for u64 (8 bytes)
        if offset + 8 <= first_sample.len() {
            let is_u64 = param_data.iter().all(|sample| {
                if sample.len() < offset + 8 {
                    return false;
                }
                let slice = &sample[offset..offset + 8];
                // Most u64 values have zeros in the high bytes
                slice[4..].iter().any(|&b| b == 0)
            });
            
            if is_u64 {
                types.push("u64".to_string());
                offset += 8;
                continue;
            }
        }
        
        // Check for u32 (4 bytes)
        if offset + 4 <= first_sample.len() {
            types.push("u32".to_string());
            offset += 4;
            continue;
        }
        
        // Check for u16 (2 bytes)
        if offset + 2 <= first_sample.len() {
            types.push("u16".to_string());
            offset += 2;
            continue;
        }
        
        // Check for u8 (1 byte)
        if offset + 1 <= first_sample.len() {
            types.push("u8".to_string());
            offset += 1;
            continue;
        }
        
        // If we get here, we couldn't determine the type
        break;
    }
    
    // If we have remaining data, add it as a bytes type
    if offset < first_sample.len() {
        types.push(format!("bytes[{}]", first_sample.len() - offset));
    }
    
    types
}

/// Analyze account usage patterns
fn analyze_account_usage(
    program_id: &Pubkey,
    transactions: &[EncodedTransaction],
    discriminator: u8,
) -> Vec<(bool, bool, usize)> {
    let mut account_usage = Vec::new();
    
    for transaction in transactions {
        if let Some(decoded) = transaction.decode() {
            for instruction in decoded.message.instructions() {
                if *instruction.program_id(decoded.message.static_account_keys()) == *program_id {
                    // Check if this is the instruction we're looking for
                    if !instruction.data.is_empty() && instruction.data[0] == discriminator {
                        // Analyze account usage
                        for account_idx in &instruction.accounts {
                            let account_idx = *account_idx as usize;
                            if account_idx < decoded.message.static_account_keys().len() {
                                let is_signer = decoded.message.is_signer(account_idx);
                                let is_writable = decoded.message.is_maybe_writable(account_idx);
                                
                                // Ensure we have enough entries in our vector
                                while account_usage.len() <= account_idx {
                                    account_usage.push((false, false, 0));
                                }
                                
                                // Update account usage
                                let (signer, writable, count) = &mut account_usage[account_idx];
                                *signer |= is_signer;
                                *writable |= is_writable;
                                *count += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    
    account_usage
} 