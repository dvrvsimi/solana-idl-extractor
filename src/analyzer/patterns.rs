//! Common instruction patterns for Solana programs

use anyhow::Result;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::{UiTransactionEncoding, TransactionBinaryEncoding, UiMessage, UiInstruction};
use crate::models::instruction::Instruction;
use log;
use std::str::FromStr;

/// Results of pattern analysis
pub struct PatternAnalysis {
    /// Detected instruction patterns
    pub instruction_patterns: Vec<InstructionPattern>,
    /// Detected account usage patterns
    pub account_patterns: Vec<AccountPattern>,
}

/// A detected instruction pattern
pub struct InstructionPattern {
    /// Instruction index
    pub index: u8,
    /// Detected parameter types
    pub parameter_types: Vec<String>,
    /// Frequency of occurrence
    pub frequency: usize,
}

/// A detected account usage pattern
pub struct AccountPattern {
    /// Instruction index
    pub instruction_index: u8,
    /// Account index
    pub account_index: usize,
    /// Is signer
    pub is_signer: bool,
    /// Is writable
    pub is_writable: bool,
    /// Frequency of occurrence
    pub frequency: usize,
}

/// Analyze transaction patterns to extract additional information
pub fn analyze(
    program_id: &Pubkey,
    transactions: &[solana_transaction_status::EncodedTransaction],
) -> Result<PatternAnalysis> {
    let instruction_data = extract_instruction_data(program_id, transactions);
    let instruction_patterns = analyze_instruction_patterns(&instruction_data);
    
    let account_patterns = analyze_account_patterns(program_id, transactions);
    
    Ok(PatternAnalysis {
        instruction_patterns,
        account_patterns,
    })
}

/// Extract instruction data from transactions
pub fn extract_instruction_data(
    program_id: &Pubkey,
    transactions: &[solana_transaction_status::EncodedTransaction],
) -> Vec<Vec<u8>> {
    let mut instruction_data = Vec::new();
    
    for transaction in transactions {
        match transaction {
            solana_transaction_status::EncodedTransaction::Json(ui_transaction) => {
                // Process JSON-encoded transaction
                if let Some(ui_message) = &ui_transaction.message {
                    // Extract instructions
                    if let Some(instructions) = &ui_message.instructions {
                        for instruction in instructions {
                            // Check if this instruction is for our program
                            if let Some(program_id_str) = &instruction.program_id {
                                if program_id_str == &program_id.to_string() {
                                    // Extract instruction data
                                    if let Some(data_str) = &instruction.data {
                                        // Try base58 decoding first
                                        match bs58::decode(data_str).into_vec() {
                                            Ok(data) => {
                                                instruction_data.push(data);
                                            },
                                            Err(err) => {
                                                // Log the error but continue processing
                                                log::debug!("Failed to decode base58 data: {}", err);
                                                
                                                // Try base64 decoding as fallback
                                                match base64::decode(data_str) {
                                                    Ok(data) => {
                                                        instruction_data.push(data);
                                                    },
                                                    Err(err) => {
                                                        log::debug!("Failed to decode base64 data: {}", err);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            solana_transaction_status::EncodedTransaction::Binary(data, encoding) => {
                // Process binary-encoded transaction
                log::debug!("Processing binary transaction with encoding: {:?}", encoding);
                
                match encoding {
                    TransactionBinaryEncoding::Base58 => {
                        if let Ok(tx_data) = bs58::decode(data).into_vec() {
                            extract_from_binary(&tx_data, program_id, &mut instruction_data);
                        }
                    },
                    TransactionBinaryEncoding::Base64 => {
                        if let Ok(tx_data) = base64::decode(data) {
                            extract_from_binary(&tx_data, program_id, &mut instruction_data);
                        }
                    },
                    _ => {
                        log::debug!("Unsupported binary encoding");
                    }
                }
            },
            _ => {
                // Handle other encoding formats
                log::debug!("Unsupported transaction encoding format");
            }
        }
    }
    
    instruction_data
}

/// Extract instruction data from binary transaction data
fn extract_from_binary(tx_data: &[u8], program_id: &Pubkey, instruction_data: &mut Vec<Vec<u8>>) {
    // This is a simplified implementation
    // In a real implementation, we would parse the transaction format
    // and extract instructions for our program
    
    // Look for program ID in the transaction data
    let program_id_bytes = program_id.to_bytes();
    
    // Scan for program ID followed by instruction data
    // This is a heuristic approach and may not work for all transactions
    for window in tx_data.windows(program_id_bytes.len()) {
        if window == program_id_bytes.as_ref() {
            // Found program ID, try to extract instruction data
            // Typically, instruction data follows the program ID and account indices
            // This is a simplified approach
            let pos = window.as_ptr() as usize - tx_data.as_ptr() as usize;
            if pos + program_id_bytes.len() + 1 < tx_data.len() {
                // Extract a chunk of data after the program ID
                // In a real implementation, we would parse the exact instruction data
                let data_start = pos + program_id_bytes.len() + 1;
                let data_end = std::cmp::min(data_start + 32, tx_data.len());
                let data = tx_data[data_start..data_end].to_vec();
                if !data.is_empty() {
                    instruction_data.push(data);
                }
            }
        }
    }
}

/// Analyze instruction patterns
fn analyze_instruction_patterns(instruction_data: &[Vec<u8>]) -> Vec<InstructionPattern> {
    let mut patterns = Vec::new();
    
    // Count instruction frequencies by discriminator
    let mut frequencies = std::collections::HashMap::new();
    let mut param_types = std::collections::HashMap::new();
    
    for data in instruction_data {
        if !data.is_empty() {
            let discriminator = data[0];
            
            // Count frequency
            *frequencies.entry(discriminator).or_insert(0) += 1;
            
            // Try to infer parameter types
            if data.len() > 1 {
                let types = infer_parameter_types(&data[1..]);
                param_types.entry(discriminator)
                    .or_insert_with(Vec::new)
                    .extend(types);
            }
        }
    }
    
    // Convert to patterns
    for (discriminator, frequency) in frequencies {
        // Get the most common parameter types for this discriminator
        let parameter_types = param_types.get(&discriminator)
            .cloned()
            .unwrap_or_else(Vec::new);
        
        patterns.push(InstructionPattern {
            index: discriminator,
            parameter_types,
            frequency,
        });
    }
    
    patterns
}

/// Try to infer parameter types from instruction data
fn infer_parameter_types(data: &[u8]) -> Vec<String> {
    let mut types = Vec::new();
    
    // Skip the first byte (discriminator)
    let mut offset = 0;
    
    // Process the data in chunks based on common Solana data types
    while offset < data.len() {
        // Check for Pubkey (32 bytes)
        if offset + 32 <= data.len() {
            // Check if this looks like a Pubkey
            // Pubkeys often have a specific pattern or distribution of bytes
            let potential_pubkey = &data[offset..offset + 32];
            
            // Simple heuristic: if it's not all zeros and has some distribution of values
            let zero_count = potential_pubkey.iter().filter(|&&b| b == 0).count();
            if zero_count < 30 && zero_count > 0 {
                types.push("pubkey".to_string());
                offset += 32;
                continue;
            }
        }
        
        // Check for u64 (8 bytes)
        if offset + 8 <= data.len() {
            // For u64, we don't have a great heuristic, but we can check
            // if the high bytes are mostly zeros (common for small numbers)
            let potential_u64 = &data[offset..offset + 8];
            let high_bytes_zero = potential_u64[4..].iter().all(|&b| b == 0);
            
            if high_bytes_zero {
                types.push("u64".to_string());
                offset += 8;
                continue;
            }
        }
        
        // Check for u32 (4 bytes)
        if offset + 4 <= data.len() {
            types.push("u32".to_string());
            offset += 4;
            continue;
        }
        
        // Check for u16 (2 bytes)
        if offset + 2 <= data.len() {
            types.push("u16".to_string());
            offset += 2;
            continue;
        }
        
        // Check for u8 (1 byte)
        if offset + 1 <= data.len() {
            types.push("u8".to_string());
            offset += 1;
            continue;
        }
        
        // If we get here, we couldn't determine the type
        break;
    }
    
    // If we have remaining data, add it as a bytes type
    if offset < data.len() {
        types.push(format!("bytes[{}]", data.len() - offset));
    }
    
    types
}

/// Analyze account patterns
fn analyze_account_patterns(
    program_id: &Pubkey,
    transactions: &[solana_transaction_status::EncodedTransaction],
) -> Vec<AccountPattern> {
    let mut patterns = Vec::new();
    let mut frequency_map = std::collections::HashMap::new();
    
    for transaction in transactions {
        match transaction {
            solana_transaction_status::EncodedTransaction::Json(ui_transaction) => {
                // Process JSON-encoded transaction
                if let Some(ui_message) = &ui_transaction.message {
                    // Extract instructions
                    if let Some(instructions) = &ui_message.instructions {
                        for instruction in instructions {
                            // Check if this instruction is for our program
                            if let Some(program_id_str) = &instruction.program_id {
                                if program_id_str == &program_id.to_string() {
                                    // Extract instruction discriminator
                                    let discriminator = extract_discriminator(instruction);
                                    
                                    // Extract account usage
                                    if let Some(accounts) = &instruction.accounts {
                                        for (i, account_idx_str) in accounts.iter().enumerate() {
                                            if let Ok(idx) = account_idx_str.parse::<usize>() {
                                                // Check if the account is a signer or writable
                                                let is_signer = is_account_signer(ui_message, idx);
                                                let is_writable = is_account_writable(ui_message, idx);
                                                
                                                // Create a key for this pattern
                                                let key = (discriminator, i, is_signer, is_writable);
                                                
                                                // Count frequency
                                                *frequency_map.entry(key).or_insert(0) += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            _ => {
                // Binary transactions are handled in extract_instruction_data
                // We focus on JSON transactions for account patterns
            }
        }
    }
    
    // Convert frequency map to patterns
    for ((discriminator, account_index, is_signer, is_writable), frequency) in frequency_map {
        patterns.push(AccountPattern {
            instruction_index: discriminator,
            account_index,
            is_signer,
            is_writable,
            frequency,
        });
    }
    
    // Sort by frequency (most common first)
    patterns.sort_by(|a, b| b.frequency.cmp(&a.frequency));
    
    patterns
}

/// Extract the instruction discriminator
pub fn extract_discriminator(instruction: &UiInstruction) -> u8 {
    // The UiInstruction doesn't have a direct data field, it has a data Option<String>
    if let Some(data_str) = &instruction.data {
        // Try to decode the data
        if let Ok(data) = bs58::decode(data_str).into_vec() {
            if !data.is_empty() {
                return data[0];
            }
        }
    }
    0
}

/// Check if an account is a signer
pub fn is_account_signer(message: &UiMessage, account_idx: usize) -> bool {
    // The UiMessage structure is different than expected
    // Let's use a simpler approach based on the account_keys
    if let Some(account_keys) = &message.account_keys {
        if account_idx < account_keys.len() {
            return account_keys[account_idx].signer;
        }
    }
    false
}

/// Check if an account is writable
pub fn is_account_writable(message: &UiMessage, account_idx: usize) -> bool {
    // The UiMessage structure is different than expected
    // Let's use a simpler approach based on the account_keys
    if let Some(account_keys) = &message.account_keys {
        if account_idx < account_keys.len() {
            return account_keys[account_idx].writable;
        }
    }
    false
}

/// Detect common parameter patterns in instruction data
pub fn detect_parameter_patterns(instruction_data: &[Vec<u8>]) -> Vec<String> {
    let mut parameter_types = Vec::new();
    
    // Group instruction data by first byte (discriminator)
    let mut grouped_data = std::collections::HashMap::new();
    
    for data in instruction_data {
        if !data.is_empty() {
            let discriminator = data[0];
            grouped_data.entry(discriminator)
                .or_insert_with(Vec::new)
                .push(data.clone());
        }
    }
    
    // Analyze each group to detect parameter patterns
    for (discriminator, data_group) in grouped_data {
        // Skip if we don't have enough samples
        if data_group.len() < 2 {
            continue;
        }
        
        // Find the most common data length for this discriminator
        let mut length_counts = std::collections::HashMap::new();
        for data in &data_group {
            *length_counts.entry(data.len()).or_insert(0) += 1;
        }
        
        let most_common_length = length_counts.iter()
            .max_by_key(|&(_, count)| *count)
            .map(|(&length, _)| length)
            .unwrap_or(0);
        
        // Filter data to only include the most common length
        let filtered_data: Vec<_> = data_group.iter()
            .filter(|data| data.len() == most_common_length)
            .collect();
        
        if filtered_data.is_empty() {
            continue;
        }
        
        // Analyze parameter types based on the filtered data
        // Skip the first byte (discriminator)
        if most_common_length > 1 {
            let param_data: Vec<_> = filtered_data.iter()
                .map(|data| &data[1..])
                .collect();
            
            // Infer parameter types
            let types = infer_parameter_types_from_samples(&param_data);
            parameter_types.extend(types);
        }
    }
    
    parameter_types
}

/// Infer parameter types from multiple samples
pub fn infer_parameter_types_from_samples(samples: &[&[u8]]) -> Vec<String> {
    if samples.is_empty() {
        return Vec::new();
    }
    
    let first_sample = samples[0];
    let mut types = Vec::new();
    let mut offset = 0;
    
    // Process the data in chunks
    while offset < first_sample.len() {
        // Check for consistent patterns across all samples
        
        // Check for Pubkey (32 bytes)
        if offset + 32 <= first_sample.len() {
            let is_pubkey = samples.iter().all(|sample| {
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
            let is_u64 = samples.iter().all(|sample| {
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

/// Detect common account usage patterns
pub fn detect_account_patterns(
    program_id: &Pubkey,
    transactions: &[solana_transaction_status::EncodedTransaction],
) -> Vec<AccountPattern> {
    let mut patterns = Vec::new();
    let mut frequency_map = std::collections::HashMap::new();
    
    for transaction in transactions {
        match transaction {
            solana_transaction_status::EncodedTransaction::Json(ui_transaction) => {
                // Process JSON-encoded transaction
                if let Some(ui_message) = &ui_transaction.message {
                    // Extract instructions
                    if let Some(instructions) = &ui_message.instructions {
                        for instruction in instructions {
                            // Check if this instruction is for our program
                            if let Some(program_id_str) = &instruction.program_id {
                                if program_id_str == &program_id.to_string() {
                                    // Extract instruction discriminator
                                    let discriminator = extract_discriminator(instruction);
                                    
                                    // Extract account usage
                                    if let Some(accounts) = &instruction.accounts {
                                        for (i, account_idx_str) in accounts.iter().enumerate() {
                                            if let Ok(idx) = account_idx_str.parse::<usize>() {
                                                // Check if the account is a signer or writable
                                                let is_signer = is_account_signer(ui_message, idx);
                                                let is_writable = is_account_writable(ui_message, idx);
                                                
                                                // Create a key for this pattern
                                                let key = (discriminator, i, is_signer, is_writable);
                                                
                                                // Count frequency
                                                *frequency_map.entry(key).or_insert(0) += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            _ => {
                // Binary transactions are handled in extract_instruction_data
                // We focus on JSON transactions for account patterns
            }
        }
    }
    
    // Convert frequency map to patterns
    for ((discriminator, account_index, is_signer, is_writable), frequency) in frequency_map {
        patterns.push(AccountPattern {
            instruction_index: discriminator,
            account_index,
            is_signer,
            is_writable,
            frequency,
        });
    }
    
    // Sort by frequency (most common first)
    patterns.sort_by(|a, b| b.frequency.cmp(&a.frequency));
    
    patterns
}

/// Try to identify the account type based on its usage pattern
pub fn identify_account_type(
    program_id: &Pubkey,
    account_pubkey: &Pubkey,
    is_signer: bool,
    is_writable: bool,
    transactions: &[solana_transaction_status::EncodedTransaction],
) -> String {
    // Common account types
    if account_pubkey == program_id {
        return "program".to_string();
    }
    
    if account_pubkey == &solana_sdk::system_program::id() {
        return "system_program".to_string();
    }
    
    if account_pubkey == &solana_sdk::sysvar::rent::id() {
        return "rent".to_string();
    }
    
    if account_pubkey == &solana_sdk::sysvar::clock::id() {
        return "clock".to_string();
    }
    
    // Heuristics for other account types
    if is_signer && is_writable {
        return "authority".to_string();
    }
    
    if is_signer && !is_writable {
        return "signer".to_string();
    }
    
    if !is_signer && is_writable {
        return "data".to_string();
    }
    
    "account".to_string()
}

/// Try to identify the instruction type based on its discriminator and parameters
pub fn identify_instruction_type(
    discriminator: u8,
    param_types: &[String],
    account_types: &[String],
) -> String {
    // Common instruction types based on discriminator
    match discriminator {
        0 => {
            if account_types.contains(&"authority".to_string()) {
                return "initialize".to_string();
            }
            return "create".to_string();
        },
        1 => return "transfer".to_string(),
        2 => return "update".to_string(),
        3 => return "close".to_string(),
        _ => {}
    }
    
    // Heuristics based on parameters and accounts
    if param_types.contains(&"pubkey".to_string()) && param_types.contains(&"u64".to_string()) {
        return "transfer".to_string();
    }
    
    if account_types.contains(&"authority".to_string()) && account_types.contains(&"data".to_string()) {
        return "update".to_string();
    }
    
    format!("instruction_{}", discriminator)
} 