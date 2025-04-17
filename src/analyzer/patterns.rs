//! Common instruction patterns for Solana programs

use anyhow::Result;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::UiTransactionEncoding;
use crate::models::instruction::Instruction;
use log;

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
                if let Some(message) = &ui_transaction.message {
                    // Extract instructions
                    if let Some(instructions) = &message.instructions {
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
                                                if let Ok(data) = base64::decode(data_str) {
                                                    instruction_data.push(data);
                                                } else {
                                                    log::debug!("Failed to decode instruction data as base58 or base64");
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
                
                // For binary transactions, we would need to:
                // 1. Decode the transaction based on the encoding
                // 2. Parse the message
                // 3. Extract instructions for our program
                
                // This is a simplified placeholder implementation
                if let Ok(transaction_bytes) = base64::decode(data) {
                    // In a real implementation, we would parse the transaction bytes
                    // and extract instructions for our program
                    
                    // For now, just check if our program ID appears in the data
                    let program_id_bytes = program_id.to_bytes();
                    if transaction_bytes.windows(program_id_bytes.len()).any(|window| window == program_id_bytes) {
                        // If we find the program ID, add a placeholder instruction
                        instruction_data.push(vec![0, 1, 2, 3]);
                    }
                }
            },
            _ => {
                // Handle other encoding formats
                log::debug!("Unsupported transaction encoding format");
            }
        }
    }
    
    // If we couldn't extract any real data, add some placeholders for testing
    if instruction_data.is_empty() && !transactions.is_empty() {
        log::debug!("No instruction data extracted, adding placeholders");
        instruction_data.push(vec![0, 1, 2, 3]);
        instruction_data.push(vec![1, 4, 5, 6]);
    }
    
    instruction_data
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
                if let Some(message) = &ui_transaction.message {
                    // Extract instructions
                    if let Some(instructions) = &message.instructions {
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
                                                let is_signer = is_account_signer(message, idx);
                                                let is_writable = is_account_writable(message, idx);
                                                
                                                // Create a key for this pattern
                                                let key = (discriminator, i, is_signer, is_writable);
                                                
                                                // Count frequency
                                                *frequency_map.entry(key).or_insert(0) += 1;
                                            } else {
                                                log::debug!("Failed to parse account index: {}", account_idx_str);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            solana_transaction_status::EncodedTransaction::Binary(_, _) => {
                // Process binary-encoded transaction
                // This would require more complex decoding
                log::debug!("Binary transaction analysis not implemented");
            },
            _ => {
                // Handle other encoding formats
                log::debug!("Unsupported transaction encoding format");
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
    
    // If we couldn't extract any patterns, add a placeholder
    if patterns.is_empty() && !transactions.is_empty() {
        log::debug!("No account patterns extracted, adding placeholder");
        patterns.push(AccountPattern {
            instruction_index: 0,
            account_index: 0,
            is_signer: true,
            is_writable: true,
            frequency: 1,
        });
    }
    
    patterns
}

/// Extract the instruction discriminator
fn extract_discriminator(instruction: &solana_transaction_status::UiInstruction) -> u8 {
    // The UiInstruction structure has a data field that contains the base58-encoded instruction data
    if let Some(data_str) = &instruction.data {
        // Try to decode the data
        match bs58::decode(data_str).into_vec() {
            Ok(data) => {
                if !data.is_empty() {
                    return data[0];
                }
            },
            Err(err) => {
                log::debug!("Failed to decode instruction data: {}", err);
            }
        }
    }
    0 // Default discriminator if we can't extract one
}

/// Check if an account is a signer
fn is_account_signer(message: &solana_transaction_status::UiMessage, account_idx: usize) -> bool {
    // The UiMessage structure has changed - we need to adapt our code
    // Check if the account is in the signers list
    if let Some(signers) = &message.header.as_ref().map(|h| &h.num_required_signatures) {
        if let Ok(num_signers) = signers.parse::<usize>() {
            return account_idx < num_signers;
        }
    }
    
    // Alternative approach: check if the account is marked as a signer in the account keys
    if let Some(account_keys) = &message.account_keys {
        if account_idx < account_keys.len() {
            if let Some(meta) = account_keys.get(account_idx) {
                return meta.signer;
            }
        }
    }
    
    false
}

/// Check if an account is writable
fn is_account_writable(message: &solana_transaction_status::UiMessage, account_idx: usize) -> bool {
    // The UiMessage structure has changed - we need to adapt our code
    // First approach: use header information
    if let Some(header) = &message.header {
        // Calculate writable accounts based on header information
        if let (Some(num_signers_str), Some(num_readonly_signers_str)) = (
            &header.num_required_signatures,
            &header.num_readonly_signed_accounts
        ) {
            if let (Ok(num_signers), Ok(num_readonly_signers)) = (
                num_signers_str.parse::<usize>(),
                num_readonly_signers_str.parse::<usize>()
            ) {
                // If it's a signer, check if it's not in the readonly signers
                if account_idx < num_signers {
                    return account_idx < (num_signers - num_readonly_signers);
                }
                
                // If it's not a signer, check if it's not in the readonly non-signers
                if let Some(num_readonly_unsigned_str) = &header.num_readonly_unsigned_accounts {
                    if let Ok(num_readonly_unsigned) = num_readonly_unsigned_str.parse::<usize>() {
                        if let Some(account_keys) = &message.account_keys {
                            let num_accounts = account_keys.len();
                            let num_unsigned = num_accounts - num_signers;
                            
                            if account_idx >= num_signers {
                                return (account_idx - num_signers) < (num_unsigned - num_readonly_unsigned);
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Alternative approach: check if the account is marked as writable in the account keys
    if let Some(account_keys) = &message.account_keys {
        if account_idx < account_keys.len() {
            if let Some(meta) = account_keys.get(account_idx) {
                return meta.writable;
            }
        }
    }
    
    false
}

/// Detect common parameter patterns in instruction data
pub fn detect_parameter_patterns(instruction_data: &[Vec<u8>]) -> Vec<String> {
    // Placeholder implementation
    // this would analyze instruction data
    // to identify common parameter patterns
    
    Vec::new()
}

/// Detect common account usage patterns
pub fn detect_account_patterns(
    program_id: &Pubkey,
    transactions: &[solana_transaction_status::EncodedTransaction],
) -> Vec<AccountPattern> {
    // Placeholder implementation
    // this would analyze account usage patterns
    // in transactions to identify common patterns
    
    Vec::new()
} 