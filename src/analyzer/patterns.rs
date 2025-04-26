//! Common instruction patterns for Solana programs

use anyhow::Result;
use log::{debug, info, warn};
use solana_pubkey::Pubkey;  // Updated import
use solana_transaction_status::{UiTransactionEncoding, TransactionBinaryEncoding, UiMessage, UiInstruction, UiCompiledInstruction, UiParsedInstruction, UiRawMessage};
use crate::models::instruction::Instruction;
use crate::constants::discriminator::program_ids;
use log;
use std::str::FromStr;
use solana_clock::Clock;
use solana_rent::Rent;
use crate::errors::{ExtractorError, ExtractorResult, ErrorExt, ErrorContext};
use solana_program::sysvar::SysvarId;

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
) -> ExtractorResult<PatternAnalysis> {
    let context = ErrorContext {
        program_id: Some(program_id.to_string()),
        component: "pattern_analyzer".to_string(),
        operation: "analyze_patterns".to_string(),
        details: Some(format!("transaction_count={}", transactions.len())),
    };
    
    // Extract instruction data with better error handling
    let instruction_data = extract_instruction_data(program_id, transactions)
        .with_simple_context("pattern_analyzer", "extract_instruction_data")?;
    
    // Analyze instruction patterns
    let instruction_patterns = analyze_instruction_patterns(&instruction_data)
        .with_simple_context("pattern_analyzer", "analyze_instruction_patterns")?;
    
    // Analyze account patterns
    let account_patterns = analyze_account_patterns(program_id, transactions)
        .with_simple_context("pattern_analyzer", "analyze_account_patterns")?;
    
    Ok(PatternAnalysis {
        instruction_patterns,
        account_patterns,
    })
}

/// Extract instruction data from transactions
pub fn extract_instruction_data(
    program_id: &Pubkey,
    transactions: &[solana_transaction_status::EncodedTransaction],
) -> ExtractorResult<Vec<Vec<u8>>> {
    let mut instruction_data = Vec::new();
    
    for transaction in transactions {
        match transaction {
            solana_transaction_status::EncodedTransaction::Json(ui_transaction) => {
                // Process JSON-encoded transaction
                let ui_message = &ui_transaction.message;
                
                // Handle different UiMessage variants
                match ui_message {
                    UiMessage::Parsed(parsed_message) => {
                        // Handle parsed message
                        for instruction in &parsed_message.instructions {
                        // Check if this instruction is for our program
                            if let Some(program_id_str) = get_program_id(instruction, ui_message) {
                                if program_id_str == program_id.to_string() {
                                // Extract instruction data
                                    if let Some(data_str) = get_instruction_data(instruction) {
                                    // Try base58 decoding first
                                        match bs58::decode(&data_str).into_vec() {
                                        Ok(data) => {
                                            instruction_data.push(data);
                                        },
                                        Err(err) => {
                                            // Log the error but continue processing
                                            log::debug!("Failed to decode base58 data: {}", err);
                                            
                                            // Try base64 decoding as fallback
                                                match base64::decode(&data_str) {
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
                    },
                    UiMessage::Raw(raw_message) => {
                        // Handle raw message
                        for instruction in &raw_message.instructions {
                            // Raw messages only have UiCompiledInstruction, not UiInstruction enum
                            let compiled = instruction; // instruction is already a UiCompiledInstruction
                            
                            // Check if this instruction is for our program
                            if compiled.program_id_index < raw_message.account_keys.len() as u8 {
                                let program_id_str = raw_message.account_keys[compiled.program_id_index as usize].clone();
                                
                                if program_id_str == program_id.to_string() {
                                    // Extract instruction data
                                    let data_str = &compiled.data;
                                    
                                    // Try base58 decoding first
                                    match bs58::decode(data_str).into_vec() {
                                        Ok(data) => {
                                            instruction_data.push(data);
                                        },
                                        Err(err) => {
                                            // Try base64 decoding as fallback
                                            if let Ok(data) = base64::decode(data_str) {
                                                instruction_data.push(data);
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
                            extract_from_binary(&tx_data, program_id, &mut instruction_data)?;
                        }
                    },
                    TransactionBinaryEncoding::Base64 => {
                        if let Ok(tx_data) = base64::decode(data) {
                            extract_from_binary(&tx_data, program_id, &mut instruction_data)?;
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
    
    Ok(instruction_data)
}

/// Extract instruction data from binary transaction data with improved error handling
fn extract_from_binary(tx_data: &[u8], program_id: &Pubkey, instruction_data: &mut Vec<Vec<u8>>) -> ExtractorResult<()> {
    match crate::utils::transaction_parser::parse_transaction(tx_data) {
        Ok((data, _)) => {
            instruction_data.push(data);
            Ok(())
        },
        Err(e) => {
            // Log the error but don't fail the entire analysis
            debug!("Failed to parse transaction: {}", e);
            
            // Try a fallback approach for this specific transaction
            if tx_data.len() > 1 {
                // Simple fallback: just take the first byte as discriminator and the rest as data
                let fallback_data = tx_data.to_vec();
                debug!("Using fallback approach: treating first byte as discriminator");
                instruction_data.push(fallback_data);
                Ok(())
            } else {
                // If we can't even do that, return the error
                Err(ExtractorError::TransactionParsing(
                    format!("Failed to parse transaction and no fallback available: {}", e)
                ))
            }
        }
    }
}

/// Analyze instruction patterns
fn analyze_instruction_patterns(instruction_data: &[Vec<u8>]) -> ExtractorResult<Vec<InstructionPattern>> {
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
    
    Ok(patterns)
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
) -> ExtractorResult<Vec<AccountPattern>> {
    let mut patterns = Vec::new();
    let mut frequency_map = std::collections::HashMap::new();
    
    for transaction in transactions {
        match transaction {
            solana_transaction_status::EncodedTransaction::Json(ui_transaction) => {
                // Process JSON-encoded transaction
                let ui_message = &ui_transaction.message;
                
                // Handle different UiMessage variants
                match ui_message {
                    UiMessage::Parsed(parsed_message) => {
                        // Handle parsed message
                        for instruction in &parsed_message.instructions {
                            // Check if this instruction is for our program
                            if let Some(program_id_str) = get_program_id(instruction, ui_message) {
                                if program_id_str == program_id.to_string() {
                                    // Extract instruction discriminator
                                    let discriminator = extract_discriminator(instruction);
                                    
                                    // Extract account usage
                                    let accounts = match instruction {
                                        UiInstruction::Compiled(compiled) => {
                                            // For compiled instructions, convert account indices to strings
                                            Some(compiled.accounts.iter().map(|&idx| idx.to_string()).collect::<Vec<_>>())
                                        },
                                        UiInstruction::Parsed(parsed) => {
                                            match parsed {
                                                UiParsedInstruction::Parsed(_) => None,
                                                UiParsedInstruction::PartiallyDecoded(partially_decoded) => {
                                                    Some(partially_decoded.accounts.clone())
                                                }
                                            }
                                        }
                                    };
                                    
                                    if let Some(accounts) = accounts {
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
                    },
                    UiMessage::Raw(raw_message) => {
                        // Handle raw message
                        for instruction in &raw_message.instructions {
                            // Check if this instruction is for our program
                            if let Some(program_id_str) = get_program_id_raw(instruction, raw_message) {
                                if program_id_str == program_id.to_string() {
                                    // Extract instruction discriminator
                                    let discriminator = extract_discriminator_raw(instruction);
                                    
                                    // Extract account usage
                                    let accounts = instruction.accounts.iter()
                                        .map(|&idx| idx.to_string())
                                        .collect::<Vec<_>>();
                                    
                                    // Rest of your code...
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
    
    Ok(patterns)
}

/// Extract the instruction discriminator
pub fn extract_discriminator(instruction: &UiInstruction) -> u8 {
    match instruction {
        UiInstruction::Compiled(compiled) => {
            // For compiled instructions, decode the data field
            if let Ok(data) = bs58::decode(&compiled.data).into_vec() {
                if !data.is_empty() {
                    return data[0];
                }
            }
        },
        UiInstruction::Parsed(parsed) => {
            match parsed {
                UiParsedInstruction::Parsed(parsed_instruction) => {
                    // For fully parsed instructions, we might need to extract from the parsed JSON
                    // This is a simplification - in a real implementation you'd extract from parsed.parsed
                    return 0; // Default for now
                },
                UiParsedInstruction::PartiallyDecoded(partially_decoded) => {
                    // For partially decoded instructions, decode the data field
                    if let Ok(data) = bs58::decode(&partially_decoded.data).into_vec() {
            if !data.is_empty() {
                return data[0];
                        }
                    }
                }
            }
        }
    }
    0 // Default return
}

/// Check if an account is a signer
pub fn is_account_signer(message: &UiMessage, account_idx: usize) -> bool {
    match message {
        UiMessage::Parsed(parsed_message) => {
            if account_idx < parsed_message.account_keys.len() {
                return parsed_message.account_keys[account_idx].signer;
            }
        },
        UiMessage::Raw(raw_message) => {
            // For raw messages, check if the account index is within the required signatures
            return account_idx < raw_message.header.num_required_signatures as usize;
        }
    }
    false
}

/// Check if an account is writable
pub fn is_account_writable(message: &UiMessage, account_idx: usize) -> bool {
    match message {
        UiMessage::Parsed(parsed_message) => {
            if account_idx < parsed_message.account_keys.len() {
                return parsed_message.account_keys[account_idx].writable;
            }
        },
        UiMessage::Raw(raw_message) => {
            // For raw messages, determine if writable based on the account's position
            // Accounts are writable if they're in the first section (before readonly signed accounts)
            // or in the third section (after readonly signed accounts but before readonly unsigned accounts)
            let num_required_sigs = raw_message.header.num_required_signatures as usize;
            let num_readonly_signed = raw_message.header.num_readonly_signed_accounts as usize;
            let num_readonly_unsigned = raw_message.header.num_readonly_unsigned_accounts as usize;
            
            // First section: writable signed accounts
            if account_idx < (num_required_sigs - num_readonly_signed) {
                return true;
            }
            
            // Third section: writable unsigned accounts
            let total_readonly = num_readonly_signed + num_readonly_unsigned;
            let total_accounts = raw_message.account_keys.len();
            if account_idx >= num_required_sigs && account_idx < (total_accounts - num_readonly_unsigned) {
                return true;
            }
            
            return false;
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
) -> ExtractorResult<Vec<AccountPattern>> {
    let mut patterns = Vec::new();
    let mut frequency_map = std::collections::HashMap::new();
    
    for transaction in transactions {
        match transaction {
            solana_transaction_status::EncodedTransaction::Json(ui_transaction) => {
                // Process JSON-encoded transaction
                let ui_message = &ui_transaction.message;
                
                // Handle different UiMessage variants
                match ui_message {
                    UiMessage::Parsed(parsed_message) => {
                        // Handle parsed message
                        for instruction in &parsed_message.instructions {
                            // Check if this instruction is for our program
                            if let Some(program_id_str) = get_program_id(instruction, ui_message) {
                                if program_id_str == program_id.to_string() {
                                    // Extract instruction discriminator
                                    let discriminator = extract_discriminator(instruction);
                                    
                                    // Extract account usage
                                    let accounts = match instruction {
                                        UiInstruction::Compiled(compiled) => {
                                            // For compiled instructions, convert account indices to strings
                                            Some(compiled.accounts.iter().map(|&idx| idx.to_string()).collect::<Vec<_>>())
                                        },
                                        UiInstruction::Parsed(parsed) => {
                                            match parsed {
                                                UiParsedInstruction::Parsed(_) => None,
                                                UiParsedInstruction::PartiallyDecoded(partially_decoded) => {
                                                    Some(partially_decoded.accounts.clone())
                                                }
                                            }
                                        }
                                    };
                                    
                                    if let Some(accounts) = accounts {
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
                    },
                    UiMessage::Raw(raw_message) => {
                        // Handle raw message
                        for instruction in &raw_message.instructions {
                            // Check if this instruction is for our program
                            if let Some(program_id_str) = get_program_id_raw(instruction, raw_message) {
                                if program_id_str == program_id.to_string() {
                                    // Extract instruction discriminator
                                    let discriminator = extract_discriminator_raw(instruction);
                                    
                                    // Extract account usage
                                    let accounts = instruction.accounts.iter()
                                        .map(|&idx| idx.to_string())
                                        .collect::<Vec<_>>();
                                    
                                    // Rest of your code...
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
    
    Ok(patterns)
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
    
    if account_pubkey.to_string() == program_ids::SYSTEM_PROGRAM {
        return "system_program".to_string();
    }
    
    if account_pubkey.to_string() == program_ids::TOKEN_PROGRAM {
        return "token_program".to_string();
    }
    
    if account_pubkey == &Rent::id() {
        return "rent".to_string();
    }
    
    if account_pubkey == &Clock::id() {
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

/// Extract program ID from an instruction
fn get_program_id(instruction: &UiInstruction, message: &UiMessage) -> Option<String> {
    match instruction {
        UiInstruction::Compiled(compiled) => {
            match message {
                UiMessage::Parsed(parsed_message) => {
                    if compiled.program_id_index < parsed_message.account_keys.len() as u8 {
                        Some(parsed_message.account_keys[compiled.program_id_index as usize].pubkey.clone())
                    } else {
                        None
                    }
                },
                UiMessage::Raw(raw_message) => {
                    if compiled.program_id_index < raw_message.account_keys.len() as u8 {
                        Some(raw_message.account_keys[compiled.program_id_index as usize].clone())
                    } else {
                        None
                    }
                }
            }
        },
        UiInstruction::Parsed(parsed) => {
            match parsed {
                UiParsedInstruction::Parsed(parsed_instruction) => {
                    Some(parsed_instruction.program_id.clone())
                },
                UiParsedInstruction::PartiallyDecoded(partially_decoded) => {
                    Some(partially_decoded.program_id.clone())
                }
            }
        }
    }
}

/// Extract data from an instruction
fn get_instruction_data(instruction: &UiInstruction) -> Option<String> {
    match instruction {
        UiInstruction::Compiled(compiled) => {
            Some(compiled.data.clone())
        },
        UiInstruction::Parsed(parsed) => {
            match parsed {
                UiParsedInstruction::Parsed(_) => {
                    // For fully parsed instructions, we don't have raw data
                    None
                },
                UiParsedInstruction::PartiallyDecoded(partially_decoded) => {
                    Some(partially_decoded.data.clone())
                }
            }
        }
    }
}

/// Extract accounts from an instruction
fn get_instruction_accounts(instruction: &UiInstruction) -> Option<Vec<String>> {
    match instruction {
        UiInstruction::Compiled(compiled) => {
            // For compiled instructions, convert account indices to strings
            let account_indices = &compiled.accounts;
            let account_strings = account_indices.iter()
                .map(|&idx| idx.to_string())
                .collect();
            Some(account_strings)
        },
        UiInstruction::Parsed(parsed) => {
            match parsed {
                UiParsedInstruction::Parsed(_) => {
                    // For fully parsed instructions, we don't have account indices
                    None
                },
                UiParsedInstruction::PartiallyDecoded(partially_decoded) => {
                    Some(partially_decoded.accounts.clone())
                }
            }
        }
    }
}

/// Add this helper function to handle UiCompiledInstruction directly
fn get_program_id_raw(instruction: &UiCompiledInstruction, raw_message: &UiRawMessage) -> Option<String> {
    if instruction.program_id_index < raw_message.account_keys.len() as u8 {
        Some(raw_message.account_keys[instruction.program_id_index as usize].clone())
    } else {
        None
    }
}

/// Add this helper function to extract discriminator from UiCompiledInstruction
fn extract_discriminator_raw(instruction: &UiCompiledInstruction) -> u8 {
    if let Ok(data) = bs58::decode(&instruction.data).into_vec() {
        if !data.is_empty() {
            return data[0];
        }
    }
    0
} 