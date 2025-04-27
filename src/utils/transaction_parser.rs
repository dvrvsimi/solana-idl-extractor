//! Transaction parsing utilities for Solana programs.
//!
//! This module provides robust utilities for parsing Solana transactions
//! in various formats, including binary, base58, base64, and JSON.
//! It includes fallback mechanisms for handling different transaction formats
//! and detailed error reporting.

use anyhow::{Result, anyhow, Context};
use log::{debug, info, warn};
use solana_pubkey::Pubkey;
use solana_instruction::Instruction;
use solana_instruction::account_meta::AccountMeta;
use solana_transaction::Transaction;
use solana_transaction::versioned::VersionedTransaction;
use solana_message::v0::Message as MessageV0;
use std::str::FromStr;
use bincode;
use bs58;
use base64;
use serde_json;
use crate::errors::{ExtractorError, ExtractorResult, ErrorExt, ErrorContext};

/// Parse a binary transaction and extract instruction data and accounts.
///
/// This function attempts to parse a transaction in multiple formats,
/// including binary, base58, base64, and JSON. It includes fallback
/// mechanisms for handling different transaction formats and detailed
/// error reporting.
///
/// # Arguments
///
/// * `transaction_data` - The binary transaction data to parse.
///
/// # Returns
///
/// A result containing the instruction data and account metas, or an error
/// if the transaction could not be parsed.
pub fn parse_transaction(transaction_data: &[u8]) -> ExtractorResult<(Vec<u8>, Vec<AccountMeta>)> {
    // Create context for errors
    let context = ErrorContext {
        program_id: None,
        component: "transaction_parser".to_string(),
        operation: "parse_transaction".to_string(),
        details: Some(format!("data_len={}", transaction_data.len())),
    };
    
    // Try multiple formats with better error handling and detailed logging
    let result = try_parse_binary(transaction_data)
        .or_else(|e| {
            debug!("Binary parsing failed: {}", e);
            try_parse_base58(transaction_data)
        })
        .or_else(|e| {
            debug!("Base58 parsing failed: {}", e);
            try_parse_base64(transaction_data)
        })
        .or_else(|e| {
            debug!("Base64 parsing failed: {}", e);
            try_parse_json(transaction_data)
        })
        .or_else(|e| {
            debug!("JSON parsing failed: {}", e);
            extract_from_raw_data(transaction_data)
        });
    
    // Add detailed logging for debugging
    match &result {
        Ok(_) => debug!("Successfully parsed transaction data"),
        Err(e) => warn!("All parsing methods failed: {}", e),
    }
    
    // Add context to the error
    result.map_err(|e| ExtractorError::from_anyhow(e.into(), context))
}

/// Try to parse transaction data as a binary transaction.
///
/// # Arguments
///
/// * `data` - The binary data to parse.
///
/// # Returns
///
/// A result containing the instruction data and account metas, or an error
/// if the data could not be parsed as a binary transaction.
fn try_parse_binary(data: &[u8]) -> ExtractorResult<(Vec<u8>, Vec<AccountMeta>)> {
    // Use the existing Transaction type
    match bincode::deserialize::<Transaction>(data) {
        Ok(tx) => extract_from_legacy_transaction(&tx),
        Err(e) => {
            // If it's not a legacy transaction, try as versioned transaction
            match bincode::deserialize::<VersionedTransaction>(data) {
                Ok(versioned_tx) => match versioned_tx {
                    VersionedTransaction::Legacy(tx) => extract_from_legacy_transaction(&tx),
                    VersionedTransaction::V0(tx) => {
                        let message = &tx.message;
                        extract_from_v0_message(message)
                    },
                },
                Err(_) => Err(ExtractorError::TransactionParsing(
                    format!("Failed to deserialize transaction: {}", e)
                )),
            }
        }
    }
}

/// Try to parse transaction data as a base58-encoded transaction.
///
/// # Arguments
///
/// * `data` - The data to parse.
///
/// # Returns
///
/// A result containing the instruction data and account metas, or an error
/// if the data could not be parsed as a base58-encoded transaction.
fn try_parse_base58(data: &[u8]) -> ExtractorResult<(Vec<u8>, Vec<AccountMeta>)> {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(decoded) = bs58::decode(s).into_vec() {
            try_parse_binary(&decoded)
        } else {
            Err(ExtractorError::TransactionParsing(
                "Not a valid base58 encoded transaction".to_string()
            ))
        }
    } else {
        Err(ExtractorError::TransactionParsing(
            "Not a valid UTF-8 string for base58 decoding".to_string()
        ))
    }
}

/// Try to parse transaction data as a base64-encoded transaction.
///
/// # Arguments
///
/// * `data` - The data to parse.
///
/// # Returns
///
/// A result containing the instruction data and account metas, or an error
/// if the data could not be parsed as a base64-encoded transaction.
fn try_parse_base64(data: &[u8]) -> ExtractorResult<(Vec<u8>, Vec<AccountMeta>)> {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(decoded) = base64::decode(s) {
            try_parse_binary(&decoded)
        } else {
            Err(ExtractorError::TransactionParsing(
                "Not a valid base64 encoded transaction".to_string()
            ))
        }
    } else {
        Err(ExtractorError::TransactionParsing(
            "Not a valid UTF-8 string for base64 decoding".to_string()
        ))
    }
}

/// Try to parse transaction data as a JSON transaction.
///
/// # Arguments
///
/// * `data` - The data to parse.
///
/// # Returns
///
/// A result containing the instruction data and account metas, or an error
/// if the data could not be parsed as a JSON transaction.
fn try_parse_json(data: &[u8]) -> ExtractorResult<(Vec<u8>, Vec<AccountMeta>)> {
    if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(data) {
        // Try multiple JSON formats
        if let Some(tx_str) = json_value.get("transaction")
            .and_then(|v| v.as_str())
            .or_else(|| json_value.get("data").and_then(|v| v.as_str()))
            .or_else(|| json_value.get("message").and_then(|v| v.as_str()))
        {
            // Try base58 first
            if let Ok(decoded) = bs58::decode(tx_str).into_vec() {
                return try_parse_binary(&decoded);
            }
            
            // Then try base64
            if let Ok(decoded) = base64::decode(tx_str) {
                return try_parse_binary(&decoded);
            }
        }
        
        // Try parsing directly from JSON structure
        if let Some(instructions) = json_value.get("instructions").and_then(|v| v.as_array()) {
            if !instructions.is_empty() {
                if let Some(first_ix) = instructions.first() {
                    // Extract data and accounts from JSON instruction
                    let data = first_ix.get("data")
                        .and_then(|v| v.as_str())
                        .map(|s| bs58::decode(s).into_vec().unwrap_or_default())
                        .unwrap_or_default();
                    
                    let accounts = first_ix.get("accounts")
                        .and_then(|v| v.as_array())
                        .map(|accounts_arr| {
                            accounts_arr.iter()
                                .filter_map(|a| {
                                    let pubkey_str = a.get("pubkey").and_then(|p| p.as_str())?;
                                    let pubkey = Pubkey::from_str(pubkey_str).ok()?;
                                    let is_signer = a.get("isSigner").and_then(|s| s.as_bool()).unwrap_or(false);
                                    let is_writable = a.get("isWritable").and_then(|w| w.as_bool()).unwrap_or(false);
                                    
                                    if is_writable {
                                        Some(AccountMeta::new(pubkey, is_signer))
                                    } else {
                                        Some(AccountMeta::new_readonly(pubkey, is_signer))
                                    }
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    
                    if !data.is_empty() || !accounts.is_empty() {
                        return Ok((data, accounts));
                    }
                }
            }
        }
    }
    
    Err(ExtractorError::TransactionParsing(
        "Not a valid JSON transaction".to_string()
    ))
}

/// Extract from raw instruction data using heuristics with better fallbacks.
///
/// This function attempts to extract instruction data and accounts from raw data
/// when other parsing methods fail. It uses heuristics to determine the format
/// of the data and provides fallback mechanisms for different formats.
///
/// # Arguments
///
/// * `data` - The raw data to parse.
///
/// # Returns
///
/// A result containing the instruction data and account metas, or an error
/// if the data could not be parsed.
fn extract_from_raw_data(data: &[u8]) -> ExtractorResult<(Vec<u8>, Vec<AccountMeta>)> {
    // Check if this looks like instruction data with an Anchor discriminator
    if data.len() >= 8 {
        // This might be an Anchor instruction with 8-byte discriminator
        let instruction_data = data.to_vec();
        
        // Create a dummy account meta since we can't determine accounts from raw data
        let dummy_account = AccountMeta::new(Pubkey::new_unique(), false);
        
        debug!("Extracted raw data as potential Anchor instruction (8-byte discriminator)");
        return Ok((instruction_data, vec![dummy_account]));
    }
    
    // Check if this looks like a non-Anchor instruction with a single byte discriminator
    if !data.is_empty() {
        // This might be a non-Anchor instruction with 1-byte discriminator
        let instruction_data = data.to_vec();
        
        // Create a dummy account meta
        let dummy_account = AccountMeta::new(Pubkey::new_unique(), false);
        
        debug!("Extracted raw data as potential non-Anchor instruction (1-byte discriminator)");
        return Ok((instruction_data, vec![dummy_account]));
    }
    
    // Last resort: treat the entire data as a raw instruction with no discriminator
    if !data.is_empty() {
        debug!("Treating entire data as raw instruction with no discriminator");
        let dummy_account = AccountMeta::new(Pubkey::new_unique(), false);
        return Ok((data.to_vec(), vec![dummy_account]));
    }
    
    Err(ExtractorError::TransactionParsing(
        "Could not parse transaction data: empty or invalid format".to_string()
    ))
}

/// Extract instruction data and accounts from a legacy transaction.
///
/// # Arguments
///
/// * `tx` - The legacy transaction to extract from.
///
/// # Returns
///
/// A result containing the instruction data and account metas, or an error
/// if the transaction does not contain any program instructions.
fn extract_from_legacy_transaction(tx: &Transaction) -> ExtractorResult<(Vec<u8>, Vec<AccountMeta>)> {
    // Find the first instruction that's not a compute budget instruction
    for instruction in &tx.message.instructions {
        let program_id = instruction.program_id;
        
        // Skip compute budget instructions
        if program_id == Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap_or_default() {
            continue;
        }
        
        // Extract instruction data
        let data = instruction.data.clone();
        
        // Extract account metas
        let accounts = instruction.accounts.clone();
        
        return Ok((data, accounts));
    }
    
    Err(ExtractorError::TransactionParsing(
        "No program instructions found in transaction".to_string()
    ))
}

/// Extract instruction data and accounts from a V0 message.
///
/// # Arguments
///
/// * `message` - The V0 message to extract from.
///
/// # Returns
///
/// A result containing the instruction data and account metas, or an error
/// if the message does not contain any program instructions.
fn extract_from_v0_message(message: &MessageV0) -> ExtractorResult<(Vec<u8>, Vec<AccountMeta>)> {
    // Find the first instruction that's not a compute budget instruction
    for compiled_ix in &message.instructions {
        let program_idx = compiled_ix.program_id_index as usize;
        if program_idx >= message.account_keys.len() {
            continue; // Skip invalid program index
        }
        
        let program_id = message.account_keys[program_idx];
        
        // Skip compute budget instructions
        if program_id == Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap_or_default() {
            continue;
        }
        
        // Extract instruction data
        let data = compiled_ix.data.clone();
        
        // Extract account metas with better bounds checking
        let mut accounts = Vec::new();
        for idx in &compiled_ix.accounts {
            let account_idx = *idx as usize;
            if account_idx >= message.account_keys.len() {
                continue; // Skip invalid account index
            }
            
            let pubkey = message.account_keys[account_idx];
            
            // Determine if signer and writable with safer checks
            let is_signer = account_idx < message.header.num_required_signatures as usize;
            let is_writable = message.is_maybe_writable(account_idx, None);
            
            if is_writable {
                accounts.push(AccountMeta::new(pubkey, is_signer));
            } else {
                accounts.push(AccountMeta::new_readonly(pubkey, is_signer));
            }
        }
        
        return Ok((data, accounts));
    }
    
    Err(ExtractorError::TransactionParsing(
        "No program instructions found in transaction".to_string()
    ))
} 