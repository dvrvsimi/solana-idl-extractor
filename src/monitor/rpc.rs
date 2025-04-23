//! RPC client interactions for Solana programs

use anyhow::{Result, anyhow};
use solana_client::rpc_client::RpcClient;
use solana_pubkey::Pubkey;
use solana_transaction_status::{EncodedTransaction, UiTransactionEncoding};
use solana_sdk::signature::Signature;
use solana_account::Account;
use reqwest;
use base64;
use std::str::FromStr;

/// Get program data for the given program ID
pub async fn get_program_data(rpc_url: &str, program_id: &Pubkey) -> Result<Vec<u8>> {
    // Create HTTP client
    let client = reqwest::Client::new();
    
    // Build RPC request
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [
            program_id.to_string(),
            {"encoding": "base64"}
        ]
    });
    
    // Send request
    let response = client.post(rpc_url)
        .json(&request)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
        
    // Parse the response
    if let Some(error) = response.get("error") {
        return Err(anyhow!("RPC error: {}", error));
    }
    
    if let Some(result) = response.get("result").and_then(|r| r.get("value")) {
        // Parse account data
        let data = result.get("data")
            .and_then(|d| d.get(0))
            .and_then(|d| d.as_str())
            .ok_or_else(|| anyhow!("Invalid account data format"))?;
            
        let data = base64::decode(data)?;
        
        // Check if this is a program account
        let executable = result.get("executable")
            .and_then(|e| e.as_bool())
            .unwrap_or(false);
            
        if !executable {
            return Err(anyhow!("Account is not executable (not a program)"));
        }
        
        Ok(data)
    } else {
        Err(anyhow!("Account not found"))
    }
}

/// Get recent transactions for the given program ID (simplified)
pub fn get_recent_transactions(
    _rpc_client: &RpcClient, 
    program_id: &Pubkey,
    limit: Option<usize>
) -> Result<Vec<EncodedTransaction>> {
    // Return empty vector for now to avoid RPC calls
    log::info!("Simplified implementation: not fetching transactions for program {}", program_id);
    log::info!("Requested limit: {:?}", limit);
    
    Ok(Vec::new())
}

/// Get account info for the given account ID
pub fn get_account_info(rpc_client: &RpcClient, account_id: &Pubkey) -> Result<solana_sdk::account::Account> {
    Ok(rpc_client.get_account(account_id)?)
} 