//! RPC client interactions for Solana programs

use anyhow::{Result, anyhow};
use solana_client::rpc_client::RpcClient;
use solana_pubkey::Pubkey;
use solana_transaction_status::{EncodedTransaction, UiTransactionEncoding};
use solana_signature::Signature;
use solana_account::Account;
use reqwest;
use base64;
use std::str::FromStr;

/// Get program data for the given program ID with retry logic
pub async fn get_program_data(rpc_client: &RpcClient, program_id: &Pubkey) -> Result<Vec<u8>> {
    // Create HTTP client with timeout
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    
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
    
    // Try up to 3 times with exponential backoff
    let mut retry_delay = 1000; // Start with 1 second
    let mut last_error = None;
    
    for attempt in 1..=3 {
        log::info!("Fetching program data, attempt {}/3", attempt);
        
        // Send request
        match client.post(rpc_client.url())
            .json(&request)
            .send()
            .await {
                Ok(response) => {
                    match response.json::<serde_json::Value>().await {
                        Ok(json_response) => {
                            // Check for RPC error
                            if let Some(error) = json_response.get("error") {
                                last_error = Some(anyhow!("RPC error: {}", error));
                                log::warn!("RPC error on attempt {}: {}", attempt, error);
                            } else if let Some(result) = json_response.get("result").and_then(|r| r.get("value")) {
                                // Parse account data
                                if let Some(data_str) = result.get("data")
                                    .and_then(|d| d.get(0))
                                    .and_then(|d| d.as_str()) {
                                    
                                    match base64::decode(data_str) {
                                        Ok(data) => {
                                            // Check if this is a program account
                                            let executable = result.get("executable")
                                                .and_then(|e| e.as_bool())
                                                .unwrap_or(false);
                                                
                                            if !executable {
                                                log::warn!("Account is not executable (not a program)");
                                                
                                                // Check if this is a BPF Upgradeable Loader account
                                                let owner = result.get("owner")
                                                    .and_then(|o| o.as_str())
                                                    .unwrap_or("");
                                                
                                                if owner == "BPFLoaderUpgradeab1e11111111111111111111111" {
                                                    log::info!("This is a BPF Upgradeable Loader account, fetching program data");
                                                    
                                                    // Parse the program data account address from the data
                                                    if data.len() >= 36 {
                                                        let program_data_address = Pubkey::new(&data[4..36]);
                                                        log::info!("Program data account: {}", program_data_address);
                                                        
                                                        // Recursively fetch the program data account
                                                        return get_program_data(rpc_client, &program_data_address).await;
                                                    }
                                                }
                                                
                                                return Err(anyhow!("Account is not executable (not a program)"));
                                            }
                                            
                                            log::info!("Successfully fetched program data, size: {} bytes", data.len());
                                            return Ok(data);
                                        },
                                        Err(e) => {
                                            last_error = Some(anyhow!("Failed to decode base64 data: {}", e));
                                            log::warn!("Failed to decode base64 data on attempt {}: {}", attempt, e);
                                        }
                                    }
                                } else {
                                    last_error = Some(anyhow!("Invalid account data format"));
                                    log::warn!("Invalid account data format on attempt {}", attempt);
                                }
                            } else {
                                last_error = Some(anyhow!("Account not found or empty result"));
                                log::warn!("Account not found or empty result on attempt {}", attempt);
                            }
                        },
                        Err(e) => {
                            last_error = Some(anyhow!("Failed to parse JSON response: {}", e));
                            log::warn!("Failed to parse JSON response on attempt {}: {}", attempt, e);
                        }
                    }
                },
                Err(e) => {
                    last_error = Some(anyhow!("Request error: {}", e));
                    log::warn!("Request error on attempt {}: {}", e, attempt);
                }
            }
        
        // If this wasn't the last attempt, wait before retrying
        if attempt < 3 {
            log::info!("Retrying in {} ms", retry_delay);
            tokio::time::sleep(tokio::time::Duration::from_millis(retry_delay)).await;
            retry_delay *= 2; // Exponential backoff
        }
    }
    
    // If we got here, all attempts failed
    Err(last_error.unwrap_or_else(|| anyhow!("Failed to fetch program data after 3 attempts")))
}

/// Get recent transactions for the given program ID
pub async fn get_recent_transactions(
    rpc_client: &RpcClient, 
    program_id: &Pubkey,
    limit: Option<usize>
) -> Result<Vec<EncodedTransaction>> {
    let limit = limit.unwrap_or(100); // Default to 100 transactions
    log::info!("Fetching up to {} recent transactions for program {}", limit, program_id);
    
    // Create HTTP client
    let client = reqwest::Client::new();
    
    // Build RPC request for getSignaturesForAddress
    let signatures_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignaturesForAddress",
        "params": [
            program_id.to_string(),
            {
                "limit": limit
            }
        ]
    });
    
    // Send request to get signatures
    let signatures_response = client.post(rpc_client.url())
        .json(&signatures_request)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    
    // Parse the signatures response
    if let Some(error) = signatures_response.get("error") {
        return Err(anyhow!("RPC error fetching signatures: {}", error));
    }
    
    let signatures = match signatures_response.get("result") {
        Some(result) => {
            if let Some(array) = result.as_array() {
                array.iter()
                    .filter_map(|item| item.get("signature")?.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>()
            } else {
                return Err(anyhow!("Invalid signature response format"));
            }
        },
        None => return Err(anyhow!("No signatures found in response")),
    };
    
    log::info!("Found {} transaction signatures", signatures.len());
    
    if signatures.is_empty() {
        return Ok(Vec::new());
    }
    
    // Now fetch the actual transactions
    let mut transactions = Vec::new();
    
    for signature_batch in signatures.chunks(10) { // Process in batches to avoid rate limits
        // Build RPC request for getTransaction
        let batch_request = signature_batch.iter().enumerate().map(|(i, signature)| {
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": i + 1,
                "method": "getTransaction",
                "params": [
                    signature,
                    {
                        "encoding": "json",
                        "maxSupportedTransactionVersion": 0
                    }
                ]
            })
        }).collect::<Vec<_>>();
        
        // Send batch request
        let batch_response = client.post(rpc_client.url())
            .json(&batch_request)
            .send()
            .await?
            .json::<Vec<serde_json::Value>>()
            .await?;
        
        // Process each transaction in the batch
        for response in batch_response {
            if let Some(error) = response.get("error") {
                log::warn!("Error fetching transaction: {}", error);
                continue;
            }
            
            if let Some(result) = response.get("result") {
                if let Some(transaction) = result.get("transaction") {
                    // Convert to EncodedTransaction
                    let encoded_tx = EncodedTransaction::Json(transaction.clone());
                    transactions.push(encoded_tx);
                }
            }
        }
        
        // Add a small delay to avoid rate limiting
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    
    log::info!("Successfully fetched {} transactions", transactions.len());
    Ok(transactions)
}

/// Get account info for the given account ID
pub fn get_account_info(rpc_client: &RpcClient, account_id: &Pubkey) -> Result<solana_account::Account> {
    Ok(rpc_client.get_account(account_id)?)
} 