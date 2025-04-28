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
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use once_cell::sync::Lazy;

// Define a set of RPC endpoints to try
pub const RPC_ENDPOINTS: [&str; 3] = [
    "https://api.devnet.solana.com",
    "https://devnet.genesysgo.net", 
    "https://devnet.helius.xyz"
];

// A global HTTP client with connection pooling
static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .build()
        .expect("Failed to create HTTP client")
});

// Blockhash cache
struct BlockhashCache {
    blockhash: Option<(String, Instant)>,
}

impl BlockhashCache {
    fn new() -> Self {
        Self { blockhash: None }
    }

    fn get(&self) -> Option<String> {
        match &self.blockhash {
            Some((hash, timestamp)) if timestamp.elapsed() < Duration::from_secs(30) => {
                Some(hash.clone())
            }
            _ => None,
        }
    }

    fn set(&mut self, blockhash: String) {
        self.blockhash = Some((blockhash, Instant::now()));
    }
}

static BLOCKHASH_CACHE: Lazy<Arc<Mutex<BlockhashCache>>> = Lazy::new(|| {
    Arc::new(Mutex::new(BlockhashCache::new()))
});

/// Check RPC endpoint health
pub async fn check_endpoint_health(url: &str) -> Result<bool> {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getHealth",
        "params": []
    });
    
    match HTTP_CLIENT.post(url)
        .json(&request)
        .send()
        .await {
            Ok(response) => {
                match response.json::<serde_json::Value>().await {
                    Ok(json_response) => {
                        if let Some(result) = json_response.get("result") {
                            // The endpoint is healthy if it returns "ok"
                            return Ok(result.as_str() == Some("ok"));
                        }
                        Ok(false)
                    },
                    Err(_) => Ok(false)
                }
            },
            Err(_) => Ok(false)
        }
}

/// Try operation with multiple RPC endpoints
pub async fn try_with_multiple_endpoints<F, T>(operation: F) -> Result<T> 
where
    F: Fn(&str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send>> + Send + Copy
{
    let mut last_error = None;
    
    for endpoint in RPC_ENDPOINTS.iter() {
        // Check if endpoint is healthy
        match check_endpoint_health(endpoint).await {
            Ok(true) => {
                match operation(endpoint).await {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        log::warn!("Operation failed with endpoint {}: {}", endpoint, e);
                        last_error = Some(e);
                    }
                }
            },
            _ => {
                log::warn!("Endpoint {} is not healthy, skipping", endpoint);
            }
        }
    }
    
    Err(last_error.unwrap_or_else(|| anyhow!("All RPC endpoints failed")))
}

/// Get recent blockhash with retry logic
pub async fn get_recent_blockhash(rpc_client: &RpcClient) -> Result<String> {
    // Check cache first
    {
        let cache = BLOCKHASH_CACHE.lock().await;
        if let Some(cached_hash) = cache.get() {
            log::debug!("Using cached blockhash");
            return Ok(cached_hash);
        }
    }
    
    // Build RPC request
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getRecentBlockhash",
        "params": []
    });
    
    // Try up to 5 times with exponential backoff
    let mut retry_delay = 500; // Start with 500ms
    let mut last_error = None;
    
    for attempt in 1..=5 {
        log::info!("Fetching recent blockhash, attempt {}/5", attempt);
        
        // Send request
        match HTTP_CLIENT.post(rpc_client.url())
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
                                
                                // Check if it's a rate limit error
                                if let Some(error_msg) = error.get("message").and_then(|m| m.as_str()) {
                                    if error_msg.contains("rate limit") || error_msg.contains("429") {
                                        log::warn!("Rate limit hit, backing off for longer");
                                        retry_delay *= 4; // More aggressive backoff for rate limits
                                    }
                                }
                            } else if let Some(blockhash) = json_response
                                .get("result")
                                .and_then(|r| r.get("value"))
                                .and_then(|v| v.get("blockhash"))
                                .and_then(|b| b.as_str()) {
                                
                                log::info!("Successfully fetched recent blockhash");
                                let blockhash = blockhash.to_string();
                                
                                // Update cache
                                let mut cache = BLOCKHASH_CACHE.lock().await;
                                cache.set(blockhash.clone());
                                
                                return Ok(blockhash);
                            } else {
                                last_error = Some(anyhow!("Invalid blockhash response format"));
                                log::warn!("Invalid blockhash response format on attempt {}", attempt);
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
                    log::warn!("Request error on attempt {}: {}", attempt, e);
                }
            }
        
        // If this wasn't the last attempt, wait before retrying
        if attempt < 5 {
            log::info!("Retrying in {} ms", retry_delay);
            tokio::time::sleep(Duration::from_millis(retry_delay)).await;
            retry_delay *= 2; // Exponential backoff
        }
    }
    
    // If we got here, all attempts failed
    Err(last_error.unwrap_or_else(|| anyhow!("Failed to fetch recent blockhash after 5 attempts")))
}

/// Get program data for the given program ID with retry logic
pub async fn get_program_data(rpc_client: &RpcClient, program_id: &Pubkey) -> Result<Vec<u8>> {
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
        match HTTP_CLIENT.post(rpc_client.url())
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
                                
                                // Check if it's a rate limit error
                                if let Some(error_msg) = error.get("message").and_then(|m| m.as_str()) {
                                    if error_msg.contains("rate limit") || error_msg.contains("429") {
                                        log::warn!("Rate limit hit, backing off for longer");
                                        retry_delay *= 4; // More aggressive backoff for rate limits
                                    }
                                }
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
            tokio::time::sleep(Duration::from_millis(retry_delay)).await;
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
    let signatures_response = HTTP_CLIENT.post(rpc_client.url())
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
        let batch_response = HTTP_CLIENT.post(rpc_client.url())
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
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    
    log::info!("Successfully fetched {} transactions", transactions.len());
    Ok(transactions)
}

/// Get account info for the given account ID
pub fn get_account_info(rpc_client: &RpcClient, account_id: &Pubkey) -> Result<solana_account::Account> {
    Ok(rpc_client.get_account(account_id)?)
} 