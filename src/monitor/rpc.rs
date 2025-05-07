//! RPC client interactions for Solana programs

use anyhow::{Result, anyhow};
use solana_client::rpc_client::RpcClient;
use solana_pubkey::Pubkey;
use solana_transaction_status::{EncodedTransaction, UiTransaction};
use reqwest;
use base64;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use once_cell::sync::Lazy;

// Define a set of RPC endpoints to try
pub fn get_rpc_endpoints() -> Vec<String> {
    let mut endpoints = vec![
        "https://api.devnet.solana.com".to_string(),
        "https://devnet.genesysgo.net".to_string(), 
        "https://devnet.helius.xyz".to_string(),
    ];
    
    // Add Helius endpoint with API key from env
    if let Ok(api_key) = std::env::var("HELIUS_API_KEY") {
        endpoints.push(format!("https://devnet.helius-rpc.com/?api-key={}", api_key));
    }
    
    endpoints
}

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
    
    for endpoint in get_rpc_endpoints().iter() {
        // Check if endpoint is healthy
        match check_endpoint_health(endpoint).await {
            Ok(true) => {
                log::info!("Endpoint {} is healthy, trying operation", endpoint);
                match operation(endpoint).await {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        log::warn!("Operation failed with endpoint {}: {}", endpoint, e);
                        last_error = Some(e);
                    }
                }
            },
            Ok(false) => {
                log::warn!("Endpoint {} is not healthy, skipping", endpoint);
            },
            Err(e) => {
                log::warn!("Failed to check health of endpoint {}: {}", endpoint, e);
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
    
    // Use the RPC client's URL - store it as a reference to avoid moving it
    let rpc_url = rpc_client.url();
    
    for attempt in 1..=5 {
        log::info!("Fetching recent blockhash, attempt {}/5", attempt);
        
        // Send request using the RPC client's URL - use a reference to avoid moving it
        match HTTP_CLIENT.post(&rpc_url)
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
    log::info!("RPC: Fetching program data for: {}", program_id);
    
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
    
    // Store the URL as a reference to avoid moving it
    let rpc_url = rpc_client.url();
    log::info!("RPC: Sending getAccountInfo request to {}", rpc_url);
    
    // Try up to 3 times with exponential backoff
    let mut retry_delay = 1000; // Start with 1 second
    let mut last_error = None;
    
    for attempt in 1..=3 {
        log::info!("RPC: Fetching program data, attempt {}/3", attempt);
        
        // Send request - use a reference to avoid moving the URL
        match HTTP_CLIENT.post(&rpc_url)
            .json(&request)
            .send()
            .await {
                Ok(response) => {
                    log::info!("RPC: Received response from {}", rpc_url);
                    
                    match response.json::<serde_json::Value>().await {
                        Ok(json_response) => {
                            // Check for RPC error
                            if let Some(error) = json_response.get("error") {
                                last_error = Some(anyhow!("RPC error: {}", error));
                                log::warn!("RPC: Error on attempt {}: {}", attempt, error);
                                
                                // Check if it's a rate limit error
                                if let Some(error_msg) = error.get("message").and_then(|m| m.as_str()) {
                                    if error_msg.contains("rate limit") || error_msg.contains("429") {
                                        log::warn!("RPC: Rate limit hit, backing off for longer");
                                        retry_delay *= 4; // More aggressive backoff for rate limits
                                    }
                                }
                            } else if let Some(result) = json_response.get("result").and_then(|r| r.get("value")) {
                                // Parse account data
                                if let Some(data_str) = result.get("data")
                                    .and_then(|d| d.get(0))
                                    .and_then(|d| d.as_str()) {
                                    
                                    log::info!("RPC: Successfully received account data");
                                    
                                    match base64::decode(data_str) {
                                        Ok(data) => {
                                            // Get the owner of this account
                                            let owner = result.get("owner")
                                                .and_then(|o| o.as_str())
                                                .unwrap_or("");
                                                
                                            log::info!("RPC: Account owner: {}", owner);
                                            
                                            // Log data size and first few bytes for debugging
                                            log::info!("RPC: Account data size: {} bytes", data.len());
                                            if data.len() > 0 {
                                                let preview_size = std::cmp::min(data.len(), 16);
                                                let hex_preview = data[..preview_size]
                                                    .iter()
                                                    .map(|b| format!("{:02x}", b))
                                                    .collect::<Vec<_>>()
                                                    .join(" ");
                                                log::info!("RPC: First {} bytes: {}", preview_size, hex_preview);
                                            }
                                            
                                            // Check if this is a BPF Upgradeable Loader account
                                            if owner == "BPFLoaderUpgradeab1e11111111111111111111111" {
                                                log::info!("RPC: This is a BPF Upgradeable Loader account");
                                                
                                                // Check if this is the program account (36 bytes)
                                                if data.len() == 36 {
                                                    log::info!("RPC: This is a program account (36 bytes), extracting program data account address");
                                                    
                                                    // Parse the program data account address from the data
                                                    let mut program_data_bytes = [0u8; 32];
                                                    program_data_bytes.copy_from_slice(&data[4..36]);
                                                    let program_data_address = Pubkey::new_from_array(program_data_bytes);
                                                    
                                                    log::info!("RPC: Program data account: {}", program_data_address);
                                                    
                                                    // Recursively fetch the program data account
                                                    match Box::pin(get_program_data(rpc_client, &program_data_address)).await {
                                                        Ok(program_data) => {
                                                            log::info!("RPC: Successfully fetched program data from program data account ({} bytes)", program_data.len());
                                                            if program_data.len() > 0 {
                                                                let preview_size = std::cmp::min(program_data.len(), 16);
                                                                let hex_preview = program_data[..preview_size]
                                                                    .iter()
                                                                    .map(|b| format!("{:02x}", b))
                                                                    .collect::<Vec<_>>()
                                                                    .join(" ");
                                                                log::info!("RPC: First {} bytes of program data: {}", preview_size, hex_preview);
                                                            }
                                                            return Ok(program_data);
                                                        },
                                                        Err(e) => {
                                                            log::error!("RPC: Failed to fetch program data from program data account: {}", e);
                                                            return Err(e);
                                                        }
                                                    }
                                                } 
                                                // Check if this is the program data account (contains the actual program)
                                                else {
                                                    log::info!("RPC: This is a program data account ({} bytes)", data.len());
                                                    
                                                    // The program data account has a header before the actual program binary
                                                    // The header is 8 bytes: 1 byte slot + 7 bytes upgrade authority info
                                                    if data.len() > 8 {
                                                        log::info!("RPC: Extracting program binary from program data account (skipping 8-byte header)");
                                                        let program_data = data[8..].to_vec();
                                                        
                                                        // Log the first few bytes of the actual program binary
                                                        if program_data.len() > 0 {
                                                            let preview_size = std::cmp::min(program_data.len(), 16);
                                                            let hex_preview = program_data[..preview_size]
                                                                .iter()
                                                                .map(|b| format!("{:02x}", b))
                                                                .collect::<Vec<_>>()
                                                                .join(" ");
                                                            log::info!("RPC: First {} bytes of program binary: {}", preview_size, hex_preview);
                                                        }
                                                        
                                                        return Ok(program_data);
                                                    } else {
                                                        log::error!("RPC: Program data account too small: {} bytes", data.len());
                                                        return Err(anyhow!("Program data account too small"));
                                                    }
                                                }
                                            } 
                                            // Check if this is a regular executable program
                                            else {
                                                let executable = result.get("executable")
                                                    .and_then(|e| e.as_bool())
                                                    .unwrap_or(false);
                                                    
                                                log::info!("RPC: Account executable status: {}", executable);
                                                
                                                if executable {
                                                    log::info!("RPC: This is a regular executable program");
                                                    return Ok(data);
                                                } else {
                                                    log::warn!("RPC: Account is not executable and not owned by BPF Upgradeable Loader");
                                                    return Err(anyhow!("Account is not executable and not owned by BPF Upgradeable Loader"));
                                                }
                                            }
                                        },
                                        Err(e) => {
                                            last_error = Some(anyhow!("Failed to decode base64 data: {}", e));
                                            log::warn!("RPC: Failed to decode base64 data on attempt {}: {}", attempt, e);
                                        }
                                    }
                                } else {
                                    last_error = Some(anyhow!("Invalid account data format"));
                                    log::warn!("RPC: Invalid account data format on attempt {}", attempt);
                                }
                            } else {
                                last_error = Some(anyhow!("Account not found or empty result"));
                                log::warn!("RPC: Account not found or empty result on attempt {}", attempt);
                            }
                        },
                        Err(e) => {
                            last_error = Some(anyhow!("Failed to parse JSON response: {}", e));
                            log::warn!("RPC: Failed to parse JSON response on attempt {}: {}", attempt, e);
                        }
                    }
                },
                Err(e) => {
                    last_error = Some(anyhow!("Request error: {}", e));
                    log::warn!("RPC: Request error on attempt {}: {}", e, attempt);
                }
            }
        
        // If this wasn't the last attempt, wait before retrying
        if attempt < 3 {
            log::info!("RPC: Retrying in {} ms", retry_delay);
            tokio::time::sleep(Duration::from_millis(retry_delay)).await;
            retry_delay *= 2; // Exponential backoff
        }
    }
    
    // If we got here, all attempts failed
    log::error!("RPC: All attempts to fetch program data failed");
    Err(last_error.unwrap_or_else(|| anyhow!("Failed to fetch program data after 3 attempts")))
}

/// Get recent transactions for the given program ID
pub async fn get_recent_transactions(rpc_client: &RpcClient, program_id: &Pubkey, limit: Option<usize>) -> Result<Vec<EncodedTransaction>> {
    let limit = limit.unwrap_or(100);
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
    
    // Store the URL as a reference to avoid moving it
    let rpc_url = rpc_client.url();
    
    // Send request to get signatures
    let signatures_response = HTTP_CLIENT.post(&rpc_url)
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
                log::warn!("Invalid signature response format: {:?}", result);
                return Err(anyhow!("Invalid signature response format"));
            }
        },
        None => return Err(anyhow!("No signatures found in response")),
    };
    
    log::info!("Found {} transaction signatures", signatures.len());
    
    if signatures.is_empty() {
        return Ok(Vec::new());
    }
    
    // Now fetch the actual transactions one by one (no batching)
    let mut transactions = Vec::new();
    
    // Limit the number of transactions to process to avoid long processing times
    let signatures_to_process = signatures.iter().take(10).collect::<Vec<_>>();
    log::info!("Processing {} transactions (limited for performance)", signatures_to_process.len());
    
    for signature in signatures_to_process {
        // Build RPC request for getTransaction
        let tx_request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                {
                    "encoding": "json",
                    "maxSupportedTransactionVersion": 0
                }
            ]
        });
        
        // Send request - use a reference to avoid moving the URL
        let response = HTTP_CLIENT.post(&rpc_url)
            .json(&tx_request)
            .send()
            .await?;
        
        let response_text = response.text().await?;
        let tx_response: serde_json::Value = serde_json::from_str(&response_text)?;
        
        if let Some(error) = tx_response.get("error") {
            log::warn!("Error fetching transaction {}: {}", signature, error);
            continue;
        }
        
        if let Some(result) = tx_response.get("result") {
            if let Some(transaction) = result.get("transaction") {
                // Convert to EncodedTransaction
                let transaction_str = serde_json::to_string(&transaction).unwrap_or_default();
                let ui_transaction = match serde_json::from_str::<UiTransaction>(&transaction_str) {
                    Ok(tx) => tx,
                    Err(e) => {
                        log::warn!("Failed to parse UiTransaction: {}", e);
                        continue; // Skip this transaction
                    }
                };
                let encoded_tx = EncodedTransaction::Json(ui_transaction);
                transactions.push(encoded_tx);
                log::info!("Successfully fetched transaction {}", signature);
            }
        }
        
        // Add a delay to avoid rate limiting
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    
    log::info!("Successfully fetched {} transactions", transactions.len());
    Ok(transactions)
}

/// Get account info for the given account ID
pub fn get_account_info(rpc_client: &RpcClient, account_id: &Pubkey) -> Result<solana_account::Account> {
    log::info!("Fetching account info for: {}", account_id);
    match rpc_client.get_account(account_id) {
        Ok(account) => {
            log::info!("Successfully fetched account info, data size: {} bytes", account.data.len());
            Ok(account)
        },
        Err(e) => {
            log::error!("Failed to fetch account info: {}", e);
            Err(anyhow!("Failed to fetch account info: {}", e))
        }
    }
} 