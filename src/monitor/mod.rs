//! Transaction monitoring for Solana programs

mod rpc;
pub mod transaction;

use anyhow::Result;
use solana_client::rpc_client::RpcClient;
use solana_pubkey::Pubkey;
use solana_transaction_status::EncodedTransaction;

pub use self::transaction::TransactionAnalysis;

/// Monitor for observing program transactions
pub struct Monitor {
    rpc_client: RpcClient,
}

impl Monitor {
    /// Create a new monitor with the given RPC URL
    pub async fn new(rpc_url: &str) -> Result<Self> {
        let rpc_client = RpcClient::new(rpc_url.to_string());
        
        Ok(Self {
            rpc_client,
        })
    }
    
    /// Get program data for a Solana program
    pub async fn get_program_data(&self, program_id: &Pubkey) -> anyhow::Result<Vec<u8>> {
        let program_data = rpc::get_program_data(&self.rpc_client, program_id).await?;
        
        // Validate program data
        if program_data.len() < 100 {
            log::warn!("Program data is suspiciously small ({} bytes). This is not the actual program binary.", 
                  program_data.len());
            
            // If it's a BPF upgradeable loader account, try to extract the program data account address
            if program_data.len() >= 36 {
                log::info!("Checking if this is a BPF upgradeable loader account...");
                
                // The first 4 bytes are a version number, next 32 bytes are the program data account address
                let mut program_data_bytes = [0u8; 32];
                program_data_bytes.copy_from_slice(&program_data[4..36]);
                let program_data_address = Pubkey::new_from_array(program_data_bytes);
                
                log::info!("Detected possible program data account: {}", program_data_address);
                log::info!("Attempting to fetch the actual program binary from this account...");
                
                // Try to fetch the actual program data
                match rpc::get_program_data(&self.rpc_client, &program_data_address).await {
                    Ok(actual_program_data) => {
                        log::info!("Successfully fetched program binary from program data account ({} bytes)", 
                              actual_program_data.len());
                        return Ok(actual_program_data);
                    },
                    Err(e) => {
                        log::warn!("Failed to fetch program binary from program data account: {}", e);
                        // Continue with the original data
                    }
                }
            }
        }
        
        Ok(program_data)
    }
    
    /// Get recent transactions for the given program ID
    pub async fn get_recent_transactions(&self, program_id: &Pubkey) -> Result<Vec<EncodedTransaction>> {
        rpc::get_recent_transactions(&self.rpc_client, program_id, None).await
    }
    
    /// Analyze transactions for the given program ID
    pub async fn analyze_transactions(&self, program_id: &Pubkey) -> Result<TransactionAnalysis> {
        let transactions = self.get_recent_transactions(program_id).await?;
        transaction::analyze(program_id, &transactions)
    }
} 