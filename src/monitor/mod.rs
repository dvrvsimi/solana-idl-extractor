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
    
    /// Get program data for the given program ID
    pub async fn get_program_data(&self, program_id: &Pubkey) -> Result<Vec<u8>> {
        rpc::get_program_data(&self.rpc_client, program_id)
    }
    
    /// Get recent transactions for the given program ID
    pub async fn get_recent_transactions(&self, program_id: &Pubkey) -> Result<Vec<EncodedTransaction>> {
        rpc::get_recent_transactions(&self.rpc_client, program_id, None)
    }
    
    /// Analyze transactions for the given program ID
    pub async fn analyze_transactions(&self, program_id: &Pubkey) -> Result<TransactionAnalysis> {
        let transactions = self.get_recent_transactions(program_id).await?;
        transaction::analyze(program_id, &transactions)
    }
} 