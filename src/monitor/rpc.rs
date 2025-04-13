//! RPC client interactions for Solana programs

use anyhow::{Result, anyhow};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::{EncodedTransaction, UiTransactionEncoding};

/// Get program data for the given program ID
pub fn get_program_data(rpc_client: &RpcClient, program_id: &Pubkey) -> Result<Vec<u8>> {
    let account = rpc_client.get_account(program_id)?;
    Ok(account.data)
}

/// Get recent transactions for the given program ID
pub fn get_recent_transactions(rpc_client: &RpcClient, program_id: &Pubkey) -> Result<Vec<EncodedTransaction>> {
    // Get signatures for the program
    let signatures = rpc_client.get_signatures_for_address(program_id)?;
    
    if signatures.is_empty() {
        return Ok(Vec::new());
    }
    
    // Limit to the most recent 100 transactions
    let signatures: Vec<_> = signatures.iter()
        .take(100)
        .map(|sig_info| sig_info.signature.clone())
        .collect();
    
    // Get transaction details
    let mut transactions = Vec::new();
    
    for signature in signatures {
        if let Ok(tx) = rpc_client.get_transaction(&signature, UiTransactionEncoding::Base64) {
            if let Some(tx) = tx.transaction {
                transactions.push(tx);
            }
        }
    }
    
    Ok(transactions)
}

/// Get account info for the given account ID
pub fn get_account_info(rpc_client: &RpcClient, account_id: &Pubkey) -> Result<solana_sdk::account::Account> {
    Ok(rpc_client.get_account(account_id)?)
} 