//! RPC client interactions for Solana programs

use anyhow::{Result, anyhow};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_transaction_status::{EncodedTransaction, UiTransactionEncoding};
use solana_sdk::signature::Signature;

/// Get program data for the given program ID
pub fn get_program_data(rpc_client: &RpcClient, program_id: &Pubkey) -> Result<Vec<u8>> {
    let account = rpc_client.get_account(program_id)?;
    Ok(account.data)
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