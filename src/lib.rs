//! A library for extracting Interface Description Language (IDL) from Solana programs
//! 
//! This crate provides tools to analyze Solana program bytecode and transaction patterns
//! to generate IDL files that can be used for client-side interaction with the programs.
//!
//! # Features
//!
//! - Bytecode analysis to extract instruction and account information
//! - Transaction pattern analysis to enhance IDL with real-world usage patterns
//! - Support for both Anchor and non-Anchor programs
//! - IDL generation in multiple formats
//!
//! # Example
//!
//! ```no_run
//! use solana_idl_extractor::extract_idl;
//! use solana_sdk::pubkey::Pubkey;
//! use std::str::FromStr;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Program ID to extract IDL for
//!     let program_id = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?;
//!     
//!     // RPC URL to use
//!     let rpc_url = "https://api.mainnet-beta.solana.com";
//!     
//!     // Extract IDL
//!     let idl = extract_idl(&program_id, rpc_url, None).await?;
//!     
//!     // Print IDL
//!     println!("{}", serde_json::to_string_pretty(&idl)?);
//!     
//!     Ok(())
//! }
//! ```

pub mod analyzer;
pub mod monitor;
pub mod models;
pub mod generator;

use std::path::Path;
use anyhow::Result;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::rpc_client::RpcClient;
use solana_sdk::info;

/// Main entry point for extracting IDL from a program
pub async fn extract_idl(
    program_id: &Pubkey,
    rpc_url: &str,
    output_path: Option<&Path>,
) -> Result<models::idl::IDL> {
    // Create RPC client
    let rpc_client = RpcClient::new(rpc_url.to_string());
    
    // Try to get program data
    let program_data = match get_program_data(&rpc_client, program_id) {
        Ok(data) => data,
        Err(err) => {
            info!("Error fetching program data: {}", err);
            info!("Creating minimal IDL");
            
            // Create a minimal IDL
            let mut idl = models::idl::IDL::new(
                format!("program_{}", program_id.to_string().chars().take(10).collect::<String>()), 
                program_id.to_string()
            );
            
            // Add metadata
            idl.metadata.address = program_id.to_string();
            idl.metadata.origin = "unknown".to_string();
            
            // Save IDL if output path provided
            if let Some(path) = output_path {
                generator::save_idl(&idl, path)?;
            }
            
            return Ok(idl);
        }
    };
    
    // Analyze program
    let idl = analyze_program(program_id, &rpc_client)?;
    
    // Save IDL if output path provided
    if let Some(path) = output_path {
        generator::save_idl(&idl, path)?;
    }
    
    Ok(idl)
}

/// Analyze a Solana program and extract its IDL
fn analyze_program(program_id: &Pubkey, rpc_client: &RpcClient) -> Result<models::idl::IDL> {
    info!("Analyzing program: {}", program_id);
    
    // Get program data
    let program_data = get_program_data(rpc_client, program_id)?;
    
    // Analyze bytecode
    let bytecode_analysis = analyzer::bytecode::analyze(&program_data, &program_id.to_string())?;
    
    // Create IDL
    let mut idl = models::idl::IDL::new(
        format!("program_{}", program_id.to_string().chars().take(10).collect::<String>()), 
        program_id.to_string()
    );
    
    // Add instructions
    for instruction in bytecode_analysis.instructions {
        idl.add_instruction(instruction);
    }
    
    // Add accounts
    for account in bytecode_analysis.accounts {
        idl.add_account(account);
    }
    
    // Add metadata
    idl.metadata.address = program_id.to_string();
    idl.metadata.origin = "native".to_string();
    
    Ok(idl)
}

/// Get program data from the blockchain
fn get_program_data(rpc_client: &RpcClient, program_id: &Pubkey) -> Result<Vec<u8>> {
    info!("Fetching program data for: {}", program_id);
    
    // Get account data
    let account = rpc_client.get_account(program_id)?;
    
    Ok(account.data)
}

/// Version of the IDL extractor
pub const VERSION: &str = env!("CARGO_PKG_VERSION"); 