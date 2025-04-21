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
//!     let idl = extract_idl(&program_id, rpc_url, None, true).await?;
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
pub mod cache;  // New module for caching

use std::path::Path;
use anyhow::{Result, anyhow, Context};
use solana_sdk::pubkey::Pubkey;
use solana_client::rpc_client::RpcClient;
use log::{info, debug, warn, error};
use std::time::Instant;

use crate::cache::Cache;

/// Main entry point for extracting IDL from a program
pub async fn extract_idl(
    program_id: &Pubkey,
    rpc_url: &str,
    output_path: Option<&Path>,
    use_cache: bool,
) -> Result<models::idl::IDL> {
    let start = Instant::now();
    info!("Starting IDL extraction for program: {}", program_id);
    
    // Check cache first if enabled
    if use_cache {
        if let Some(cached_idl) = Cache::get_idl(program_id)? {
            info!("Using cached IDL for program: {}", program_id);
            return Ok(cached_idl);
        }
    }
    
    // Create RPC client
    let rpc_client = RpcClient::new(rpc_url.to_string());
    
    // Try to get program data
    let program_data = match get_program_data(&rpc_client, program_id) {
        Ok(data) => {
            info!("Successfully fetched program data ({} bytes)", data.len());
            data
        },
        Err(err) => {
            warn!("Error fetching program data: {}", err);
            info!("Creating minimal IDL");
            
            let idl = create_minimal_idl(program_id, "Failed to fetch program data");
            
            // Save IDL if output path provided
            if let Some(path) = output_path {
                if let Err(e) = generator::save_idl(&idl, path) {
                    warn!("Failed to save minimal IDL: {}", e);
                }
            }
            
            return Ok(idl);
        }
    };
    
    // Analyze program
    let idl = match analyze_program(program_id, &program_data) {
        Ok(idl) => idl,
        Err(err) => {
            warn!("Error analyzing program: {}", err);
            info!("Creating minimal IDL");
            
            create_minimal_idl(program_id, &format!("Failed to analyze program: {}", err))
        }
    };
    
    // Save IDL if output path provided
    if let Some(path) = output_path {
        generator::save_idl(&idl, path)
            .with_context(|| format!("Failed to save IDL to {}", path.display()))?;
        info!("Saved IDL to {}", path.display());
    }
    
    // Cache the result if caching is enabled
    if use_cache {
        if let Err(e) = Cache::save_idl(program_id, &idl) {
            warn!("Failed to cache IDL: {}", e);
        } else {
            debug!("Cached IDL for program: {}", program_id);
        }
    }
    
    let elapsed = start.elapsed();
    info!("IDL extraction completed in {:.2?}", elapsed);
    
    Ok(idl)
}

/// Create a minimal IDL when analysis fails
fn create_minimal_idl(program_id: &Pubkey, reason: &str) -> models::idl::IDL {
    let mut idl = models::idl::IDL::new(
        format!("program_{}", program_id.to_string().chars().take(10).collect::<String>()), 
        program_id.to_string()
    );
    
    // Add a generic instruction
    let mut instruction = models::instruction::Instruction::new("process".to_string(), 0);
    instruction.add_arg("data".to_string(), "bytes".to_string());
    idl.add_instruction(instruction);
    
    // Add a generic account
    let mut account = models::account::Account::new("State".to_string(), "state".to_string());
    account.add_field("data".to_string(), "bytes".to_string(), 0);
    idl.add_account(account);
    
    // Add metadata
    idl.metadata.address = program_id.to_string();
    idl.metadata.origin = "unknown".to_string();
    idl.metadata.notes = Some(format!("Minimal IDL created because: {}", reason));
    
    idl
}

/// Analyze a Solana program and extract its IDL
fn analyze_program(program_id: &Pubkey, program_data: &[u8]) -> Result<models::idl::IDL> {
    info!("Analyzing program: {}", program_id);
    
    // Check for known program IDs first
    if program_id.to_string() == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" {
        info!("Detected Token program, using specialized analysis");
        return analyzer::known_programs::analyze_token_program(program_id);
    }
    
    // Analyze bytecode
    let bytecode_analysis = analyzer::bytecode::analyze(program_data, &program_id.to_string())
        .with_context(|| "Failed to analyze program bytecode")?;
    
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
    match rpc_client.get_account(program_id) {
        Ok(account) => {
            info!("Successfully fetched account data, size: {} bytes", account.data.len());
            
            // Check if this is a program account
            if !account.executable {
                return Err(anyhow!("Account is not executable (not a program)"));
            }
            
            // Print the first few bytes for debugging
            let prefix = if account.data.len() >= 32 {
                &account.data[0..32]
            } else {
                &account.data
            };
            
            let prefix_hex = prefix.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            
            debug!("First 32 bytes: {}", prefix_hex);
            
            Ok(account.data)
        },
        Err(err) => {
            error!("Error fetching account: {}", err);
            Err(anyhow!("Failed to fetch program data: {}", err))
        }
    }
}

/// Version of the IDL extractor
pub const VERSION: &str = env!("CARGO_PKG_VERSION"); 