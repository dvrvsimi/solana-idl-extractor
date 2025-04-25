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
pub mod cache;
pub mod constants;
pub mod utils;

use std::path::Path;
use anyhow::{Result, Context};
use log::{info, debug, warn};
use solana_pubkey::Pubkey;
use solana_client::rpc_client::RpcClient;

// Re-export key types
pub use models::idl::IDL;
pub use analyzer::simulation::TransactionSimulator;

/// Version of the tool
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Extract IDL from a Solana program
pub async fn extract_idl(
    program_id: &Pubkey,
    rpc_url: &str,
    output_path: Option<&Path>,
    use_cache: bool,
) -> Result<IDL> {
    info!("Extracting IDL for program: {}", program_id);
    
    // Check cache first if enabled
    if use_cache {
        if let Ok(Some(cached_idl)) = cache::Cache::get_idl(program_id) {
            info!("Using cached IDL for program: {}", program_id);
            return Ok(cached_idl);
        }
    }
    
    // Create monitor for blockchain interaction
    let monitor = monitor::Monitor::new(rpc_url)
        .context("Failed to create monitor")?;
    
    // Create analyzer
    let analyzer = analyzer::Analyzer::new();
    
    // Analyze bytecode
    let bytecode_analysis = analyzer.analyze_bytecode(program_id, &monitor).await
        .context("Failed to analyze bytecode")?;
    
    // Analyze transaction patterns
    let pattern_analysis = analyzer.analyze_patterns(program_id, &monitor).await
        .context("Failed to analyze transaction patterns")?;
    
    // Build IDL
    let idl = analyzer.build_idl(program_id, bytecode_analysis, pattern_analysis)
        .context("Failed to build IDL")?;
    
    // Save to cache
    if use_cache {
        if let Err(e) = cache::Cache::save_idl(program_id, &idl) {
            warn!("Failed to cache IDL: {}", e);
        }
    }
    
    // Save to file if path provided
    if let Some(path) = output_path {
        generator::save_idl(&idl, path)
            .with_context(|| format!("Failed to save IDL to {}", path.display()))?;
        
        info!("Saved IDL to {}", path.display());
    }
    
    Ok(idl)
}

/// Extract IDL from a Solana program with transaction simulation
pub async fn extract_idl_with_simulation(
    program_id: &Pubkey,
    rpc_url: &str,
    output_path: Option<&Path>,
    use_cache: bool,
) -> Result<IDL> {
    // First, extract the basic IDL
    let mut idl = extract_idl(program_id, rpc_url, None, use_cache).await?;
    
    // Then enhance it with transaction simulation
    info!("Enhancing IDL with transaction simulation...");
    
    // Create a transaction simulator
    let simulator = TransactionSimulator::new(rpc_url, program_id, idl.clone())?;
    
    // Simulate all instructions
    let simulation_results = simulator.simulate_all().await?;
    
    // Enhance the IDL based on simulation results
    idl = simulator.enhance_idl(&simulation_results)?;
    
    // Save the enhanced IDL if an output path was provided
    if let Some(path) = output_path {
        let enhanced_path = path.with_file_name(format!(
            "{}_enhanced{}",
            path.file_stem().unwrap().to_string_lossy(),
            path.extension().map_or_else(|| "".to_string(), |ext| format!(".{}", ext.to_string_lossy()))
        ));
        
        generator::save_idl(&idl, &enhanced_path)
            .with_context(|| format!("Failed to save enhanced IDL to {}", enhanced_path.display()))?;
        
        info!("Enhanced IDL saved to {}", enhanced_path.display());
    }
    
    Ok(idl)
}

/// Analyze a Solana program and extract its IDL
fn analyze_program(program_id: &Pubkey, program_data: &[u8]) -> Result<models::idl::IDL> {
    info!("Analyzing program: {}", program_id);
    
    // First, check if this is an Anchor program
    if analyzer::anchor::is_anchor_program(program_data) {
        info!("Detected Anchor program, using Anchor-specific analysis");
        return analyze_anchor_program(program_id, program_data);
    }
    
    // If not Anchor, use the general bytecode analyzer
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
    
    // Add error codes
    for (code, name) in bytecode_analysis.error_codes {
        idl.add_error(code, name.clone(), name);
    }
    
    // Add metadata
    idl.metadata.address = program_id.to_string();
    idl.metadata.origin = "native".to_string();
    
    Ok(idl)
}

/// Analyze an Anchor program and extract its IDL
fn analyze_anchor_program(program_id: &Pubkey, program_data: &[u8]) -> Result<models::idl::IDL> {
    info!("Analyzing Anchor program: {}", program_id);
    
    // Use Anchor-specific analysis
    let anchor_analysis = analyzer::anchor::analyze(program_id, program_data)
        .with_context(|| "Failed to analyze Anchor program")?;
    
    // Create IDL
    let mut idl = models::idl::IDL::new(
        format!("anchor_program_{}", program_id.to_string().chars().take(10).collect::<String>()), 
        program_id.to_string()
    );
    
    // Add instructions
    for instruction in anchor_analysis.instructions {
        idl.add_instruction(instruction);
    }
    
    // Add accounts
    for account in anchor_analysis.accounts {
        idl.add_account(account);
    }
    
    // Add error codes
    for (code, name) in anchor_analysis.error_codes {
        idl.add_error(code, name.clone(), name);
    }
    
    // Add metadata
    idl.metadata.address = program_id.to_string();
    idl.metadata.origin = "anchor".to_string();
    
    // Enhance IDL with additional Anchor-specific information
    analyzer::anchor::enhance_idl(&mut idl, program_data)?;
    
    Ok(idl)
} 