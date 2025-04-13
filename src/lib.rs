//! A library for extracting Interface Description Language (IDL) from Solana programs
//! 
//! This crate provides tools to analyze Solana program bytecode and transaction patterns
//! to generate IDL files that can be used for client-side interaction with the programs.

pub mod analyzer;
pub mod monitor;
pub mod models;
pub mod generator;

use std::path::Path;
use anyhow::Result;
use solana_sdk::pubkey::Pubkey;

/// Main entry point for extracting IDL from a program
pub async fn extract_idl(
    program_id: &Pubkey,
    rpc_url: &str,
    output_path: Option<&Path>,
) -> Result<models::idl::IDL> {
    // Initialize the analyzer
    let analyzer = analyzer::Analyzer::new();
    
    // Initialize the monitor
    let monitor = monitor::Monitor::new(rpc_url).await?;
    
    // Analyze program bytecode
    let bytecode_analysis = analyzer.analyze_bytecode(program_id, &monitor).await?;
    
    // Monitor transactions to extract patterns
    let transaction_analysis = monitor.analyze_transactions(program_id).await?;
    
    // Combine analyses to build the IDL model
    let idl = analyzer.build_idl(program_id, bytecode_analysis, transaction_analysis)?;
    
    // Generate and save the IDL if output path is provided
    if let Some(path) = output_path {
        generator::save_idl(&idl, path)?;
    }
    
    Ok(idl)
}

/// Version of the IDL extractor
pub const VERSION: &str = env!("CARGO_PKG_VERSION"); 