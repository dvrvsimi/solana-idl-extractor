//! # Solana IDL Extractor
//! 
//! A library and CLI tool for extracting Interface Description Language (IDL)
//! from Solana programs through bytecode analysis and instruction parsing.
//!
//! ## Features
//!
//! * Extracts instructions, accounts, and error codes from Solana programs
//! * Works with both Anchor and native Solana programs
//! * Uses advanced bytecode analysis techniques to identify program structure
//!
//! ## Example
//!
//! ```
//! use solana_idl_extractor::analyzer;
//!
//! fn main() -> anyhow::Result<()> {
//!     let program_id = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
//!     let program_data = vec![/* program bytecode */];
//!     
//!     let idl = analyzer::analyze_program(&program_id.parse()?, &program_data)?;
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
pub mod errors;

use std::path::Path;
use anyhow::{Result, Context};
use log::{info, warn};
use solana_pubkey::Pubkey;

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
    .await
        .context("Failed to create monitor")?;
    
    // Create analyzer
    let analyzer = analyzer::Analyzer::new();
    
    // Analyze bytecode
    let bytecode_analysis = analyzer.analyze_bytecode(program_id, &monitor).await
        .context("Failed to analyze bytecode")?;
    
    // Analyze transaction patterns,  WIP
    let pattern_analysis = analyzer.analyze_patterns(program_id, &monitor).await
        .context("Failed to analyze transaction patterns")?;

    // Fetch the ELF bytes
    let elf_bytes = monitor.get_program_data(program_id).await
    .context("Failed to fetch program ELF bytes")?;
    
    // Build IDL
    let idl = analyzer.build_idl(program_id, &elf_bytes, bytecode_analysis.clone(), pattern_analysis)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to build IDL: {}", e))?;
    
    // Save to cache
    if use_cache {
        if let Err(e) = cache::Cache::save_idl(program_id, &idl) {
            warn!("Failed to cache IDL: {}", e);
        }
    }
    
    // Save to file if --output is specified
    if let Some(path) = output_path {
        generator::save_idl(&idl, path)
            .with_context(|| format!("Failed to save IDL to {}", path.display()))?;
        
        info!("Saved IDL to {}", path.display());
    }
    
    Ok(idl)
}



/// Analyze a Solana program and extract its IDL
pub fn analyze_program(program_id: &Pubkey, program_data: &[u8]) -> Result<models::idl::IDL> {
    info!("Analyzing program: {}", program_id);

    let program_name = analyzer::bytecode::extract_program_name(program_data)
        .unwrap_or_else(|_| format!("program_{}", program_id.to_string().chars().take(10).collect::<String>()));

    if analyzer::anchor::is_anchor_program(program_data) {
        info!("Detected Anchor program, using Anchor-specific analysis");
        let anchor_analysis = analyzer::anchor::analyze(program_id, program_data)
            .with_context(|| "Failed to analyze Anchor program")?;
        let mut idl = models::idl::IDL::new(program_name, program_id.to_string());
        for instruction in anchor_analysis.instructions {
            idl.add_instruction(instruction);
        }
        for account in anchor_analysis.accounts {
            idl.add_account(account);
        }
        for (code, name) in anchor_analysis.error_codes {
            idl.add_error(code, name.clone(), name);
        }
        idl.metadata.address = program_id.to_string();
        idl.metadata.origin = "anchor".to_string();
        analyzer::anchor::enhance_idl(&mut idl, program_data)?;
        Ok(idl)

    } else { // non anchor analysis
        let bytecode_analysis = analyzer::bytecode::analyze(program_data, &program_id.to_string())
            .with_context(|| "Failed to analyze program bytecode")?;
        let mut idl = models::idl::IDL::new(program_name, program_id.to_string());
        for instruction in bytecode_analysis.instructions {
            idl.add_instruction(instruction);
        }
        for account in bytecode_analysis.accounts {
            idl.add_account(account);
        }
        for (code, name) in bytecode_analysis.error_codes {
            idl.add_error(code, name.clone(), name);
        }
        idl.metadata.address = program_id.to_string();
        idl.metadata.origin = "native".to_string();
        Ok(idl)
    }
}


/// Extract IDL with simulation to enhance results, WIP too
pub async fn extract_idl_with_simulation(
    program_id: &Pubkey,
    rpc_url: &str,
    output_path: Option<&Path>,
    use_cache: bool,
) -> Result<IDL> {
    info!("Extracting IDL with simulation for program: {}", program_id);
    
    // Check cache first if enabled
    if use_cache {
        if let Ok(Some(cached_idl)) = cache::Cache::get_idl(program_id) {
            info!("Using cached IDL for program: {}", program_id);
            return Ok(cached_idl);
        }
    }
    
    // Create monitor for blockchain interaction
    let monitor = monitor::Monitor::new(rpc_url)
        .await
        .context("Failed to create monitor")?;
    
    // Create analyzer
    let analyzer = analyzer::Analyzer::new();
    
    // Analyze bytecode
    let bytecode_analysis = analyzer.analyze_bytecode(program_id, &monitor).await
        .context("Failed to analyze bytecode")?;
    
    // Analyze transaction patterns
    let pattern_analysis = analyzer.analyze_patterns(program_id, &monitor).await
        .context("Failed to analyze transaction patterns")?;

    
    // First create a temporary IDL with just the instructions
    let temp_idl = {
        let mut idl = models::idl::IDL::new(
            format!("program_{}", program_id.to_string().chars().take(10).collect::<String>()), 
            program_id.to_string()
        );
        for instruction in &bytecode_analysis.instructions {
            idl.add_instruction(instruction.clone());
        }
        idl
    };


    // Create transaction simulator
    let simulator = analyzer::simulation::TransactionSimulator::new(
        rpc_url,
        program_id,
        temp_idl
    )
    .context("Failed to create transaction simulator")?;
    
    // Simulate instructions to enhance IDL
    let mut simulation_results = Vec::new();
    for instruction in &bytecode_analysis.instructions {
        match simulator.simulate_instruction(instruction).await {
            Ok(result) => simulation_results.push(result),
            Err(e) => warn!("Failed to simulate instruction {}: {}", instruction.name, e),
        }
    }

    
    // Build IDL with all analysis results
    let idl = analyzer.build_idl_with_simulation(
        program_id, 
        bytecode_analysis, 
        pattern_analysis,
        simulation_results
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to build IDL: {}", e))?;
    
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