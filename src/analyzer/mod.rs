//! Analyzer module for Solana programs

pub mod bytecode;
// pub mod patterns;  // Comment out the original patterns module
pub mod patterns_simplified;  // Import the simplified module
pub use patterns_simplified as patterns;  // Re-export it as patterns
#[cfg(test)]
mod tests;
pub mod anchor;
pub mod known_programs;  // Add this line to create the module

use anyhow::Result;
use solana_sdk::pubkey::Pubkey;
use solana_client::rpc_client::RpcClient;
use log::{info, warn};

use crate::models::idl::IDL;
use crate::monitor::Monitor;

pub use self::bytecode::BytecodeAnalysis;
pub use self::patterns_simplified::PatternAnalysis;

/// Analyzer for Solana programs
pub struct Analyzer {
    // Configuration options could go here
}

impl Analyzer {
    /// Create a new analyzer
    pub fn new() -> Self {
        Self {}
    }
    
    /// Analyze program bytecode
    pub async fn analyze_bytecode(&self, program_id: &Pubkey, monitor: &Monitor) -> Result<bytecode::BytecodeAnalysis> {
        // Get program data
        let program_data = monitor.get_program_data(program_id).await?;
        
        // Analyze bytecode
        bytecode::analyze(&program_data, &program_id.to_string())
    }
    
    /// Analyze transaction patterns
    pub async fn analyze_patterns(&self, program_id: &Pubkey, monitor: &Monitor) -> Result<patterns_simplified::PatternAnalysis> {
        // Get recent transactions
        let transactions = monitor.get_recent_transactions(program_id).await?;
        
        // Analyze patterns
        patterns_simplified::analyze(program_id, &transactions)
    }
    
    /// Build IDL from analyses
    pub fn build_idl(&self, program_id: &Pubkey, bytecode_analysis: bytecode::BytecodeAnalysis, pattern_analysis: patterns_simplified::PatternAnalysis) -> Result<IDL> {
        // Create IDL
        let mut idl = IDL::new(format!("program_{}", program_id.to_string().chars().take(10).collect::<String>()), program_id.to_string());
        
        // Add instructions from bytecode analysis
        for instruction in bytecode_analysis.instructions {
            idl.add_instruction(instruction);
        }
        
        // Add accounts from bytecode analysis
        for account in bytecode_analysis.accounts {
            idl.add_account(account);
        }
        
        // Enhance IDL with pattern analysis
        idl.enhance_with_patterns(&pattern_analysis);
        
        // Set metadata
        idl.metadata.address = program_id.to_string();
        idl.metadata.origin = "native".to_string();
        
        Ok(idl)
    }
}

/// Analyze a Solana program and extract its IDL
pub fn analyze_program(program_id: &Pubkey, rpc_client: &RpcClient) -> Result<IDL> {
    info!("Analyzing program: {}", program_id);
    
    // Get program data
    let program_data = get_program_data(rpc_client, program_id)?;
    
    // Check for known program IDs first
    if program_id.to_string() == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" {
        info!("Detected Token program, using specialized analysis");
        return known_programs::analyze_token_program(program_id);
    }
    
    // Check if this is an Anchor program
    let is_anchor = anchor::is_anchor_program(&program_data);
    
    let mut idl = if is_anchor {
        info!("Detected Anchor program, using specialized analysis");
        match anchor::analyze(program_id, &program_data) {
            Ok(analysis) => {
                let mut idl = IDL::new(
                    format!("program_{}", program_id.to_string().chars().take(10).collect::<String>()), 
                    program_id.to_string()
                );
                
                // Add instructions
                for instruction in analysis.instructions {
                    idl.add_instruction(instruction);
                }
                
                // Add accounts
                for account in analysis.accounts {
                    idl.add_account(account);
                }
                
                // Add error codes
                for (code, name) in analysis.error_codes {
                    idl.add_error(code, name.clone(), name);
                }
                
                // Set metadata
                idl.metadata.address = program_id.to_string();
                idl.metadata.origin = "anchor".to_string();
                
                idl
            },
            Err(e) => {
                warn!("Anchor analysis failed: {}, falling back to bytecode analysis", e);
                // Fall back to bytecode analysis
                let bytecode_analysis = bytecode::analyze(&program_data, &program_id.to_string())?;
                
                let mut idl = IDL::new(
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
                
                // Set metadata
                idl.metadata.address = program_id.to_string();
                idl.metadata.origin = "native".to_string();
                
                idl
            }
        }
    } else {
        // Analyze bytecode
        let bytecode_analysis = bytecode::analyze(&program_data, &program_id.to_string())?;
        
        let mut idl = IDL::new(
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
        
        // Set metadata
        idl.metadata.address = program_id.to_string();
        idl.metadata.origin = "native".to_string();
        
        idl
    };
    
    // Enhance IDL with Anchor-specific information if applicable
    if is_anchor {
        if let Err(e) = anchor::enhance_idl(&mut idl, &program_data) {
            warn!("Failed to enhance IDL with Anchor information: {}", e);
        }
    }
    
    Ok(idl)
}

/// Get program data from the blockchain
fn get_program_data(rpc_client: &RpcClient, program_id: &Pubkey) -> Result<Vec<u8>> {
    info!("Fetching program data for: {}", program_id);
    
    // Get account data
    let account = rpc_client.get_account(program_id)?;
    
    Ok(account.data)
} 