//! Analyzer module for Solana programs

pub mod bytecode;
pub mod anchor;
pub mod patterns;
pub mod simulation;

#[cfg(test)]

use anyhow::Result;
use solana_pubkey::Pubkey;
use log::{info, warn};
use solana_client::rpc_client::RpcClient;

use crate::models::idl::IDL;
use crate::monitor::Monitor;
use crate::errors::ExtractorResult;
use crate::errors::{ExtractorError, ErrorContext};


// Re-export common types
pub use self::bytecode::BytecodeAnalysis;
pub use self::patterns::PatternAnalysis;
pub use self::simulation::TransactionSimulator;

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
    pub async fn analyze_bytecode(&self, program_id: &Pubkey, monitor: &Monitor) -> ExtractorResult<bytecode::BytecodeAnalysis> {
        log::info!("Analyzer: Starting bytecode analysis for {}", program_id);
        
        // Get program data
        log::info!("Analyzer: Requesting program data from monitor");
        let program_data = monitor.get_program_data(program_id).await
            .map_err(|e| ExtractorError::from_anyhow(anyhow::anyhow!("{}", e), ErrorContext {
                program_id: Some(program_id.to_string()),
                component: "analyzer".to_string(),
                operation: "analyze_bytecode".to_string(),
                details: Some("get_program_data".to_string()),
            }))?;
        
        log::info!("Analyzer: Received program data, size: {} bytes", program_data.len());
        
        // Check if this looks like valid ELF data
        if program_data.len() >= 4 && program_data[0] == 0x7F && program_data[1] == b'E' && program_data[2] == b'L' && program_data[3] == b'F' {
            log::info!("Analyzer: Program data appears to be a valid ELF file");
        } else {
            log::warn!("Analyzer: Program data does not appear to be a valid ELF file");
            // Log the first few bytes for debugging
            if !program_data.is_empty() {
                let preview_size = std::cmp::min(16, program_data.len());
                log::debug!("Analyzer: First {} bytes: {:?}", preview_size, &program_data[..preview_size]);
            }
        }
        
        // Analyze bytecode
        log::info!("Analyzer: Analyzing bytecode");
        let result = bytecode::analyze(&program_data, &program_id.to_string())
            .map_err(|e| ExtractorError::from_anyhow(anyhow::anyhow!("{}", e), ErrorContext {
                program_id: Some(program_id.to_string()),
                component: "analyzer".to_string(),
                operation: "analyze_bytecode".to_string(),
                details: None,
            }));
        
        match &result {
            Ok(analysis) => log::info!("Analyzer: Bytecode analysis complete, found {} instructions", analysis.instructions.len()),
            Err(e) => log::error!("Analyzer: Bytecode analysis failed: {}", e),
        }
        
        result
    }
    
    /// Analyze transaction patterns
    pub async fn analyze_patterns(&self, program_id: &Pubkey, monitor: &Monitor) -> ExtractorResult<patterns::PatternAnalysis> {
        // Get recent transactions
        let transactions = monitor.get_recent_transactions(program_id).await
            .map_err(|e| ExtractorError::from_anyhow(anyhow::anyhow!("{}", e), ErrorContext {
                program_id: Some(program_id.to_string()),
                component: "analyzer".to_string(),
                operation: "analyze_patterns".to_string(),
                details: Some("get_recent_transactions".to_string()),
            }))?;
        
        // Analyze patterns
        patterns::analyze(program_id, &transactions)
            .map_err(|e| ExtractorError::from_anyhow(anyhow::anyhow!("{}", e), ErrorContext {
                program_id: Some(program_id.to_string()),
                component: "analyzer".to_string(),
                operation: "analyze_patterns".to_string(),
                details: None,
            }))
    }
    
    /// Build IDL from analyses
    pub fn build_idl(&self, program_id: &Pubkey, bytecode_analysis: bytecode::BytecodeAnalysis, pattern_analysis: patterns::PatternAnalysis) -> ExtractorResult<IDL> {
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
pub fn analyze_program(program_id: &Pubkey, rpc_client: &RpcClient) -> ExtractorResult<IDL> {
    info!("Analyzing program: {}", program_id);
    
    // Get program data
    let program_data = get_program_data(rpc_client, program_id)?;
    
    // Check if this is an Anchor program
    let is_anchor = anchor::is_anchor_program(&program_data);
    
    let mut idl = if is_anchor {
        info!("Detected Anchor program, using specialized analysis");
        match anchor::analyze(program_id, &program_data).map_err(|e| ExtractorError::from_anyhow(e, ErrorContext {
            program_id: Some(program_id.to_string()),
            component: "analyzer".to_string(),
            operation: "analyze_anchor".to_string(),
            details: None,
        })) {
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
                let bytecode_analysis = bytecode::analyze(&program_data, &program_id.to_string())
                    .map_err(|e| ExtractorError::from_anyhow(anyhow::anyhow!("{}", e), ErrorContext {
                        program_id: Some(program_id.to_string()),
                        component: "analyzer".to_string(),
                        operation: "analyze_program".to_string(),
                        details: Some("anchor_fallback".to_string()),
                    }))?;
                
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
        let bytecode_analysis = bytecode::analyze(&program_data, &program_id.to_string())
            .map_err(|e| ExtractorError::from_anyhow(anyhow::anyhow!("{}", e), ErrorContext {
                program_id: Some(program_id.to_string()),
                component: "analyzer".to_string(),
                operation: "analyze_program".to_string(),
                details: Some("native_analysis".to_string()),
            }))?;
        
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
        if let Err(e) = anchor::enhance_idl(&mut idl, &program_data)
            .map_err(|e| ExtractorError::from_anyhow(anyhow::anyhow!("{}", e), ErrorContext {
                program_id: Some(program_id.to_string()),
                component: "analyzer".to_string(),
                operation: "enhance_idl".to_string(),
                details: None,
            })) {
            warn!("Failed to enhance IDL with Anchor information: {}", e);
        }
    }
    
    Ok(idl)
}

/// Get program data from the blockchain
fn get_program_data(rpc_client: &RpcClient, program_id: &Pubkey) -> ExtractorResult<Vec<u8>> {
    info!("Fetching program data for: {}", program_id);
    
    // Get account data
    let account = rpc_client.get_account(program_id)
        .map_err(|e| ExtractorError::from_anyhow(anyhow::anyhow!("{}", e), ErrorContext {
            program_id: Some(program_id.to_string()),
            component: "analyzer".to_string(),
            operation: "get_program_data".to_string(),
            details: None,
        }))?;
    
    Ok(account.data)
} 