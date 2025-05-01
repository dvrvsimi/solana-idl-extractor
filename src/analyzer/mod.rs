//! Analyzer module for Solana programs

pub mod bytecode;
pub mod anchor;
pub mod patterns;
pub mod simulation;

#[cfg(test)]

use log::{info, warn, debug};
use solana_client::rpc_client::RpcClient;
use anyhow;
use thiserror::Error;

use crate::models::idl::IDL;
use crate::monitor::Monitor;
use crate::errors::ExtractorResult;
use crate::errors::{ExtractorError, ErrorContext};
use crate::errors::AnalyzerError;

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
    pub async fn analyze_bytecode(&self, program_id: &solana_pubkey::Pubkey, monitor: &Monitor) -> ExtractorResult<bytecode::BytecodeAnalysis> {

        // Validate inputs
        if program_id.to_bytes() == [0; 32] {
            return Err(ExtractorError::BytecodeAnalysis("Invalid program data".to_string()));
        }
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
            
            // Check if this is an Anchor program early
            let is_anchor = anchor::is_anchor_program(&program_data);
            if is_anchor {
                log::info!("Analyzer: Detected Anchor program");
            } else {
                log::info!("Analyzer: Detected non-Anchor program");
            }
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
    pub async fn analyze_patterns(&self, program_id: &solana_pubkey::Pubkey, monitor: &Monitor) -> ExtractorResult<patterns::PatternAnalysis> {
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
    
    /// Build IDL from analysis results
    pub async fn build_idl(&self, program_id: &solana_pubkey::Pubkey, bytecode_analysis: BytecodeAnalysis, pattern_analysis: PatternAnalysis) -> ExtractorResult<IDL> {
        // Create IDL
        let mut idl = IDL::new(format!("program_{}", program_id.to_string().chars().take(10).collect::<String>()), program_id.to_string());
        
        // Add instructions from bytecode analysis
        for instruction in bytecode_analysis.instructions.clone() {
            idl.add_instruction(instruction);
        }
        
        // Add accounts from bytecode analysis
        for account in bytecode_analysis.accounts.clone() {
            idl.add_account(account);
        }
        
        // Enhance IDL with pattern analysis
        for pattern in &pattern_analysis.instruction_patterns {
            // Find matching instruction in IDL
            if let Some(instruction) = idl.instructions.iter_mut().find(|i| i.index == pattern.index as u8) {
                // Update instruction with pattern information
                for (i, param_type) in pattern.parameter_types.iter().enumerate() {
                    if i < instruction.args.len() {
                        // Update existing argument type if it's more specific
                        if instruction.args[i].ty == "bytes" || instruction.args[i].ty == "unknown" {
                            instruction.args[i].ty = param_type.clone();
                        }
                    } else {
                        // Add new argument
                        instruction.add_arg(format!("param_{}", i), param_type.clone());
                    }
                }
            }
        }
        
        // Add account usage patterns
        for pattern in &pattern_analysis.account_patterns {
            // Find matching instruction
            if let Some(instruction) = idl.instructions.iter_mut().find(|i| i.index == pattern.instruction_index) {
                // Find or add account
                if pattern.account_index < instruction.accounts.len() {
                    // Update existing account
                    instruction.accounts[pattern.account_index].is_signer = pattern.is_signer;
                    instruction.accounts[pattern.account_index].is_writable = pattern.is_writable;
                } else {
                    // Add new account
                    instruction.add_account(
                        format!("account_{}", pattern.account_index),
                        pattern.is_signer,
                        pattern.is_writable,
                        false
                    );
                }
            }
        }
        
        // Enhance IDL with account relationship information
        let relationships = bytecode::account_analyzer::infer_account_relationships(
            &bytecode_analysis.accounts.clone(),
            &bytecode_analysis.instructions.clone()
        );
        
        // Add relationship information to accounts in the IDL
        for account in &mut idl.accounts {
            if let Some(related) = relationships.get(&account.name) {
                // Add a field to indicate relationships
                for related_account in related {
                    log::debug!("Account {} is related to {}", account.name, related_account);
                    // You could add a field or metadata to indicate this relationship
                }
            }
        }
        
        // Detect account hierarchies
        let hierarchies = bytecode::account_analyzer::detect_account_hierarchies(
            &bytecode_analysis.accounts.clone(),
            &relationships
        );
        
        // Add hierarchy information to accounts in the IDL
        for (parent, children) in &hierarchies {
            log::debug!("Account {} is parent of {} children", parent, children.len());
            // You could add a field or metadata to indicate this hierarchy
        }
        
        // Set metadata
        idl.metadata.address = program_id.to_string();
        idl.metadata.origin = "native".to_string();
        
        Ok(idl)
    }
    
    /// Build IDL with simulation results
    pub async fn build_idl_with_simulation(
        &self, 
        program_id: &solana_pubkey::Pubkey, 
        bytecode_analysis: BytecodeAnalysis, 
        pattern_analysis: PatternAnalysis,
        simulation_results: Vec<simulation::SimulationResult>
    ) -> ExtractorResult<IDL> {
        // First build the basic IDL
        let mut idl = self.build_idl(program_id, bytecode_analysis.clone(), pattern_analysis)
            .await?;
        
        // Enhance IDL with simulation results
        for result in simulation_results {
            if let Some(instruction) = idl.instructions.iter_mut()
                .find(|i| i.name == result.instruction.name || i.index == result.instruction.index) 
            {
                // Update instruction with more accurate arguments from simulation
                if !result.instruction.args.is_empty() {
                    // Only replace args if simulation found better ones
                    let has_better_args = result.instruction.args.iter()
                        .any(|arg| arg.ty != "bytes" && arg.ty != "unknown");
                    
                    if has_better_args {
                        instruction.args = result.instruction.args.clone();
                    }
                }
                
                // Update accounts with more accurate information
                for (i, account) in result.instruction.accounts.iter().enumerate() {
                    if i < instruction.accounts.len() {
                        // Update existing account
                        instruction.accounts[i].is_signer = account.is_signer;
                        instruction.accounts[i].is_writable = account.is_writable;
                    } else {
                        // Add new account
                        instruction.add_account(
                            account.name.clone(),
                            account.is_signer,
                            account.is_writable,
                            account.is_optional
                        );
                    }
                }
            }
            
            // Add any new accounts discovered during simulation
            for change in &result.account_changes {
                if change.is_new && !idl.accounts.iter().any(|a| a.name == change.address) {
                    // Create a new account from the observed data
                    let mut account = crate::models::account::Account::new(
                        format!("Account_{}", idl.accounts.len()),
                        "account".to_string()
                    );
                    
                    // Add a basic field for the data
                    account.add_field("data".to_string(), "bytes".to_string(), 0);
                    
                    // Add the account to the IDL
                    idl.add_account(account);
                }
            }
        }
        
        Ok(idl)
    }
}

/// Analyze a Solana program and extract its IDL
pub fn analyze_program(program_id: &solana_pubkey::Pubkey, rpc_client: &RpcClient) -> ExtractorResult<IDL> {
    log::info!("Analyzing program: {}", program_id);
    
    // Get program data
    let program_data = get_program_data(rpc_client, program_id)?;
    
    // Check if this is an Anchor program
    let is_anchor = anchor::is_anchor_program(&program_data);
    
    let mut idl = if is_anchor {
        log::info!("Detected Anchor program, using specialized analysis");
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
                log::warn!("Anchor analysis failed: {}, falling back to bytecode analysis", e);
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
            log::warn!("Failed to enhance IDL with Anchor information: {}", e);
        }
    }
    
    Ok(idl)
}

/// Get program data from the blockchain
fn get_program_data(rpc_client: &RpcClient, program_id: &solana_pubkey::Pubkey) -> ExtractorResult<Vec<u8>> {
    log::info!("Fetching program data for: {}", program_id);
    
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