//! Analyzer module for Solana programs

pub mod bytecode;
pub mod anchor;
pub mod patterns;
pub mod simulation;

use solana_client::rpc_client::RpcClient;
use anyhow;
use crate::models::idl::IDL;
use crate::monitor::Monitor;
use crate::errors::ExtractorResult;
use crate::errors::{ExtractorError, ErrorContext};
use crate::analyzer::bytecode::extract_program_name;
use crate::monitor::rpc::get_program_data;
use solana_sbpf::insn_builder::Instruction; // use this instead for impl on l107

// Re-export common types
pub use self::bytecode::BytecodeAnalysis;
pub use self::patterns::PatternAnalysis;
pub use self::simulation::TransactionSimulator;

/// Analyzer for Solana programs
pub struct Analyzer {
    // TODO: configuration options could go here, feature toggles, analysis depth, etc.
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
        log::info!("Analyzing bytecode for program: {}", program_id);
        
        // Get program ELF data robustly (handles upgradeable/non-upgradeable)
        let elf_bytes = monitor.get_program_data(program_id).await?;
        
        log::debug!("Received program data, size: {} bytes", elf_bytes.len());
        
        // Analyze bytecode
        let result = bytecode::analyze(&elf_bytes, &program_id.to_string())
            .map_err(|e| ExtractorError::from_anyhow(anyhow::anyhow!("{}", e), ErrorContext {
                program_id: Some(program_id.to_string()),
                component: "analyzer".to_string(),
                operation: "analyze_bytecode".to_string(),
                details: None,
            }));
        
        match &result {
            Ok(analysis) => log::info!("Bytecode analysis complete, found {} instructions", analysis.instructions.len()),
            Err(e) => log::error!("Bytecode analysis failed: {}", e),
        }
        
        result
    }

    /// Analyze a Solana program and extract its IDL
    pub async fn analyze_program(program_id: &solana_pubkey::Pubkey, rpc_client: &RpcClient) -> ExtractorResult<IDL> {
        log::info!("Analyzing program: {}", program_id);
        
        // Get program data
        let program_data = get_program_data(rpc_client, program_id).await?;
        
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
    
    
    /// Build IDL from analysis results
    pub async fn build_idl(
        &self, 
        program_id: &solana_pubkey::Pubkey, 
        program_data: &[u8], 
        bytecode_analysis: BytecodeAnalysis, 
        pattern_analysis: PatternAnalysis // TODO: use this to further enrich the IDL
    ) -> ExtractorResult<IDL> {
        // Use extracted program name if possible
        let program_name = extract_program_name(program_data)
            .unwrap_or_else(|_| format!("program_{}", program_id.to_string().chars().take(10).collect::<String>()));

        let mut idl = IDL::new(program_name.clone(), program_id.to_string());

        // Add instructions from bytecode analysis
        for ix in &bytecode_analysis.instructions {
            idl.add_instruction(ix.clone());
        }

        // Add accounts from bytecode analysis
        for acc in &bytecode_analysis.accounts {
            idl.add_account(acc.clone());
        }

        // Add error codes from bytecode analysis
        for (code, name) in &bytecode_analysis.error_codes {
            idl.add_error(*code, name.clone(), name.clone());
        }

        // Set metadata name and notes
        idl.metadata.metadata_name = program_name;
        idl.metadata.notes = Some("Extracted from native Solana program".to_string());

        // TODO: Use pattern_analysis to further enrich the IDL if needed

        Ok(idl)
    }

    /// Analyze transaction patterns, TODO: improve this
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
    
    /// Build IDL with simulation results, TODO: improve this
    pub async fn build_idl_with_simulation(
        &self, 
        program_id: &solana_pubkey::Pubkey, 
        bytecode_analysis: BytecodeAnalysis, 
        pattern_analysis: PatternAnalysis,
        simulation_results: Vec<simulation::SimulationResult>
    ) -> ExtractorResult<IDL> {
        // First build the basic IDL
        let mut idl = self.build_idl(program_id, &[], bytecode_analysis.clone(), pattern_analysis)
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

