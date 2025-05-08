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
use crate::utils::get_program_elf_bytes;

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
        log::info!("Analyzing bytecode for program: {}", program_id);
        
        // Get program ELF data robustly (handles upgradeable/non-upgradeable)
        let elf_bytes = monitor.get_program_data(program_id).await?;
        
        log::debug!("Received program data, size: {} bytes", elf_bytes.len());
        
        // Check if this looks like valid ELF data
        if elf_bytes.len() >= 4 && elf_bytes[0] == 0x7F && elf_bytes[1] == b'E' && elf_bytes[2] == b'L' && elf_bytes[3] == b'F' {
            let is_anchor = anchor::is_anchor_program(&elf_bytes);
            if is_anchor {
                log::info!("Detected Anchor program");
            } else {
                log::info!("Detected native Solana program");
            }
        } else {
            log::warn!("Program data does not appear to be a valid ELF file");
        }
        
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
        let mut idl = IDL::new(
            format!("program_{}", program_id.to_string().chars().take(10).collect::<String>()), 
            program_id.to_string()
        );

        // Use official SBPF analysis for better instruction detection
        let instructions = analyze_with_sbpf(&bytecode_analysis.raw_data)?;
        
        // Group instructions using official analysis patterns
        let mut current_instruction = None;
        let mut instructions = Vec::new();

        for instruction in &instructions {
            if instruction.is_instruction_handler() {
                // Start new instruction group
                if let Some(complete_instruction) = current_instruction.take() {
                    instructions.push(complete_instruction);
                }
                
                // Use discriminator value for instruction name
                let name = if instruction.is_discriminator_check() {
                    format!("instruction_{}", instruction.imm)
                } else {
                    format!("instruction_{}", instructions.len())
                };
                
                current_instruction = Some(Instruction::new(name, instructions.len() as u8));
            }

            // Add accounts and parameters based on instruction patterns
            if let Some(ref mut current) = current_instruction {
                if instruction.is_account_validation() {
                    // Add account to current instruction
                    current.add_account(
                        format!("account_{}", current.accounts.len()),
                        true,  // Is signer - can be refined based on checks
                        true,  // Is writable - can be refined based on checks
                        false  // Not optional by default
                    );
                }

                if instruction.is_parameter_loading() {
                    // Add parameter based on load size
                    let param_type = match instruction.size {
                        1 => "u8",
                        2 => "u16",
                        4 => "u32",
                        8 => "u64",
                        _ => "bytes"
                    };
                    current.add_arg(
                        format!("param_{}", current.args.len()),
                        param_type.to_string()
                    );
                }
            }
        }
        
        // Add final instruction if any
        if let Some(instruction) = current_instruction {
            instructions.push(instruction);
        }

        // Add processed instructions to IDL
        for instruction in instructions {
            idl.add_instruction(instruction);
        }

        // Rest of the existing build_idl implementation...
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

/// Get program data from the blockchain
async fn get_program_data(rpc_client: &RpcClient, program_id: &solana_pubkey::Pubkey) -> ExtractorResult<Vec<u8>> {
    log::info!("Fetching program data for: {}", program_id);
    
    // Create a monitor to use the robust implementation
    let monitor = match crate::monitor::Monitor::new(rpc_client.url().as_str()).await {
        Ok(m) => m,
        Err(e) => return Err(ExtractorError::from_anyhow(anyhow::anyhow!("{}", e), ErrorContext {
            program_id: Some(program_id.to_string()),
            component: "analyzer".to_string(),
            operation: "get_program_data".to_string(),
            details: Some("create_monitor".to_string()),
        })),
    };
    
    // Use the monitor's implementation which correctly handles BPF upgradeable loader accounts
    match monitor.get_program_data(program_id).await {
        Ok(data) => Ok(data),
        Err(e) => Err(ExtractorError::from_anyhow(anyhow::anyhow!("{}", e), ErrorContext {
            program_id: Some(program_id.to_string()),
            component: "analyzer".to_string(),
            operation: "get_program_data".to_string(),
            details: None,
        })),
    }
}