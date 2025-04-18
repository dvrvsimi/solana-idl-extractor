//! IDL model

use serde::{Serialize, Deserialize};
use crate::models::instruction::Instruction;
use crate::models::account::Account;
use crate::analyzer::patterns_simplified::PatternAnalysis;
use crate::monitor::transaction::TransactionAnalysis;

/// Interface Description Language (IDL) for a Solana program
#[derive(Debug, Serialize, Deserialize)]
pub struct IDL {
    /// Program name
    pub name: String,
    /// Program version
    pub version: String,
    /// Program ID
    pub program_id: String,
    /// Program instructions
    pub instructions: Vec<Instruction>,
    /// Program accounts
    pub accounts: Vec<Account>,
    /// Program errors
    pub errors: Vec<Error>,
    /// Program metadata
    pub metadata: Metadata,
}

/// Error definition
#[derive(Debug, Serialize, Deserialize)]
pub struct Error {
    /// Error code
    pub code: u32,
    /// Error name
    pub name: String,
    /// Error message
    pub msg: Option<String>,
}

/// Program metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    /// Program address
    pub address: String,
    /// Program origin (native, anchor, etc.)
    pub origin: String,
    /// Framework version (if applicable)
    pub framework_version: Option<String>,
    /// Instruction frequencies from transaction analysis
    pub instruction_frequencies: Option<Vec<(u8, u64)>>,
}

impl IDL {
    /// Create a new IDL
    pub fn new(name: String, program_id: String) -> Self {
        Self {
            name,
            version: "0.1.0".to_string(),
            program_id,
            instructions: Vec::new(),
            accounts: Vec::new(),
            errors: Vec::new(),
            metadata: Metadata {
                address: "".to_string(),
                origin: "".to_string(),
                framework_version: None,
                instruction_frequencies: None,
            },
        }
    }
    
    /// Add an instruction to the IDL
    pub fn add_instruction(&mut self, instruction: Instruction) {
        // Check if we already have an instruction with this index
        if self.instructions.iter().any(|i| i.index == instruction.index) {
            // If the existing instruction has a generic name and the new one doesn't,
            // replace it
            if let Some(existing) = self.instructions.iter_mut().find(|i| i.index == instruction.index) {
                if existing.name.starts_with("instruction_") && !instruction.name.starts_with("instruction_") {
                    *existing = instruction;
                }
            }
        } else {
            // Otherwise, add the new instruction
            self.instructions.push(instruction);
        }
    }
    
    /// Add an account to the IDL
    pub fn add_account(&mut self, account: Account) {
        // Check if we already have an account with this name
        if !self.accounts.iter().any(|a| a.name == account.name) {
            self.accounts.push(account);
        }
    }
    
    /// Enhance IDL with pattern analysis
    pub fn enhance_with_patterns(&mut self, pattern_analysis: &PatternAnalysis) {
        // Add instruction frequencies
        // Convert instruction patterns to frequencies
        let frequencies: Vec<(u8, u64)> = pattern_analysis.instruction_patterns
            .iter()
            .map(|pattern| (pattern.index, pattern.frequency as u64))
            .collect();
        
        self.metadata.instruction_frequencies = Some(frequencies);
        
        // Enhance instructions with additional information from patterns
        for pattern in &pattern_analysis.instruction_patterns {
            // Find the instruction with this index
            if let Some(instruction) = self.instructions.iter_mut().find(|i| i.index == pattern.index) {
                // Add any missing arguments from pattern
                for arg in &pattern.args {
                    if !instruction.args.iter().any(|a| a.name == arg.name) {
                        instruction.add_arg(arg.name.clone(), arg.ty.clone());
                    }
                }
                
                // Add any missing accounts from pattern
                for account in &pattern.accounts {
                    if !instruction.accounts.iter().any(|a| a.name == account.name) {
                        instruction.add_account(
                            account.name.clone(), 
                            account.is_signer, 
                            account.is_writable, 
                            false
                        );
                    }
                }
            }
        }
    }

    /// Add an error to the IDL
    pub fn add_error(&mut self, code: u32, name: String, msg: String) {
        self.errors.push(Error { code, name, msg: Some(msg) });
    }
    
    /// Set the metadata for the IDL
    pub fn set_metadata(&mut self, origin: String, framework_version: Option<String>) {
        self.metadata.origin = origin;
        self.metadata.framework_version = framework_version;
    }

    // Add method to enhance with transaction analysis
    pub fn enhance_with_transaction_analysis(&mut self, analysis: &TransactionAnalysis) {
        // Add instructions from transaction analysis
        for instruction in &analysis.instructions {
            // Check if we already have this instruction
            if !self.instructions.iter().any(|i| i.index == instruction.index) {
                self.instructions.push(instruction.clone());
            }
        }
        
        // Add frequency information as metadata
        let frequencies: Vec<(u8, u64)> = analysis.frequencies
            .iter()
            .map(|(idx, freq)| (*idx, *freq as u64))
            .collect();
        
        self.metadata.instruction_frequencies = Some(frequencies);
    }
} 