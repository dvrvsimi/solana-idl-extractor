//! IDL representation for Solana programs

use serde::{Serialize, Deserialize};
use crate::analyzer::patterns::PatternAnalysis;
use super::{Instruction, Account};

/// Represents a program IDL
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub metadata: Option<Metadata>,
}

/// Represents a program error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Error {
    /// Error code
    pub code: u32,
    /// Error name
    pub name: String,
    /// Error message
    pub msg: String,
}

/// Represents program metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// Program address
    pub address: String,
    /// Program origin (e.g., "anchor", "native")
    pub origin: String,
    /// Program framework version
    pub framework_version: Option<String>,
}

impl IDL {
    /// Create a new IDL
    pub fn new(program_id: String) -> Self {
        Self {
            name: format!("program_{}", program_id[0..8].to_string()),
            version: "0.1.0".to_string(),
            program_id,
            instructions: Vec::new(),
            accounts: Vec::new(),
            errors: Vec::new(),
            metadata: None,
        }
    }
    
    /// Enhance the IDL with pattern analysis
    pub fn enhance_with_patterns(&mut self, pattern_analysis: &PatternAnalysis) {
        // Placeholder implementation
        // In a real implementation, this would enhance the IDL with
        // information from pattern analysis
    }
    
    /// Add an error to the IDL
    pub fn add_error(&mut self, code: u32, name: String, msg: String) {
        self.errors.push(Error { code, name, msg });
    }
    
    /// Set the metadata for the IDL
    pub fn set_metadata(&mut self, origin: String, framework_version: Option<String>) {
        self.metadata = Some(Metadata {
            address: self.program_id.clone(),
            origin,
            framework_version,
        });
    }
} 