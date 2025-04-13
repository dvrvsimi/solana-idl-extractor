//! Core analysis engine for Solana programs

mod bytecode;
mod patterns;
#[cfg(test)]
mod tests;

use anyhow::Result;
use solana_sdk::pubkey::Pubkey;

use crate::models::idl::IDL;
use crate::monitor::Monitor;

pub use self::bytecode::BytecodeAnalysis;
pub use self::patterns::PatternAnalysis;

/// Main analyzer that coordinates the extraction process
pub struct Analyzer;

impl Analyzer {
    /// Create a new analyzer
    pub fn new() -> Self {
        Self
    }
    
    /// Analyze program bytecode to extract instruction and account information
    pub async fn analyze_bytecode(
        &self,
        program_id: &Pubkey,
        monitor: &Monitor,
    ) -> Result<BytecodeAnalysis> {
        let program_data = monitor.get_program_data(program_id).await?;
        bytecode::analyze(&program_data)
    }
    
    /// Analyze transaction patterns to extract additional information
    pub async fn analyze_patterns(
        &self,
        program_id: &Pubkey,
        monitor: &Monitor,
    ) -> Result<PatternAnalysis> {
        let transactions = monitor.get_recent_transactions(program_id).await?;
        patterns::analyze(program_id, &transactions)
    }
    
    /// Build the IDL from the combined analyses
    pub fn build_idl(
        &self,
        program_id: &Pubkey,
        bytecode_analysis: BytecodeAnalysis,
        pattern_analysis: PatternAnalysis,
    ) -> Result<IDL> {
        // Combine the analyses to build a comprehensive IDL
        let mut idl = IDL::new(program_id.to_string());
        
        // Add instructions from bytecode analysis
        for instruction in bytecode_analysis.instructions {
            idl.instructions.push(instruction);
        }
        
        // Add accounts from bytecode analysis
        for account in bytecode_analysis.accounts {
            idl.accounts.push(account);
        }
        
        // Enhance with pattern analysis
        idl.enhance_with_patterns(&pattern_analysis);
        
        Ok(idl)
    }
} 