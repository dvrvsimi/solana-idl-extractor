//! Tests for the analyzer module

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::models::{Instruction, Account};
    
    #[test]
    fn test_bytecode_analysis_basic() {
        // Create a simple mock program bytecode
        // This would be a simplified representation of a Solana program
        let program_data = include_bytes!("../../tests/fixtures/simple_program.so");
        
        // Analyze the bytecode
        let analysis = bytecode::analyze(program_data).unwrap();
        
        // Verify the analysis results
        assert!(!analysis.instructions.is_empty(), "Should extract at least one instruction");
        
        // Check the first instruction
        let first_instruction = &analysis.instructions[0];
        assert_eq!(first_instruction.name, "initialize", "First instruction should be 'initialize'");
        assert_eq!(first_instruction.index, 0, "First instruction should have index 0");
    }
    
    #[test]
    fn test_is_anchor_program() {
        // Create mock bytecode for an Anchor program
        let anchor_program = b"anchor_program_some_data";
        assert!(bytecode::is_anchor_program(anchor_program), "Should detect Anchor program");
        
        // Create mock bytecode for a non-Anchor program
        let non_anchor_program = b"regular_solana_program";
        assert!(!bytecode::is_anchor_program(non_anchor_program), "Should not detect as Anchor program");
    }
} 