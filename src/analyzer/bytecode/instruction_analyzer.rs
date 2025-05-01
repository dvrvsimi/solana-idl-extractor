//! Instruction analyzer for Solana programs

use anyhow::Result;
use crate::models::instruction::Instruction;
use super::parser::SbfInstruction;
use super::discriminator_detection::AnchorDiscriminator;

/// Find instruction boundaries in the program
pub fn find_instruction_boundaries(instructions: &[SbfInstruction]) -> Result<Vec<usize>> {
    let mut boundaries = Vec::new();
    
    // Look for function prologues (common patterns)
    for (i, insn) in instructions.iter().enumerate() {
        // Check for common BPF function prologue pattern
        if insn.opcode == 0x0f && // ALU64_REG 
           insn.dst_reg == 11 && 
           insn.src_reg == 11 && 
           insn.imm < 0 {
            boundaries.push(i);
        }
    }
    
    // If we didn't find any boundaries, add a default one at the beginning
    if boundaries.is_empty() {
        boundaries.push(0);
    }
    
    Ok(boundaries)
}

/// Extract program instructions from the analyzed bytecode
pub fn extract_program_instructions(
    _instructions: &[SbfInstruction],
    boundaries: &[usize],
    discriminators: &[AnchorDiscriminator]
) -> Result<Vec<Instruction>> {
    let mut program_instructions = Vec::new();
    
    // For each boundary, create an instruction
    for (i, &_boundary) in boundaries.iter().enumerate() {
        // Try to find a matching discriminator
        let discriminator = discriminators.iter()
            .find(|d| d.code.map_or(false, |code| code as usize == i));
        
        // Create instruction name
        let name = if let Some(disc) = discriminator {
            disc.name.clone().unwrap_or_else(|| format!("instruction_{}", i))
        } else {
            format!("instruction_{}", i)
        };
        
        // Create instruction
        let mut instruction = Instruction::new(name, i as u8);
        
        // Add discriminator if available
        if let Some(disc) = discriminator {
            instruction.discriminator = Some(disc.bytes.clone());
        }
        
        // Add generic arguments
        instruction.add_arg("data".to_string(), "bytes".to_string());
        
        // Add standard accounts
        instruction.add_account("authority".to_string(), true, false, false);
        instruction.add_account("data".to_string(), false, true, false);
        
        program_instructions.push(instruction);
    }
    
    // If we didn't find any instructions, add a generic one
    if program_instructions.is_empty() {
        let mut instruction = Instruction::new("process".to_string(), 0);
        instruction.add_arg("data".to_string(), "bytes".to_string());
        instruction.add_account("authority".to_string(), true, false, false);
        instruction.add_account("data".to_string(), false, true, false);
        program_instructions.push(instruction);
    }
    
    Ok(program_instructions)
} 