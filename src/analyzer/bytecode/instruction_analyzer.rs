//! Instruction analyzer for Solana programs

use anyhow::Result;
use crate::models::instruction::Instruction;
use super::parser::SbfInstruction;
use super::discriminator_detection::AnchorDiscriminator;
use log;

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
    
    // Before the loop, ensure boundaries ends with instructions.len()
    let mut boundaries = boundaries.clone();
    if *boundaries.last().unwrap() != instructions.len() {
        boundaries.push(instructions.len());
    }
    
    Ok(boundaries)
}

/// Extract program instructions from the analyzed bytecode
pub fn extract_program_instructions(
    instructions: &[SbfInstruction],
    boundaries: &[usize],
    discriminators: &[AnchorDiscriminator]
) -> Result<Vec<Instruction>> {
    let mut program_instructions = Vec::new();
    
    // Common instruction name patterns
    let common_instructions = [
        "initialize", "create", "update", "delete", "transfer",
        "mint", "burn", "swap", "deposit", "withdraw",
        "stake", "unstake", "claim", "vote", "propose"
    ];
    
    let instruction_size = 8;
    for i in 0..boundaries.len() - 1 {
        let start = boundaries[i];
        let end = boundaries[i + 1];
        if end > instructions.len() {
            log::warn!("Boundary end {} out of range for instructions of length {}", end, instructions.len());
            continue;
        }
        if start > end {
            log::warn!("Boundary start {} greater than end {}", start, end);
            continue;
        }
        if (end - start) % instruction_size != 0 {
            log::warn!("Instruction slice from {} to {} is not aligned to instruction size {}", start, end, instruction_size);
            continue;
        }
        let instruction_slice = &instructions[start..end];
        
        // Try to find a matching discriminator
        let discriminator = discriminators.iter()
            .find(|d| d.code.map_or(false, |code| code as usize == i));
        
        // Create instruction name
        let name = if let Some(disc) = discriminator {
            disc.name.clone().unwrap_or_else(|| {
                // Analyze instruction patterns to infer name
                infer_instruction_name(instruction_slice, i, &common_instructions)
            })
        } else {
            // Analyze instruction patterns to infer name
            infer_instruction_name(instruction_slice, i, &common_instructions)
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

fn infer_instruction_name(instructions: &[SbfInstruction], index: usize, common_instructions: &[&str]) -> String {
    // Look for common instruction patterns
    if let Some(pattern) = common_instructions.get(index) {
        pattern.to_string()
    } else {
        // Analyze instruction patterns to infer name
        if instructions.iter().any(|insn| insn.is_mov_imm() && insn.imm > 0) {
            format!("instruction_{}_with_imm", index)
        } else if instructions.iter().any(|insn| insn.is_load()) {
            format!("instruction_{}_with_load", index)
        } else {
            format!("instruction_{}", index)
        }
    }
} 