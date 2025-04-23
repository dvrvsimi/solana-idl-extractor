//! Control flow graph building

use anyhow::Result;
use crate::analyzer::bytecode::parser::SbfInstruction;

/// Basic block in the control flow graph
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Start address
    pub start: usize,
    /// End address
    pub end: usize,
    /// Instructions in this block
    pub instructions: Vec<SbfInstruction>,
    /// Successor blocks
    pub successors: Vec<usize>,
    /// Predecessor blocks
    pub predecessors: Vec<usize>,
}

/// Function in the program
#[derive(Debug, Clone)]
pub struct Function {
    /// Function name
    pub name: String,
    /// Entry point address
    pub entry: usize,
    /// Exit points
    pub exits: Vec<usize>,
    /// Basic blocks in this function
    pub blocks: Vec<usize>,
}

/// Build a control flow graph from instructions
pub fn build_control_flow_graph(instructions: &[SbfInstruction]) -> Result<(Vec<BasicBlock>, Vec<Function>)> {
    let mut blocks = Vec::new();
    let mut functions = Vec::new();
    
    // Find basic block boundaries
    let mut block_starts = vec![0];
    
    for (i, insn) in instructions.iter().enumerate() {
        if insn.is_jump() {
            // Add the next instruction as a block start
            if i + 1 < instructions.len() {
                block_starts.push(i + 1);
            }
            
            // Add the jump target as a block start
            let target_addr = insn.address + 8 + (insn.offset as isize * 8) as usize;
            let target_idx = instructions.iter().position(|i| i.address == target_addr);
            if let Some(idx) = target_idx {
                block_starts.push(idx);
            }
        } else if insn.is_exit() {
            // Add the next instruction as a block start
            if i + 1 < instructions.len() {
                block_starts.push(i + 1);
            }
        }
    }
    
    // Sort and deduplicate block starts
    block_starts.sort();
    block_starts.dedup();
    
    // Create basic blocks
    for (i, &start) in block_starts.iter().enumerate() {
        let end = if i + 1 < block_starts.len() {
            block_starts[i + 1]
        } else {
            instructions.len()
        };
        
        let start_addr = if start < instructions.len() {
            instructions[start].address
        } else {
            continue;
        };
        
        let end_addr = if end <= instructions.len() && end > 0 {
            instructions[end - 1].address + 8
        } else {
            continue;
        };
        
        let block_instructions = instructions[start..end].to_vec();
        
        let block = BasicBlock {
            start: start_addr,
            end: end_addr,
            instructions: block_instructions,
            successors: Vec::new(),
            predecessors: Vec::new(),
        };
        
        blocks.push(block);
    }
    
    // Store pending updates to avoid borrow checker issues
    let mut pending_successors = Vec::new();
    let mut pending_predecessors = Vec::new();
    
    // Connect blocks
    for (i, block) in blocks.iter().enumerate() {
        if let Some(last_insn) = block.instructions.last() {
            if last_insn.is_jump() {
                // Add the jump target as a successor
                let target_addr = last_insn.address + 8 + (last_insn.offset as isize * 8) as usize;
                
                // Find the block containing this address
                let target_idx = blocks.iter().position(|b| b.start <= target_addr && target_addr < b.end);
                if let Some(idx) = target_idx {
                    pending_successors.push((i, idx));
                    pending_predecessors.push((idx, i));
                }
                
                // For conditional jumps, also add the fall-through block
                if last_insn.opcode != crate::constants::opcodes::JA {
                    if i + 1 < blocks.len() {
                        pending_successors.push((i, i + 1));
                        pending_predecessors.push((i + 1, i));
                    }
                }
            } else if !last_insn.is_exit() {
                // For non-jump, non-exit instructions, add the fall-through block
                if i + 1 < blocks.len() {
                    pending_successors.push((i, i + 1));
                    pending_predecessors.push((i + 1, i));
                }
            }
        }
    }
    
    // Apply the pending updates
    for (block_idx, succ_idx) in pending_successors {
        blocks[block_idx].successors.push(succ_idx);
    }
    
    for (block_idx, pred_idx) in pending_predecessors {
        blocks[block_idx].predecessors.push(pred_idx);
    }
    
    // Identify functions
    // For now, we'll just create a single function for the entire program
    let mut function = Function {
        name: "main".to_string(),
        entry: blocks[0].start,
        exits: Vec::new(),
        blocks: (0..blocks.len()).collect(),
    };
    
    // Find exit points
    for (i, block) in blocks.iter().enumerate() {
        if let Some(last_insn) = block.instructions.last() {
            if last_insn.is_exit() {
                function.exits.push(i);
            }
        }
    }
    
    functions.push(function);
    
    Ok((blocks, functions))
}

/// Find instruction dispatch points in the code
pub fn find_instruction_dispatch(instructions: &[SbfInstruction]) -> Vec<(usize, u8)> {
    let mut dispatch_points = Vec::new();
    
    // Look for instruction dispatch patterns
    for (i, window) in instructions.windows(3).enumerate() {
        // Look for a pattern like:
        // ldxb r0, [r1+0]   // Load discriminator byte
        // jeq r0, <imm>, +12 // Compare and jump if equal
        
        if window[0].is_load() && 
           window[0].mem_size() == Some(1) && 
           window[0].dst_reg == 0 && 
           (window[1].opcode == crate::constants::opcodes::JEQ_IMM || 
            window[1].opcode == crate::constants::opcodes::JNE_IMM) {
            
            let discriminator = window[1].imm as u8;
            let offset = i;
            
            dispatch_points.push((offset, discriminator));
        }
    }
    
    dispatch_points
}

/// Find byte comparisons in the code
pub fn find_byte_comparisons(instructions: &[SbfInstruction]) -> Vec<(usize, u8)> {
    let mut comparisons = Vec::new();
    
    // Look for byte comparison patterns
    for (i, window) in instructions.windows(2).enumerate() {
        // Look for a pattern like:
        // jeq r0, <imm>, +12 // Compare and jump if equal
        
        if (window[0].opcode == crate::constants::opcodes::JEQ_IMM || 
            window[0].opcode == crate::constants::opcodes::JNE_IMM) {
            let value = window[0].imm as u8;
            let offset = i;
            
            comparisons.push((offset, value));
        }
    }
    
    comparisons
}