//! Control flow graph building

use anyhow::Result;
use crate::analyzer::bytecode::parser::SbfInstruction;
use std::collections::{HashSet, VecDeque};
use crate::constants::opcodes::opcodes;

/// Basic block in the control flow graph
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Block ID
    pub id: usize,
    /// Start instruction index
    pub start: usize,
    /// End instruction index (inclusive)
    pub end: usize,
    /// Predecessor blocks
    pub predecessors: Vec<usize>,
    /// Successor blocks
    pub successors: Vec<usize>,
    /// Instructions in this block
    pub instructions: Vec<SbfInstruction>,
}

impl BasicBlock {
    /// Create a new basic block
    pub fn new(id: usize, start: usize) -> Self {
        Self {
            id,
            start,
            end: start,
            predecessors: Vec::new(),
            successors: Vec::new(),
            instructions: Vec::new(),
        }
    }
    
    /// Check if this block is a function entry point
    pub fn is_function_entry(&self) -> bool {
        // Function entry points typically have specific patterns:
        // 1. They often start with stack setup instructions
        // 2. They may have no predecessors or special predecessors
        
        if self.instructions.is_empty() {
            return false;
        }
        
        // Check for stack setup pattern
        let first_insns = &self.instructions[..std::cmp::min(3, self.instructions.len())];
        
        // Look for stack frame setup pattern
        let has_stack_setup = first_insns.iter().any(|insn| 
            (insn.is_mov_reg() && insn.dst_reg == 11 && insn.src_reg == 1) || // mov r11, r1 (frame pointer setup)
            (insn.is_add_imm() && insn.dst_reg == 1 && insn.imm < 0) // add r1, #-X (stack allocation)
        );
        
        // Check for register saving pattern (common in function prologues)
        let has_register_save = first_insns.iter().any(|insn|
            insn.is_store() && insn.src_reg == 0 // str rx, [sp, #X]
        );
        
        has_stack_setup || has_register_save || self.predecessors.is_empty()
    }
    
    /// Check if this block is likely an instruction handler
    pub fn is_instruction_handler(&self) -> bool {
        // Instruction handlers often:
        // 1. Start by checking the instruction discriminator
        // 2. Have conditional branches based on the discriminator
        
        if self.instructions.len() < 3 {
            return false;
        }
        
        // Look for discriminator loading pattern
        // Typically loads first 8 bytes from instruction data
        let has_discriminator_load = self.instructions.iter().take(5).any(|insn| 
            (insn.is_load() && insn.src_reg == 2 && insn.offset == 0) || // ldr rx, [r2] (load from instruction data)
            (insn.is_load() && insn.src_reg == 2 && insn.offset == 4)    // ldr rx, [r2, #4] (load second part)
        );
        
        // Look for comparison after loading
        let has_comparison = self.instructions.iter().take(10).any(|insn|
            insn.is_cmp() || insn.is_branch() // cmp or branch instructions
        );
        
        has_discriminator_load && has_comparison
    }
}

/// Function in the program
#[derive(Debug, Clone)]
pub struct Function {
    /// Function ID
    pub id: usize,
    /// Entry block ID
    pub entry_block: usize,
    /// All blocks in this function
    pub blocks: Vec<usize>,
    /// Function name (if known)
    pub name: Option<String>,
    /// Parameters (if known)
    pub parameters: Vec<String>,
    /// Return type (if known)
    pub return_type: Option<String>,
}

/// Build a control flow graph from instructions
pub fn build_cfg(instructions: &[SbfInstruction]) -> Result<(Vec<BasicBlock>, Vec<Function>)> {
    // Find basic block boundaries
    let mut block_starts = HashSet::new();
    block_starts.insert(0); // First instruction is always a block start
    
    // Find branch targets and instructions after branches
    for (i, insn) in instructions.iter().enumerate() {
        if insn.is_branch() {
            // Branch target is a block start
            if let Some(target) = insn.branch_target() {
                if target < instructions.len() {
                    block_starts.insert(target);
                }
            }
            
            // Instruction after branch is a block start
            if i + 1 < instructions.len() {
                block_starts.insert(i + 1);
            }
        }
        
        // Call targets are also block starts
        if insn.is_call() {
            if let Some(target) = insn.call_target() {
                if target < instructions.len() {
                    block_starts.insert(target);
                }
            }
        }
    }
    
    // Create basic blocks
    let mut blocks = Vec::new();
    let mut block_starts_vec: Vec<usize> = block_starts.into_iter().collect();
    block_starts_vec.sort();
    
    for (i, &start) in block_starts_vec.iter().enumerate() {
        let end = if i + 1 < block_starts_vec.len() {
            block_starts_vec[i + 1] - 1
        } else {
            instructions.len() - 1
        };
        
        let mut block = BasicBlock::new(i, start);
        block.end = end;
        
        // Add instructions to the block
        for j in start..=end {
            if j < instructions.len() {
                block.instructions.push(instructions[j].clone());
            }
        }
        
        blocks.push(block);
    }
    
    // Connect blocks (add successors and predecessors)
    // First, collect all the connections we need to make
    let mut connections = Vec::new();

    for i in 0..blocks.len() {
        let block = &blocks[i];
        
        if block.instructions.is_empty() {
            continue;
        }
        
        let last_insn = &block.instructions[block.instructions.len() - 1];
        
        if last_insn.is_branch() {
            // Add branch target as successor
            if let Some(target) = last_insn.branch_target() {
                // Find block containing this target
                if let Some(target_block) = blocks.iter().position(|b| b.start <= target && target <= b.end) {
                    connections.push((i, target_block));
                }
            }
            
            // For conditional branches, the next block is also a successor
            if last_insn.is_conditional_branch() && i + 1 < blocks.len() {
                connections.push((i, i + 1));
            }
        } else if !last_insn.is_return() && !last_insn.is_exit() && i + 1 < blocks.len() {
            // If not a branch or return, the next block is a successor
            connections.push((i, i + 1));
        }
    }

    // Now apply all the connections
    for (from, to) in connections {
        blocks[from].successors.push(to);
        blocks[to].predecessors.push(from);
    }
    
    // Identify functions
    let mut functions = Vec::new();
    let mut visited = HashSet::new();
    
    // First pass: identify function entry points
    let mut entry_points = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        if block.is_function_entry() {
            entry_points.push(i);
        }
    }
    
    // Second pass: build functions from entry points
    for (func_id, &entry) in entry_points.iter().enumerate() {
        let mut function = Function {
            id: func_id,
            entry_block: entry,
            blocks: Vec::new(),
            name: None,
            parameters: Vec::new(),
            return_type: None,
        };
        
        // Use BFS to find all blocks in this function
        let mut queue = VecDeque::new();
        queue.push_back(entry);
        visited.insert(entry);
        
        while let Some(block_id) = queue.pop_front() {
            function.blocks.push(block_id);
            
            // Add successors to queue
            for &succ in &blocks[block_id].successors {
                if !visited.contains(&succ) {
                    visited.insert(succ);
                    queue.push_back(succ);
                }
            }
        }
        
        // Try to identify function name
        if blocks[entry].instructions.len() > 0 {
            // Look for string references near the function start
            // This is a heuristic - function names are often referenced near the start
            for insn in blocks[entry].instructions.iter().take(10) {
                if insn.is_load_imm() && insn.imm > 0 {
                    // This might be loading a string pointer
                    // In a real implementation, we'd try to resolve this to a string
                    function.name = Some(format!("func_{}", func_id));
                    break;
                }
            }
        }
        
        if function.name.is_none() {
            function.name = Some(format!("func_{}", func_id));
        }
        
        functions.push(function);
    }
    
    // Identify instruction handlers among the functions
    for function in &mut functions {
        let entry_block = &blocks[function.entry_block];
        if entry_block.is_instruction_handler() {
            // This is likely an instruction handler
            function.name = Some(format!("process_instruction_{}", function.id));
        }
    }
    
    Ok((blocks, functions))
}

/// Analyze instruction data access to identify parameters
pub fn analyze_instruction_parameters(blocks: &[BasicBlock], function: &Function) -> Vec<(String, String)> {
    let mut parameters = Vec::new();
    
    // Look for instruction data accesses in the function blocks
    for &block_id in &function.blocks {
        let block = &blocks[block_id];
        
        for insn in &block.instructions {
            if insn.is_load() && insn.src_reg == 2 {
                // This is likely loading from instruction data (r2 is often used for this)
                let offset = insn.offset as usize;
                
                // Skip the first 8 bytes (discriminator)
                if offset >= 8 {
                    let param_offset = offset - 8;
                    let param_size = match insn.size {
                        1 => "u8",
                        2 => "u16",
                        4 => "u32",
                        8 => "u64",
                        _ => "bytes",
                    };
                    
                    // Check if we already have this parameter
                    if !parameters.iter().any(|(_, o)| o == &param_offset.to_string()) {
                        parameters.push((param_size.to_string(), param_offset.to_string()));
                    }
                }
            }
        }
    }
    
    // Sort parameters by offset
    parameters.sort_by(|a, b| {
        let a_offset = a.1.parse::<usize>().unwrap_or(0);
        let b_offset = b.1.parse::<usize>().unwrap_or(0);
        a_offset.cmp(&b_offset)
    });
    
    // Convert to named parameters
    parameters.into_iter()
        .enumerate()
        .map(|(i, (ty, _))| (format!("param_{}", i), ty))
        .collect()
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
           (window[1].opcode == opcodes::JEQ_IMM || 
            window[1].opcode == opcodes::JNE_IMM) {
            
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
        
        if window[0].opcode == opcodes::JEQ_IMM || 
            window[0].opcode == opcodes::JNE_IMM {
            let value = window[0].imm as u8;
            let offset = i;
            
            comparisons.push((offset, value));
        }
    }
    
    comparisons
}


/// Find functions in a control flow graph
pub fn find_functions(blocks: &[BasicBlock]) -> Vec<Function> {
    let mut functions = Vec::new();
    
    // Find entry points (blocks with no predecessors or blocks after a return)
    for (i, block) in blocks.iter().enumerate() {
        if block.predecessors.is_empty() || 
           (i > 0 && blocks[i-1].instructions.last().map_or(false, |insn| insn.opcode == opcodes::EXIT)) {
            let mut function = Function {
                id: functions.len(),
                entry_block: i,
                blocks: vec![i],
                name: Some(format!("func_{:x}", block.start)),
                parameters: Vec::new(),
                return_type: None,
            };
            
            // Add all blocks reachable from this entry point
            let mut visited = HashSet::new();
            let mut stack = vec![i];
            
            while let Some(block_idx) = stack.pop() {
                if visited.insert(block_idx) {
                    function.blocks.push(block_idx);
                    
                    // Add successors to the stack
                    for &succ in &blocks[block_idx].successors {
                        if !visited.contains(&succ) {
                            stack.push(succ);
                        }
                    }
                }
            }
            
            functions.push(function);
        }
    }
    
    functions
}
