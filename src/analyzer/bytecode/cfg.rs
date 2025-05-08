//! Control flow graph building

use anyhow::Result;
use crate::analyzer::bytecode::parser::SbfInstruction;
use std::collections::{HashSet, VecDeque};
use crate::constants::opcodes::opcodes;
use crate::utils::control_flow::{
    is_jump, is_call, is_exit, is_branch, is_conditional_branch,
    branch_target, call_target, analyze_control_flow, find_function_boundaries
};
use solana_sbpf::static_analysis::Analysis;

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
    
    /// Check if this block is a function entry point using SBPF analysis
    pub fn is_function_entry(&self) -> bool {
        if self.instructions.is_empty() {
            return false;
        }
        
        // Use SBPF's analysis to detect function entry points
        let first_insn = &self.instructions[0];
        
        // Function entry points typically:
        // 1. Start with a call or jump
        // 2. Have no predecessors
        // 3. Have specific register setup patterns
        is_call(first_insn) || 
        is_jump(first_insn) || 
        self.predecessors.is_empty() ||
        (first_insn.is_mov_reg() && first_insn.dst_reg == 11 && first_insn.src_reg == 1)
    }
    
    /// Check if this block is likely an instruction handler using SBPF analysis
    pub fn is_instruction_handler(&self) -> bool {
        if self.instructions.len() < 3 {
            return false;
        }
        
        // Look for instruction handler patterns:
        // 1. Load discriminator
        // 2. Compare discriminator
        // 3. Branch based on comparison
        let has_discriminator_load = self.instructions.iter().take(5).any(|insn| 
            insn.is_load() && insn.src_reg == 2 && insn.offset == 0
        );
        
        let has_comparison = self.instructions.iter().take(10).any(|insn|
            is_conditional_branch(insn)
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

/// Build a control flow graph from instructions using SBPF analysis
pub fn build_cfg(instructions: &[SbfInstruction], analysis: &Analysis) -> Result<(Vec<BasicBlock>, Vec<Function>)> {
    // Use SBPF's analysis to find function boundaries
    let function_boundaries = find_function_boundaries(analysis);
    
    // Use SBPF's analysis to build CFG
    let cfg = analyze_control_flow(analysis);
    
    // Create basic blocks from CFG
    let mut blocks = Vec::new();
    for (i, (start, successors)) in cfg.iter().enumerate() {
        let mut block = BasicBlock::new(i, *start);
        
        // Add instructions to block
        let end = if i + 1 < cfg.len() {
            cfg[i + 1].0 - 1
        } else {
            instructions.len() - 1
        };
        
        block.end = end;
        for j in *start..=end {
            if j < instructions.len() {
                block.instructions.push(instructions[j].clone());
            }
        }
        
        // Add successors
        block.successors = successors.clone();
        
        blocks.push(block);
    }
    
    // Add predecessors
    for (i, block) in blocks.iter().enumerate() {
        for &succ in &block.successors {
            if succ < blocks.len() {
                blocks[succ].predecessors.push(i);
            }
        }
    }
    
    // Create functions from boundaries
    let mut functions = Vec::new();
    for (func_id, (start, end)) in function_boundaries.iter().enumerate() {
        let mut function = Function {
            id: func_id,
            entry_block: *start,
            blocks: Vec::new(),
            name: None,
            parameters: Vec::new(),
            return_type: None,
        };
        
        // Find all blocks in this function
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(*start);
        visited.insert(*start);
        
        while let Some(block_id) = queue.pop_front() {
            function.blocks.push(block_id);
            
            // Add successors to queue if they're within function bounds
            for &succ in &blocks[block_id].successors {
                if !visited.contains(&succ) && succ <= *end {
                    visited.insert(succ);
                    queue.push_back(succ);
                }
            }
        }
        
        // Try to identify function name using SBPF analysis
        if let Some(block) = blocks.get(*start) {
            if block.is_instruction_handler() {
                function.name = Some(format!("process_instruction_{}", func_id));
            } else {
                function.name = Some(format!("func_{}", func_id));
            }
        }
        
        functions.push(function);
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
