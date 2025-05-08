use crate::analyzer::bytecode::parser::SbfInstruction;
use crate::constants::opcodes::opcodes;
use solana_sbpf::static_analysis::Analysis;

/// Check if instruction is a jump
pub fn is_jump(instruction: &SbfInstruction) -> bool {
    matches!(
        instruction.opcode,
        opcodes::JA | opcodes::JEQ_REG | opcodes::JEQ_IMM | 
        opcodes::JNE_REG | opcodes::JNE_IMM | opcodes::JGT_IMM |
        opcodes::JGT_REG | opcodes::JGE_IMM | opcodes::JGE_REG |
        opcodes::JLT_IMM | opcodes::JLT_REG | opcodes::JLE_IMM |
        opcodes::JLE_REG | opcodes::JSET_IMM | opcodes::JSET_REG |
        opcodes::JSGT_IMM | opcodes::JSGT_REG | opcodes::JSGE_IMM |
        opcodes::JSGE_REG | opcodes::JSLT_IMM | opcodes::JSLT_REG |
        opcodes::JSLE_IMM | opcodes::JSLE_REG
    )
}

/// Check if instruction is a call
pub fn is_call(instruction: &SbfInstruction) -> bool {
    instruction.opcode == opcodes::CALL || instruction.opcode == opcodes::CALLX
}

/// Check if instruction is an exit
pub fn is_exit(instruction: &SbfInstruction) -> bool {
    instruction.opcode == opcodes::EXIT || instruction.opcode == opcodes::RETURN
}

/// Check if instruction is a branch
pub fn is_branch(instruction: &SbfInstruction) -> bool {
    instruction.opcode == opcodes::JA ||
    instruction.opcode == opcodes::JEQ_IMM ||
    instruction.opcode == opcodes::JNE_IMM ||
    instruction.opcode == opcodes::JEQ_REG ||
    instruction.opcode == opcodes::JNE_REG
}

/// Check if instruction is a conditional branch
pub fn is_conditional_branch(instruction: &SbfInstruction) -> bool {
    instruction.opcode == opcodes::JEQ_IMM ||
    instruction.opcode == opcodes::JNE_IMM ||
    instruction.opcode == opcodes::JEQ_REG ||
    instruction.opcode == opcodes::JNE_REG
}

/// Get branch target address
pub fn branch_target(instruction: &SbfInstruction, current_address: usize) -> Option<usize> {
    if is_branch(instruction) {
        Some(current_address.wrapping_add(instruction.offset as usize))
    } else {
        None
    }
}

/// Get call target address
pub fn call_target(instruction: &SbfInstruction, current_address: usize) -> Option<usize> {
    if instruction.opcode == opcodes::CALL {
        Some(current_address.wrapping_add(instruction.offset as usize))
    } else if instruction.opcode == opcodes::CALLX {
        // For CALLX, target is in src register
        Some(instruction.src_reg as usize)
    } else {
        None
    }
}

/// Analyze control flow using SBPF analysis
pub fn analyze_control_flow(analysis: &Analysis) -> Vec<(usize, Vec<usize>)> {
    let mut cfg = Vec::new();
    let mut current_block = Vec::new();
    let mut current_address = 0;

    for (pc, insn) in analysis.instructions.iter().enumerate() {
        let instruction = SbfInstruction::from_sbpf(insn);
        
        // Check for block boundaries
        if is_branch(&instruction) || is_call(&instruction) || is_exit(&instruction) {
            // Add current block to CFG
            if !current_block.is_empty() {
                cfg.push((current_address, current_block.clone()));
                current_block.clear();
            }
            
            // Add branch/call targets
            if let Some(target) = branch_target(&instruction, pc) {
                current_block.push(target);
            }
            if let Some(target) = call_target(&instruction, pc) {
                current_block.push(target);
            }
            
            current_address = pc + 1;
        } else {
            current_block.push(pc + 1);
        }
    }

    // Add final block if any
    if !current_block.is_empty() {
        cfg.push((current_address, current_block));
    }

    cfg
}

/// Find function boundaries using SBPF analysis
pub fn find_function_boundaries(analysis: &Analysis) -> Vec<(usize, usize)> {
    let mut functions = Vec::new();
    let mut current_start = 0;
    let mut in_function = false;

    for (pc, insn) in analysis.instructions.iter().enumerate() {
        let instruction = SbfInstruction::from_sbpf(insn);

        // Function entry points are typically calls or jumps
        if !in_function && (is_call(&instruction) || is_jump(&instruction)) {
            current_start = pc;
            in_function = true;
        }

        // Function end points are typically returns or exits
        if in_function && is_exit(&instruction) {
            functions.push((current_start, pc));
            in_function = false;
        }
    }

    // Add final function if any
    if in_function {
        functions.push((current_start, analysis.instructions.len() - 1));
    }

    functions
} 