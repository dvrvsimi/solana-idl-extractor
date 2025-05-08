use crate::analyzer::bytecode::parser::SbfInstruction;
use crate::constants::opcodes::opcodes;

/// Check if instruction is part of account validation
pub fn is_account_validation(instruction: &SbfInstruction) -> bool {
    // Check for syscall-based account validation
    if instruction.is_syscall() {
        match instruction.imm {
            0x100000 => return true, // create_account
            0x100001 => return true, // transfer
            0x100002 => return true, // allocate
            _ => {}
        }
    }

    // Check for account data access patterns
    if instruction.is_load() {
        // Check for account data access (32 bytes for pubkey)
        if instruction.size == 32 && instruction.offset == 0 {
            return true;
        }
        // Check for account flags access
        if instruction.size == 1 && instruction.offset == 32 {
            return true;
        }
    }

    // Check for ownership comparison
    if instruction.class == InstructionClass::ControlFlow && 
       (instruction.opcode == opcodes::JEQ_IMM || instruction.opcode == opcodes::JEQ_REG) {
        return true;
    }

    false
}

/// Check if instruction is part of account ownership validation
pub fn is_account_ownership_check(instruction: &SbfInstruction) -> bool {
    // Check for syscall-based ownership check
    if instruction.is_syscall() && instruction.imm == 0x100000 {
        return true;
    }

    // Check for ownership comparison pattern
    if instruction.class == InstructionClass::ControlFlow && 
       instruction.opcode == opcodes::JEQ_IMM {
        // Check for program ID comparison
        if instruction.imm >= 0x100000000 && instruction.imm <= 0x1FFFFFFFF {
            return true;
        }
    }

    false
}

/// Check if instruction is accessing account data
pub fn is_account_data_access(instruction: &SbfInstruction) -> bool {
    if !instruction.is_load() {
        return false;
    }

    // Check for account data access patterns
    match instruction.size {
        32 => true,  // pubkey
        1 => instruction.offset >= 32,  // flags
        8 => instruction.offset >= 33,  // lamports
        _ => false
    }
}

/// Get account data size from instruction
pub fn get_account_size(instruction: &SbfInstruction) -> Option<usize> {
    if !is_account_data_access(instruction) {
        return None;
    }

    match instruction.size {
        32 => Some(32),  // pubkey
        1 => Some(1),    // flags
        8 => Some(8),    // lamports
        _ => None
    }
}

/// Check if instruction is part of account constraint validation
pub fn is_account_constraint_check(instruction: &SbfInstruction) -> bool {
    // Check for syscall-based constraint check
    if instruction.is_syscall() {
        match instruction.imm {
            0x100000 => return true, // create_account
            0x100001 => return true, // transfer
            _ => {}
        }
    }

    // Check for constraint validation patterns
    if instruction.class == InstructionClass::ControlFlow {
        match instruction.opcode {
            opcodes::JEQ_IMM | opcodes::JEQ_REG => {
                // Check for constraint comparison
                if instruction.imm >= 0 && instruction.imm <= 0xFF {
                    return true;
                }
            }
            opcodes::JGT_IMM | opcodes::JGT_REG => {
                // Check for size/balance constraints
                return true;
            }
            _ => {}
        }
    }

    false
} 