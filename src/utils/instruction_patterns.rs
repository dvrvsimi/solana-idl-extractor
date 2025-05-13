use crate::analyzer::bytecode::parser::{SbfInstruction, InstructionClass};
use crate::constants::opcodes::opcodes;

/// Check if instruction is likely part of an instruction handler
pub fn is_instruction_handler(instruction: &SbfInstruction) -> bool {
    match instruction.class {
        InstructionClass::ControlFlow => {
            // Look for Anchor-style discriminator patterns
            if instruction.opcode == opcodes::JEQ_IMM {
                // Check for 8-byte discriminator comparison
                if instruction.imm >= 0 && instruction.imm <= 0xFF {
                    return true;
                }
                // Check for Anchor's 8-byte discriminator pattern
                if instruction.imm >= 0x100000000 && instruction.imm <= 0x1FFFFFFFF {
                    return true;
                }
            }
            // Look for syscall patterns
            if instruction.opcode == opcodes::CALL && instruction.imm >= 0x100000 {
                return true;
            }
            false
        }
        InstructionClass::MemoryLoadOr32BitALU => {
            // Look for account data loading patterns
            if instruction.is_load() {
                // Check for account data access (32 bytes for pubkey)
                if instruction.size == 32 && instruction.offset == 0 {
                    return true;
                }
                // Check for instruction data access (8 bytes for discriminator)
                if instruction.size == 8 && instruction.offset == 0 {
                    return true;
                }
            }
            false
        }
        _ => false
    }
}

/// Check if instruction is a discriminator check
pub fn is_discriminator_check(instruction: &SbfInstruction) -> bool {
    instruction.class == InstructionClass::ControlFlow &&
    instruction.opcode == opcodes::JEQ_IMM &&
    instruction.imm >= 0 && instruction.imm <= 0xFF
}

/// Check if instruction is an Anchor discriminator check
pub fn is_anchor_discriminator(instruction: &SbfInstruction) -> bool {
    instruction.class == InstructionClass::ControlFlow &&
    instruction.opcode == opcodes::JEQ_IMM &&
    instruction.imm >= 0x100000000 && instruction.imm <= 0x1FFFFFFFF
}

/// Check if instruction is a syscall
pub fn is_syscall(instruction: &SbfInstruction) -> bool {
    instruction.class == InstructionClass::ControlFlow &&
    instruction.opcode == opcodes::CALL &&
    instruction.imm >= 0x100000
}

/// Check if instruction is part of account validation
pub fn is_account_validation(instruction: &SbfInstruction) -> bool {
    if instruction.is_load() && instruction.size == 32 {
        return true;
    }

    // Check for ownership comparison
    if instruction.class == InstructionClass::ControlFlow && 
       (instruction.opcode == opcodes::JEQ_IMM || instruction.opcode == opcodes::JEQ_REG) {
        return true;
    }

    false
}

/// Check if instruction is loading parameters
pub fn is_parameter_loading(instruction: &SbfInstruction) -> bool {
    if !instruction.is_load() {
        return false;
    }

    matches!(instruction.size, 1 | 2 | 4 | 8)
} 