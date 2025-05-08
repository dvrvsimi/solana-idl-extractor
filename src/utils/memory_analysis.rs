use crate::analyzer::bytecode::parser::{SbfInstruction, MemoryAccessType};
use crate::constants::opcodes::opcodes;

/// Check if instruction accesses memory
pub fn accesses_memory(instruction: &SbfInstruction) -> bool {
    matches!(instruction.opcode,
        opcodes::LDXB | opcodes::LDXH | opcodes::LDXW | opcodes::LDXDW |
        opcodes::STB | opcodes::STH | opcodes::STW | opcodes::STDW |
        opcodes::STXB | opcodes::STXH | opcodes::STXW | opcodes::STXDW
    )
}

/// Get memory access type if applicable
pub fn memory_access_type(instruction: &SbfInstruction) -> Option<MemoryAccessType> {
    if !accesses_memory(instruction) {
        return None;
    }
    
    match instruction.opcode {
        opcodes::LDXB | opcodes::LDXH | opcodes::LDXW | opcodes::LDXDW => {
            Some(MemoryAccessType::Load)
        }
        opcodes::STB | opcodes::STH | opcodes::STW | opcodes::STDW |
        opcodes::STXB | opcodes::STXH | opcodes::STXW | opcodes::STXDW => {
            Some(MemoryAccessType::Store) 
        }
        _ => None
    }
}

/// Get size of memory access
pub fn mem_size(instruction: &SbfInstruction) -> Option<usize> {
    if !accesses_memory(instruction) {
        return None;
    }

    match instruction.opcode {
        opcodes::LDXB | opcodes::STB | opcodes::STXB => Some(1),
        opcodes::LDXH | opcodes::STH | opcodes::STXH => Some(2),
        opcodes::LDXW | opcodes::STW | opcodes::STXW => Some(4),
        opcodes::LDXDW | opcodes::STDW | opcodes::STXDW => Some(8),
        _ => None
    }
}

/// Check if instruction is a load
pub fn is_load(instruction: &SbfInstruction) -> bool {
    matches!(instruction.opcode,
        opcodes::LDXB | opcodes::LDXH | opcodes::LDXW | opcodes::LDXDW
    )
}

/// Check if instruction is a store
pub fn is_store(instruction: &SbfInstruction) -> bool {
    matches!(instruction.opcode,
        opcodes::STB | opcodes::STH | opcodes::STW | opcodes::STDW |
        opcodes::STXB | opcodes::STXH | opcodes::STXW | opcodes::STXDW
    )
} 