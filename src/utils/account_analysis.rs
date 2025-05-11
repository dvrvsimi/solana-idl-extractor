use crate::analyzer::bytecode::parser::SbfInstruction;
use crate::constants::opcodes::opcodes;
use crate::constants::discriminator::program_ids;
use solana_sbpf::static_analysis::Analysis;

/// Account validation type
#[derive(Debug, Clone)]
pub enum AccountValidationType {
    Ownership,      // Check if account is owned by program
    DataSize,       // Check account data size
    DataFormat,     // Check account data format
    Signer,         // Check if account is a signer
    Writable,       // Check if account is writable
    Custom(u8),     // Custom validation type
}

/// Account constraint
#[derive(Debug, Clone)]
pub struct AccountConstraint {
    pub constraint_type: ConstraintType,
    pub value: Option<u64>,
}

/// Constraint type
#[derive(Debug, Clone, PartialEq)]
pub enum ConstraintType {
    MinSize,
    MaxSize,
    MinBalance,
    MaxBalance,
    MustBeSigner,
    MustBeWritable,
    MustBeProgramOwned,
    Custom(u8),
}

/// Native account validation
#[derive(Debug, Clone)]
pub struct NativeAccountValidation {
    pub validation_type: AccountValidationType,
    pub program_id: Option<String>,
    pub constraints: Vec<AccountConstraint>,
}

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

    false
}

/// Extract native account validations
pub fn extract_native_account_validations(instructions: &[SbfInstruction]) -> Vec<NativeAccountValidation> {
    let mut validations = Vec::new();
    
    for window in instructions.windows(5) {
        // Check for ownership validation
        if is_ownership_validation(window) {
            validations.push(NativeAccountValidation {
                validation_type: AccountValidationType::Ownership,
                program_id: detect_program_id(window),
                constraints: vec![],
            });
        }
        
        // Check for data size validation
        if is_data_size_validation(window) {
            validations.push(NativeAccountValidation {
                validation_type: AccountValidationType::DataSize,
                program_id: detect_program_id(window),
                constraints: extract_size_constraints(window),
            });
        }
        
        // Check for signer validation
        if is_signer_validation(window) {
            validations.push(NativeAccountValidation {
                validation_type: AccountValidationType::Signer,
                program_id: detect_program_id(window),
                constraints: vec![],
            });
        }
    }
    
    validations
}

/// Check if instruction window is ownership validation
fn is_ownership_validation(window: &[SbfInstruction]) -> bool {
    // Look for ownership check pattern:
    // 1. Load account owner (32 bytes)
    // 2. Compare with program ID
    window[0].is_load() && 
    window[0].size == 32 && 
    window[0].offset == 32 && // Owner is at offset 32
    window[1].is_cmp_imm() && 
    window[2].is_branch()
}

/// Check if instruction window is data size validation
fn is_data_size_validation(window: &[SbfInstruction]) -> bool {
    // Look for size check pattern:
    // 1. Load account data size
    // 2. Compare with expected size
    window[0].is_load() && 
    window[0].size == 8 && 
    window[0].offset == 0 && // Size is at offset 0
    window[1].is_cmp_imm() && 
    window[2].is_branch()
}

/// Check if instruction window is signer validation
fn is_signer_validation(window: &[SbfInstruction]) -> bool {
    // Look for signer check pattern:
    // 1. Load account flags
    // 2. Check signer bit
    window[0].is_load() && 
    window[0].size == 1 && 
    window[0].offset == 32 && // Flags are at offset 32
    window[1].is_cmp_imm() && 
    window[2].is_branch()
}

/// Extract size constraints from instruction window
fn extract_size_constraints(window: &[SbfInstruction]) -> Vec<AccountConstraint> {
    let mut constraints = Vec::new();
    
    if window[1].is_cmp_imm() {
        let size = window[1].imm as u64;
        
        // Check if this is a minimum or maximum size check
        if window[2].opcode == opcodes::JGT_IMM || window[2].opcode == opcodes::JGE_IMM {
            constraints.push(AccountConstraint {
                constraint_type: ConstraintType::MinSize,
                value: Some(size),
            });
        } else if window[2].opcode == opcodes::JLT_IMM || window[2].opcode == opcodes::JLE_IMM {
            constraints.push(AccountConstraint {
                constraint_type: ConstraintType::MaxSize,
                value: Some(size),
            });
        }
    }
    
    constraints
}


/// first convert program id to int, then compare (is there a better way?)
fn program_id_to_int(program_id: &str) -> i64 {
    i64::from_str_radix(program_id, 10).unwrap_or_default()
}

/// Detect program ID from instruction window
fn detect_program_id(window: &[SbfInstruction]) -> Option<String> {
    for insn in window {
        if insn.is_load() && insn.size == 32 {
            if let Some(next) = window.get(1) {
                if next.is_cmp_imm() {
                    match next.imm {
                        x if x == program_id_to_int(program_ids::SYSTEM_PROGRAM) => {
                            return Some(program_ids::SYSTEM_PROGRAM.to_string());
                        }
                        x if x == program_id_to_int(program_ids::TOKEN_PROGRAM) => {
                            return Some(program_ids::TOKEN_PROGRAM.to_string());
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    None
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