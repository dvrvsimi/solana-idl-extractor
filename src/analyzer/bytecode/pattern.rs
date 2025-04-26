//! Pattern recognition in bytecode

use std::collections::{HashMap, HashSet};
use crate::analyzer::bytecode::parser::SbfInstruction;
use crate::analyzer::bytecode::cfg::{BasicBlock, Function};
use crate::constants::opcodes::opcodes;
use crate::constants::syscalls::syscalls;
use crate::models::instruction::Instruction;
use crate::models::account::Account;

/// Instruction handler
#[derive(Debug, Clone)]
pub struct InstructionHandler {
    /// Handler name
    pub name: String,
    /// Entry point address
    pub entry: usize,
    /// Discriminator
    pub discriminator: Option<u8>,
    /// Anchor discriminator (8 bytes)
    pub anchor_discriminator: Option<[u8; 8]>,
    /// Parameter types
    pub parameters: Vec<String>,
    /// Required accounts
    pub accounts: Vec<(String, bool, bool)>, // (name, is_signer, is_writable)
}

/// Extract strings from .rodata section
pub fn extract_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current_string = Vec::new();
    
    for &byte in data {
        if byte == 0 {
            if !current_string.is_empty() {
                if let Ok(s) = String::from_utf8(current_string) {
                    if s.len() >= 3 && s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                        strings.push(s);
                    }
                }
                current_string = Vec::new();
            }
        } else if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
            current_string.push(byte);
        } else {
            current_string.clear();
        }
    }
    
    strings
}

/// Detect if this is an Anchor program
pub fn detect_anchor_program(instructions: &[SbfInstruction], strings: &[String]) -> bool {
    // Check for Anchor's characteristic log message pattern
    if strings.iter().any(|s| s.contains("Instruction: ")) {
        return true;
    }
    
    // Check for Anchor's error code patterns
    if strings.iter().any(|s| 
        s.contains("ConstraintMut") || 
        s.contains("ConstraintSigner") || 
        s.contains("ConstraintRentExempt") ||
        s.contains("AccountDiscriminator")
    ) {
        return true;
    }
    
    // Check for Anchor's discriminator generation pattern
    if strings.iter().any(|s| s.contains("global:") || s.contains("account:")) {
        return true;
    }
    
    // Look for 8-byte discriminator patterns
    // This is a more complex check that looks for common Anchor instruction dispatch patterns
    let mut consecutive_comparisons = 0;
    let mut last_comparison_offset = 0;
    
    for (i, insn) in instructions.iter().enumerate() {
        // Look for comparison instructions
        if matches!(insn.opcode, opcodes::JEQ_REG | opcodes::JEQ_IMM | opcodes::JNE_REG | opcodes::JNE_IMM) {
            if last_comparison_offset > 0 && i - last_comparison_offset <= 10 {
                consecutive_comparisons += 1;
                if consecutive_comparisons >= 7 {  // Need 8 bytes, but allow for some flexibility
                    return true;
                }
            } else {
                consecutive_comparisons = 1;
            }
            
            last_comparison_offset = i;
        }
    }
    
    // Look for constraint check patterns
    for window in instructions.windows(5) {
        if is_checking_signer(window) || is_checking_writable(window) || 
           is_checking_rent_exempt(window) || is_checking_discriminator(window) {
            return true;
        }
    }
    
    false
}

/// Find instruction handlers in an Anchor program
pub fn find_anchor_instruction_handlers(
    instructions: &[SbfInstruction], 
    blocks: &[BasicBlock],
    strings: &[String]
) -> Vec<InstructionHandler> {
    let mut handlers = Vec::new();
    
    // Extract instruction names from strings
    let instruction_names: Vec<_> = strings.iter()
        .filter_map(|s| {
            if s.starts_with("Instruction: ") {
                Some(s[12..].to_string())
            } else {
                None
            }
        })
        .collect();
    
    // Look for discriminator comparisons
    for (i, block) in blocks.iter().enumerate() {
        // Check if this block contains a discriminator comparison
        let mut has_discriminator_check = false;
        let mut discriminator = [0u8; 8];
        
        for window in block.instructions.windows(3) {
            // Look for a pattern like:
            // ldxdw r0, [r1+0]   // Load 8-byte discriminator
            // mov r1, <imm>      // Load immediate value (part of discriminator)
            // jeq r0, r1, +12    // Compare and jump
            
            if window[0].is_load() && 
               window[0].mem_size() == Some(8) && 
               window[1].opcode == opcodes::MOV64_IMM && 
               window[2].opcode == opcodes::JEQ_REG {
                
                has_discriminator_check = true;
                
                // Extract the discriminator (this is simplified)
                discriminator[0..4].copy_from_slice(&window[1].imm.to_le_bytes());
                
                // We'd need to track more instructions to get the full 8 bytes
                break;
            }
        }
        
        if has_discriminator_check && i < instruction_names.len() {
            // Create a handler for this instruction
            let name = instruction_names[i].clone();
            
            // Generate the full discriminator using Anchor's algorithm
            let full_discriminator = generate_anchor_discriminator(&name);
            
            let handler = InstructionHandler {
                name,
                entry: block.start,
                discriminator: None,
                anchor_discriminator: Some(full_discriminator),
                parameters: infer_parameters(block),
                accounts: infer_accounts(block),
            };
            
            handlers.push(handler);
        }
    }
    
    handlers
}

/// Generate an Anchor instruction discriminator
fn generate_anchor_discriminator(name: &str) -> [u8; 8] {
    use sha2::{Sha256, Digest};
    
    let namespace = format!("global:{}", name);
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    let hash = hasher.finalize();
    
    let mut result = [0u8; 8];
    result.copy_from_slice(&hash[..8]);
    result
}

/// Find instruction handlers in a non-Anchor program
pub fn find_instruction_handlers(
    instructions: &[SbfInstruction],
    blocks: &[BasicBlock],
    functions: &[Function],
    strings: &[String]
) -> Vec<InstructionHandler> {
    let mut handlers = Vec::new();
    
    // Look for instruction dispatch patterns
    for block in blocks {
        // Check if this block contains an instruction dispatch pattern
        let mut has_dispatch = false;
        let mut discriminator = None;
        
        for window in block.instructions.windows(3) {
            // Look for a pattern like:
            // ldxb r0, [r1+0]   // Load discriminator byte
            // jeq r0, <imm>, +12 // Compare and jump if equal
            
            if window[0].is_load() && 
               window[0].mem_size() == Some(1) && 
               window[0].dst_reg == 0 && 
               (window[1].opcode == opcodes::JEQ_IMM || window[1].opcode == opcodes::JNE_IMM) {
                
                has_dispatch = true;
                discriminator = Some(window[1].imm as u8);
                break;
            }
        }
        
        if has_dispatch {
            // Try to find a name for this instruction
            let name = find_instruction_name(block, strings)
                .unwrap_or_else(|| format!("instruction_{}", discriminator.unwrap_or(0)));
            
            let handler = InstructionHandler {
                name,
                entry: block.start,
                discriminator,
                anchor_discriminator: None,
                parameters: infer_parameters(block),
                accounts: infer_accounts(block),
            };
            
            handlers.push(handler);
        }
    }
    
    // If we couldn't find any handlers, create a generic one
    if handlers.is_empty() {
        handlers.push(InstructionHandler {
            name: "process".to_string(),
            entry: 0,
            discriminator: Some(0),
            anchor_discriminator: None,
            parameters: vec!["bytes".to_string()],
            accounts: Vec::new(),
        });
    }
    
    handlers
}

/// Find a name for an instruction handler
fn find_instruction_name(block: &BasicBlock, strings: &[String]) -> Option<String> {
    // Look for log messages that might indicate the instruction name
    for insn in &block.instructions {
        if insn.is_call() && insn.imm as u32 == syscalls::SOL_LOG {
            // This is a call to sol_log, try to find the string being logged
            // This is a simplified approach - in a real implementation, we would
            // track register values to find the string pointer
            
            // Look for common instruction name patterns in strings
            for s in strings {
                let lower = s.to_lowercase();
                for pattern in &[
                    "initialize", "create", "update", "delete", "transfer", "mint", "burn",
                    "approve", "revoke", "freeze", "thaw", "close", "set", "get"
                ] {
                    if lower.contains(pattern) {
                        return Some(s.clone());
                    }
                }
            }
        }
    }
    
    None
}

/// Infer parameter types from a basic block
fn infer_parameters(block: &BasicBlock) -> Vec<String> {
    let mut parameters = Vec::new();
    
    // Look for memory loads that might indicate parameter access
    for window in block.instructions.windows(2) {
        if window[0].is_load() {
            // This is a load instruction, check the size
            if let Some(size) = window[0].mem_size() {
                match size {
                    1 => parameters.push("u8".to_string()),
                    2 => parameters.push("u16".to_string()),
                    4 => parameters.push("u32".to_string()),
                    8 => {
                        // This could be a u64 or a pubkey
                        // Check if it's used in a pubkey-specific way
                        if is_pubkey_usage(&block.instructions, window[0].dst_reg) {
                            parameters.push("pubkey".to_string());
                        } else {
                            parameters.push("u64".to_string());
                        }
                    },
                    _ => {}
                }
            }
        }
    }
    
    // Deduplicate parameters
    parameters.sort();
    parameters.dedup();
    
    // If we couldn't infer any parameters, add a generic one
    if parameters.is_empty() {
        parameters.push("bytes".to_string());
    }
    
    parameters
}

/// Check if a register is used as a pubkey
fn is_pubkey_usage(instructions: &[SbfInstruction], reg: u8) -> bool {
    for insn in instructions {
        if insn.is_call() {
            // Check if this is a call to a pubkey-related syscall
            let syscall_hash = insn.imm as u32;
            if syscall_hash == syscalls::SOL_LOG_PUBKEY ||
               syscall_hash == syscalls::SOL_CREATE_PROGRAM_ADDRESS ||
               syscall_hash == syscalls::SOL_TRY_FIND_PROGRAM_ADDRESS {
                // This is a pubkey-related syscall
                // Check if our register is used as an argument
                // This is a simplified approach - in a real implementation, we would
                // track register values more carefully
                if insn.src_reg == reg || insn.dst_reg == reg {
                    return true;
                }
            }
        }
    }
    
    false
}

/// Infer account usage from a basic block
fn infer_accounts(block: &BasicBlock) -> Vec<(String, bool, bool)> {
    let mut accounts = Vec::new();
    let mut account_constraints = HashMap::new();
    
    // Look for account access patterns
    for (i, window) in block.instructions.windows(3).enumerate() {
        if window[0].is_load() && window[0].mem_size() == Some(8) {
            // This might be loading an account pointer
            let reg = window[0].dst_reg;
            
            // Check if the next instructions access fields of this account
            if i + 3 < block.instructions.len() {
                let next_insn = &block.instructions[i + 3];
                if next_insn.is_load() && next_insn.src_reg == reg {
                    // This is accessing a field of the account
                    // Try to determine if it's checking is_signer or is_writable
                    let is_signer = is_checking_signer(&block.instructions[i+3..]);
                    let is_writable = is_checking_writable(&block.instructions[i+3..]);
                    
                    let account_idx = accounts.len();
                    let account_name = format!("account_{}", account_idx);
                    
                    accounts.push((account_name.clone(), is_signer, is_writable));
                    account_constraints.insert(account_name, detect_constraints(&block.instructions[i+3..]));
                }
            }
        }
    }
    
    // Look for Anchor-specific account validation patterns
    for window in block.instructions.windows(5) {
        // Look for discriminator checks (first 8 bytes of account data)
        if is_checking_discriminator(window) {
            // This is likely an Anchor account validation
            let account_idx = accounts.len();
            let account_name = format!("account_{}", account_idx);
            
            // Anchor accounts are typically required to be mutable
            accounts.push((account_name.clone(), false, true));
            
            let mut constraints = HashSet::new();
            constraints.insert("discriminator".to_string());
            account_constraints.insert(account_name, constraints);
        }
    }
    
    // If we couldn't infer any accounts, add some generic ones
    if accounts.is_empty() {
        accounts.push(("authority".to_string(), true, false));
        accounts.push(("data".to_string(), false, true));
    }
    
    // Update account properties based on constraints
    accounts = accounts.into_iter().map(|(name, is_signer, is_writable)| {
        if let Some(constraints) = account_constraints.get(&name) {
            let is_signer = is_signer || constraints.contains("signer");
            let is_writable = is_writable || constraints.contains("mut");
            (name, is_signer, is_writable)
        } else {
            (name, is_signer, is_writable)
        }
    }).collect();
    
    accounts
}

/// Detect constraints on an account
fn detect_constraints(instructions: &[SbfInstruction]) -> HashSet<String> {
    let mut constraints = HashSet::new();
    
    // Look for common constraint check patterns
    for window in instructions.windows(4) {
        // Check for signer constraint
        if is_checking_signer(window) {
            constraints.insert("signer".to_string());
        }
        
        // Check for mut constraint
        if is_checking_writable(window) {
            constraints.insert("mut".to_string());
        }
        
        // Check for rent-exempt constraint
        if is_checking_rent_exempt(window) {
            constraints.insert("rent-exempt".to_string());
        }
        
        // Check for owner constraint
        if is_checking_owner(window) {
            constraints.insert("owner".to_string());
        }
        
        // Check for initialized constraint
        if is_checking_initialized(window) {
            constraints.insert("initialized".to_string());
        }
    }
    
    constraints
}

/// Check if the instructions are checking a discriminator
pub fn is_checking_discriminator(instructions: &[SbfInstruction]) -> bool {
    // Look for a pattern that loads 8 bytes and compares them
    if instructions.len() >= 3 {
        if instructions[0].is_load() && 
           instructions[0].mem_size() == Some(8) &&
           (instructions[1].opcode == opcodes::JEQ_REG || 
            instructions[1].opcode == opcodes::JEQ_IMM ||
            instructions[1].opcode == opcodes::JNE_REG ||
            instructions[1].opcode == opcodes::JNE_IMM) {
            return true;
        }
    }
    
    false
}

/// Check if the instructions are checking the rent-exempt status
pub fn is_checking_rent_exempt(instructions: &[SbfInstruction]) -> bool {
    // This is a simplified check - in reality, we'd need to track
    // the flow of data more carefully to identify rent-exempt checks
    
    // Look for calls to sol_invoke_signed with system program
    for window in instructions.windows(3) {
        if window[0].is_call() && 
           (window[0].imm as u32 == syscalls::SOL_INVOKE_SIGNED_C || 
            window[0].imm as u32 == syscalls::SOL_INVOKE_SIGNED_RUST) {
            // This might be a call to check rent exemption
            return true;
        }
    }
    
    false
}

/// Check if the instructions are checking the owner of an account
pub fn is_checking_owner(instructions: &[SbfInstruction]) -> bool {
    // Look for a pattern that loads the owner field and compares it
    for window in instructions.windows(4) {
        if window[0].is_load() && 
           window[0].mem_size() == Some(8) && 
           window[0].offset == 8 && // Owner field is typically at offset 8
           (window[1].opcode == opcodes::JEQ_REG || 
            window[1].opcode == opcodes::JEQ_IMM ||
            window[1].opcode == opcodes::JNE_REG ||
            window[1].opcode == opcodes::JNE_IMM) {
            return true;
        }
    }
    
    false
}

/// Check if the instructions are checking if an account is initialized
pub fn is_checking_initialized(instructions: &[SbfInstruction]) -> bool {
    // Look for a pattern that checks if data size > 0
    for window in instructions.windows(3) {
        if window[0].is_load() && 
           window[0].mem_size() == Some(8) && 
           window[0].offset == 16 && // Data size field is typically at offset 16
           (window[1].opcode == opcodes::JEQ_IMM || 
            window[1].opcode == opcodes::JNE_IMM) &&
           window[1].imm == 0 {
            return true;
        }
    }
    
    false
}

/// Check if the instructions are checking the is_signer flag
pub fn is_checking_signer(instructions: &[SbfInstruction]) -> bool {
    for window in instructions.windows(3) {
        if window[0].is_load() && window[0].mem_size() == Some(1) {
            // This might be loading the is_signer flag
            // Check if it's followed by a comparison
            if window[1].opcode == opcodes::JEQ_IMM || window[1].opcode == opcodes::JNE_IMM {
                return true;
            }
        }
    }
    
    false
}

/// Check if the instructions are checking the is_writable flag
pub fn is_checking_writable(instructions: &[SbfInstruction]) -> bool {
    for window in instructions.windows(3) {
        if window[0].is_load() && window[0].mem_size() == Some(1) {
            // This might be loading the is_writable flag
            // Check if it's followed by a comparison
            if window[1].opcode == opcodes::JEQ_IMM || window[1].opcode == opcodes::JNE_IMM {
                return true;
            }
        }
    }
    
    false
}

/// Extract error codes from instructions and strings
pub fn extract_error_codes(instructions: &[SbfInstruction], strings: &[String]) -> HashMap<u32, String> {
    let mut error_codes = HashMap::new();
    
    // Look for error code patterns in strings
    for s in strings {
        // Check if this string looks like an error message
        if s.contains("Error") || s.contains("Failed") || s.contains("Invalid") {
            // Try to find a nearby error code
            for window in instructions.windows(2) {
                if window[0].opcode == opcodes::MOV64_IMM && window[1].is_call() {
                    // This might be setting an error code before calling sol_panic
                    if window[1].imm as u32 == syscalls::SOL_PANIC {
                        let error_code = window[0].imm as u32;
                        error_codes.insert(error_code, s.clone());
                    }
                }
            }
        }
    }
    
    // Look for Anchor error code patterns
    // Anchor error codes are typically defined in a specific range
    for window in instructions.windows(3) {
        if window[0].opcode == opcodes::MOV64_IMM && 
           (window[0].imm >= 100 && window[0].imm < 10000) && // Typical Anchor error code range
           window[1].is_call() && 
           window[1].imm as u32 == syscalls::SOL_PANIC {
            
            let error_code = window[0].imm as u32;
            
            // Try to find a matching error message
            let error_message = find_error_message_for_code(error_code, strings)
                .unwrap_or_else(|| format!("Error code {}", error_code));
            
            error_codes.insert(error_code, error_message);
        }
    }
    
    // Add common Anchor error codes if we detect it's an Anchor program
    if strings.iter().any(|s| s.contains("Anchor") || s.contains("anchor")) {
        // Anchor program constraint errors (2000-2999)
        if !error_codes.contains_key(&2000) { error_codes.insert(2000, "ConstraintMut".to_string()); }
        if !error_codes.contains_key(&2001) { error_codes.insert(2001, "ConstraintHasOne".to_string()); }
        if !error_codes.contains_key(&2002) { error_codes.insert(2002, "ConstraintSigner".to_string()); }
        // Add more common Anchor error codes as needed
    }
    
    error_codes
}

/// Find an error message for a specific error code
fn find_error_message_for_code(code: u32, strings: &[String]) -> Option<String> {
    // Look for strings that might be error messages for this code
    for s in strings {
        // Check for common error message patterns
        if s.contains(&format!("Error {}", code)) || 
           s.contains(&format!("Error: {}", code)) ||
           s.contains(&format!("Error code {}", code)) {
            return Some(s.clone());
        }
        
        // Check for Anchor-style error messages
        if (code >= 2000 && code < 3000) && s.contains("Constraint") {
            return Some(s.clone());
        }
        
        if (code >= 3000 && code < 4000) && s.contains("Account") {
            return Some(s.clone());
        }
    }
    
    None
}

/// Convert instruction handlers to IDL instructions
pub fn convert_to_idl_instructions(handlers: &[InstructionHandler], is_anchor: bool) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    
    for handler in handlers {
        let mut instruction = Instruction::new(handler.name.clone(), handler.discriminator.unwrap_or(0));
        
        // Add discriminator for Anchor programs
        if is_anchor {
            instruction.discriminator = handler.anchor_discriminator;
        }
        
        // Add parameters
        for (i, param_type) in handler.parameters.iter().enumerate() {
            instruction.add_arg(format!("arg_{}", i), param_type.clone());
        }
        
        // Add accounts
        for (name, is_signer, is_writable) in &handler.accounts {
            instruction.add_account(name.clone(), *is_signer, *is_writable, false);
        }
        
        instructions.push(instruction);
    }
    
    instructions
}

/// Extract account structures from instructions and strings
pub fn extract_account_structures(
    instructions: &[SbfInstruction], 
    strings: &[String],
    is_anchor: bool
) -> Vec<Account> {
    let mut accounts = Vec::new();
    
    // Look for account structure patterns in strings
    let account_names: Vec<_> = strings.iter()
        .filter(|s| {
            s.contains("Account") || s.contains("State") || 
            s.contains("Config") || s.contains("Data")
        })
        .cloned()
        .collect();
    
    // Extract discriminators for Anchor accounts
    let discriminators = if is_anchor {
        extract_anchor_discriminators(instructions)
    } else {
        HashMap::new()
    };
    
    for name in account_names {
        let mut account = Account::new(name.clone(), "account".to_string());
        
        // Add discriminator if this is an Anchor account
        if is_anchor {
            if let Some(disc) = discriminators.get(&name) {
                account.set_discriminator(disc.clone());
            }
        }
        
        // Add fields based on common patterns
        if name.to_lowercase().contains("mint") {
            account.add_field("mint_authority".to_string(), "pubkey".to_string(), 0);
            account.add_field("supply".to_string(), "u64".to_string(), 32);
            account.add_field("decimals".to_string(), "u8".to_string(), 40);
        } else if name.to_lowercase().contains("token") {
            account.add_field("mint".to_string(), "pubkey".to_string(), 0);
            account.add_field("owner".to_string(), "pubkey".to_string(), 32);
            account.add_field("amount".to_string(), "u64".to_string(), 64);
        } else {
            // Generic account fields
            account.add_field("owner".to_string(), "pubkey".to_string(), 0);
            account.add_field("data".to_string(), "bytes".to_string(), 32);
        }
        
        accounts.push(account);
    }
    
    // If we couldn't find any accounts, add a generic one
    if accounts.is_empty() {
        let mut account = Account::new("State".to_string(), "state".to_string());
        account.add_field("data".to_string(), "bytes".to_string(), 0);
        accounts.push(account);
    }
    
    accounts
}

/// Extract Anchor account discriminators
fn extract_anchor_discriminators(instructions: &[SbfInstruction]) -> HashMap<String, Vec<u8>> {
    let mut discriminators = HashMap::new();
    
    // Look for discriminator generation patterns
    for window in instructions.windows(8) {
        // Look for a pattern that generates a discriminator
        // This is a simplified approach - in reality, we'd need to track
        // the flow of data more carefully
        
        // Check if this looks like a call to hash("account:<name>")
        if window[0].opcode == opcodes::MOV64_IMM && 
           window[1].opcode == opcodes::MOV64_IMM && 
           window[2].opcode == opcodes::MOV64_IMM && 
           window[3].opcode == opcodes::MOV64_IMM {
            
            // This might be loading a string like "account:MyAccount"
            // Extract the bytes and try to form a string
            let bytes = [
                window[0].imm as u8, (window[0].imm >> 8) as u8, (window[0].imm >> 16) as u8, (window[0].imm >> 24) as u8,
                window[1].imm as u8, (window[1].imm >> 8) as u8, (window[1].imm >> 16) as u8, (window[1].imm >> 24) as u8,
                window[2].imm as u8, (window[2].imm >> 8) as u8, (window[2].imm >> 16) as u8, (window[2].imm >> 24) as u8,
                window[3].imm as u8, (window[3].imm >> 8) as u8, (window[3].imm >> 16) as u8, (window[3].imm >> 24) as u8,
            ];
            
            if let Ok(s) = std::str::from_utf8(&bytes) {
                if s.starts_with("account:") {
                    let account_name = s[8..].to_string();
                    
                    // Generate the discriminator using Anchor's algorithm
                    let discriminator = generate_anchor_discriminator(&account_name);
                    
                    discriminators.insert(account_name, discriminator.to_vec());
                }
            }
        }
    }
    
    discriminators
}