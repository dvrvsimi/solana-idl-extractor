//! Account structure analysis from bytecode

use anyhow::{Result, anyhow, Context};
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use crate::models::account::Account;
use crate::constants::discriminator::ANCHOR_DISCRIMINATOR_LENGTH;
use super::parser::{SbfInstruction, parse_instructions};
use super::elf::ElfAnalyzer;

/// Field access information
#[derive(Debug, Clone)]
struct FieldAccess {
    /// Offset from the start of the account
    offset: usize,
    /// Size of the access (1, 2, 4, or 8 bytes)
    size: usize,
    /// Is this a write access?
    is_write: bool,
    /// Frequency of access
    frequency: usize,
    /// Instruction context where this access occurs
    context: Option<String>,
}

/// Memory access pattern
#[derive(Debug, Clone)]
struct MemoryAccessPattern {
    /// Base register
    base_reg: u8,
    /// Accesses using this base register
    accesses: Vec<FieldAccess>,
    /// Is this likely an account?
    is_account: bool,
}

/// Extract account structures from bytecode analysis
pub fn extract_account_structures(program_data: &[u8]) -> Result<Vec<Account>> {
    let mut accounts = Vec::new();
    let mut memory_patterns: HashMap<u8, MemoryAccessPattern> = HashMap::new();
    
    // Try to parse the ELF file
    let elf_analyzer = ElfAnalyzer::from_bytes(program_data)?;
    
    // Get the text section (code)
    if let Ok(Some(text_section)) = elf_analyzer.get_text_section() {
        // Parse instructions
        let instructions = parse_instructions(&text_section.data, text_section.address as usize)?;
        
        // Track register values to follow data flow
        let mut register_values: HashMap<u8, (String, usize)> = HashMap::new();
        
        // First pass: identify memory access patterns
        for (i, insn) in instructions.iter().enumerate() {
            // Track register assignments
            if insn.is_mov_imm() {
                register_values.insert(insn.dst_reg, ("immediate".to_string(), insn.imm as usize));
            } else if insn.is_mov_reg() {
                if let Some(&(source, offset)) = register_values.get(&insn.src_reg) {
                    register_values.insert(insn.dst_reg, (source, offset));
                }
            } else if insn.is_add_imm() {
                if let Some(&(source, offset)) = register_values.get(&insn.dst_reg) {
                    register_values.insert(insn.dst_reg, (source, offset + insn.imm as usize));
                }
            } else if insn.is_add_reg() {
                if let Some(&(source1, offset1)) = register_values.get(&insn.dst_reg) {
                    if let Some(&(source2, offset2)) = register_values.get(&insn.src_reg) {
                        register_values.insert(insn.dst_reg, (format!("{}+{}", source1, source2), offset1 + offset2));
                    }
                }
            }
            
            // Track memory accesses
            if insn.is_load() || insn.is_store() {
                let base_reg = insn.src_reg;
                let offset = insn.offset as usize;
                let size = insn.size;
                let is_write = insn.is_store();
                
                // Get context from surrounding instructions
                let context = get_access_context(&instructions, i);
                
                // Add to memory patterns
                let pattern = memory_patterns.entry(base_reg).or_insert_with(|| MemoryAccessPattern {
                    base_reg,
                    accesses: Vec::new(),
                    is_account: false,
                });
                
                // Check if we already have this access
                let existing_access = pattern.accesses.iter_mut().find(|a| a.offset == offset && a.size == size);
                
                if let Some(access) = existing_access {
                    access.frequency += 1;
                    if is_write {
                        access.is_write = true;
                    }
                    if access.context.is_none() && context.is_some() {
                        access.context = context;
                    }
                } else {
                    pattern.accesses.push(FieldAccess {
                        offset,
                        size,
                        is_write,
                        frequency: 1,
                        context,
                    });
                }
            }
        }
        
        // Second pass: identify which patterns are likely accounts
        for pattern in memory_patterns.values_mut() {
            // Sort accesses by offset
            pattern.accesses.sort_by_key(|a| a.offset);
            
            // Heuristics to identify accounts:
            // 1. Has multiple field accesses
            // 2. Has a discriminator (first 8 bytes) access
            // 3. Has fields at regular offsets
            // 4. Has both reads and writes
            
            let has_multiple_fields = pattern.accesses.len() >= 3;
            let has_discriminator_access = pattern.accesses.iter().any(|a| a.offset < 8);
            let has_regular_offsets = has_regular_offset_pattern(&pattern.accesses);
            let has_reads_and_writes = pattern.accesses.iter().any(|a| a.is_write) && 
                                      pattern.accesses.iter().any(|a| !a.is_write);
            
            pattern.is_account = has_multiple_fields && 
                                (has_discriminator_access || has_regular_offsets || has_reads_and_writes);
        }
        
        // Third pass: create account models
        for (reg, pattern) in &memory_patterns {
            if !pattern.is_account {
                continue;
            }
            
            // Try to determine account name from context
            let account_name = determine_account_name(pattern, &register_values);
            
            let mut account = Account::new(account_name.clone(), account_name.to_lowercase());
            
            // Group fields by likely structure
            let fields = group_fields_by_structure(&pattern.accesses);
            
            // Add fields to account
            for (offset, (name, ty, _)) in &fields {
                account.add_field(name.clone(), ty.clone(), *offset);
            }
            
            // If this looks like an Anchor account, add a discriminator
            if account_name.contains("Account") && !fields.is_empty() {
                let discriminator = crate::utils::hash::generate_anchor_account_discriminator(&account_name);
                account.set_discriminator(discriminator.to_vec());
            }
            
            accounts.push(account);
        }
    }
    
    Ok(accounts)
}

/// Get context for a memory access from surrounding instructions
fn get_access_context(instructions: &[SbfInstruction], index: usize) -> Option<String> {
    // Look for string references or function calls before this instruction
    let start = index.saturating_sub(5);
    let end = std::cmp::min(index + 5, instructions.len());
    
    for i in start..end {
        let insn = &instructions[i];
        
        // Look for string loading (often used for logging account names)
        if insn.is_load_imm() && insn.imm > 0 {
            // This might be loading a string pointer
            return Some(format!("context_{}", insn.imm));
        }
        
        // Look for function calls (might indicate account validation)
        if insn.is_call() {
            return Some(format!("call_{}", insn.imm));
        }
    }
    
    None
}

/// Check if memory accesses have a regular offset pattern
fn has_regular_offset_pattern(accesses: &[FieldAccess]) -> bool {
    if accesses.len() < 3 {
        return false;
    }
    
    // Check for common patterns
    
    // Pattern 1: 8-byte aligned fields (common in Rust structs)
    let aligned_8 = accesses.iter()
        .filter(|a| a.offset % 8 == 0)
        .count() >= accesses.len() / 2;
    
    // Pattern 2: 4-byte aligned fields
    let aligned_4 = accesses.iter()
        .filter(|a| a.offset % 4 == 0)
        .count() >= accesses.len() / 2;
    
    // Pattern 3: Sequential fields with consistent sizes
    let mut consistent_sizes = true;
    let mut prev_offset = accesses[0].offset;
    let mut prev_size = accesses[0].size;
    
    for access in &accesses[1..] {
        if access.offset != prev_offset + prev_size {
            consistent_sizes = false;
            break;
        }
        prev_offset = access.offset;
        prev_size = access.size;
    }
    
    aligned_8 || aligned_4 || consistent_sizes
}

/// Determine account name from context
fn determine_account_name(pattern: &MemoryAccessPattern, register_values: &HashMap<u8, (String, usize)>) -> String {
    // Try to get name from register source
    if let Some((source, _)) = register_values.get(&pattern.base_reg) {
        if source.contains("account") || source.contains("Account") {
            return source.clone();
        }
    }
    
    // Try to get name from access contexts
    for access in &pattern.accesses {
        if let Some(ref context) = access.context {
            if context.contains("account") || context.contains("Account") {
                return context.clone();
            }
        }
    }
    
    // Default name based on access pattern
    if pattern.accesses.iter().any(|a| a.offset < 8) {
        "AnchorAccount".to_string()
    } else {
        "DataAccount".to_string()
    }
}

/// Group fields by likely structure
fn group_fields_by_structure(accesses: &[FieldAccess]) -> HashMap<usize, (String, String, usize)> {
    let mut fields = HashMap::new();
    
    // Skip discriminator (first 8 bytes in Anchor accounts)
    let data_accesses = accesses.iter().filter(|a| a.offset >= 8);
    
    for access in data_accesses {
        // Check if this is part of a larger field
        let mut is_part_of_larger = false;
        
        for other in accesses {
            // If there's a larger access that contains this one, it's part of that field
            if other.offset < access.offset && 
               other.offset + other.size > access.offset + access.size {
                is_part_of_larger = true;
                break;
            }
        }
        
        if is_part_of_larger {
            continue;
        }
        
        // Determine field type based on access pattern
        let field_type = if is_likely_pubkey(access.offset, accesses) {
            "Pubkey"
        } else {
            match access.size {
                1 => "u8",
                2 => "u16",
                4 => "u32",
                8 => "u64",
                _ => "bytes",
            }
        };
        
        // Generate field name
        let field_name = if field_type == "Pubkey" {
            if access.offset == 8 {
                "authority".to_string()
            } else {
                format!("pubkey_at_{}", access.offset)
            }
        } else {
            format!("field_at_{}", access.offset)
        };
        
        fields.insert(access.offset, (field_name, field_type.to_string(), access.size));
    }
    
    fields
}

/// Check if a field is likely a Pubkey based on its usage pattern
fn is_likely_pubkey(offset: usize, accesses: &[FieldAccess]) -> bool {
    // Pubkeys are 32 bytes, but often accessed as a 64-bit value
    // They're typically at specific offsets and have specific usage patterns
    
    // Check if there are multiple 8-byte accesses at consecutive offsets
    // This might indicate a 32-byte field being accessed in chunks
    let consecutive_offsets = [offset, offset + 8, offset + 16, offset + 24];
    let mut found_consecutive = 0;
    
    for &check_offset in &consecutive_offsets {
        if accesses.iter().any(|a| a.offset == check_offset && a.size == 8) {
            found_consecutive += 1;
        }
    }
    
    // If we found at least 2 consecutive 8-byte accesses, this might be a Pubkey
    if found_consecutive >= 2 {
        return true;
    }
    
    // Check for common Pubkey offsets in Anchor accounts
    // Authority fields are often at specific offsets
    if offset == 8 || offset == 40 || offset == 72 {
        return true;
    }
    
    false
} 