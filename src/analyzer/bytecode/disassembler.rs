//! BPF bytecode disassembler for Solana programs

use anyhow::Result;
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use crate::models::instruction::Instruction;
use crate::models::account::Account;
use crate::errors::{ExtractorError, ExtractorResult};
use crate::constants::opcodes::opcodes;
use goblin;

/// Disassembled program
#[derive(Debug)]
pub struct DisassembledProgram {
    /// Disassembled instructions
    pub instructions: Vec<String>,
    /// Function entry points
    pub functions: HashMap<String, usize>,
    /// Control flow graph
    pub cfg: Vec<(usize, usize)>, // (from, to)
    /// Memory access patterns
    pub memory_accesses: Vec<MemoryAccess>,
}

/// Memory access information
#[derive(Debug, Clone)]
pub struct MemoryAccess {
    /// Instruction offset
    pub offset: usize,
    /// Access type (read/write)
    pub access_type: AccessType,
    /// Memory address or offset
    pub address: usize,
    /// Size of access
    pub size: usize,
}

/// Memory access type
#[derive(Debug, Clone)]
pub enum AccessType {
    /// Read access
    Read,
    /// Write access
    Write,
}

/// Simple disassembler for BPF bytecode
fn disassemble(data: &[u8], base_addr: usize) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    let mut offset = 0;
    
    while offset + 8 <= data.len() {
        let opcode = data[offset] & 0x7f;
        let dst_reg = data[offset + 1] & 0x0f;
        let src_reg = (data[offset + 1] >> 4) & 0x0f;
        
        let imm = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        
        let addr = base_addr + offset;
        
        let insn_str = match opcode {
            opcodes::ADD32_IMM => format!("{:x}: add r{}, {}", addr, dst_reg, imm),
            opcodes::ADD32_REG => format!("{:x}: add r{}, r{}", addr, dst_reg, src_reg),
            opcodes::SUB32_IMM => format!("{:x}: sub r{}, {}", addr, dst_reg, imm),
            opcodes::SUB32_REG => format!("{:x}: sub r{}, r{}", addr, dst_reg, src_reg),
            opcodes::MUL32_IMM => format!("{:x}: mul r{}, {}", addr, dst_reg, imm),
            opcodes::MUL32_REG => format!("{:x}: mul r{}, r{}", addr, dst_reg, src_reg),
            opcodes::DIV32_IMM => format!("{:x}: div r{}, {}", addr, dst_reg, imm),
            opcodes::DIV32_REG => format!("{:x}: div r{}, r{}", addr, dst_reg, src_reg),
            opcodes::OR32_IMM => format!("{:x}: or r{}, {}", addr, dst_reg, imm),
            opcodes::OR32_REG => format!("{:x}: or r{}, r{}", addr, dst_reg, src_reg),
            opcodes::AND32_IMM => format!("{:x}: and r{}, {}", addr, dst_reg, imm),
            opcodes::AND32_REG => format!("{:x}: and r{}, r{}", addr, dst_reg, src_reg),
            opcodes::LSH32_IMM => format!("{:x}: lsh r{}, {}", addr, dst_reg, imm),
            opcodes::LSH32_REG => format!("{:x}: lsh r{}, r{}", addr, dst_reg, src_reg),
            opcodes::RSH32_IMM => format!("{:x}: rsh r{}, {}", addr, dst_reg, imm),
            opcodes::RSH32_REG => format!("{:x}: rsh r{}, r{}", addr, dst_reg, src_reg),
            opcodes::NEG32 => format!("{:x}: neg r{}", addr, dst_reg),
            opcodes::MOD32_IMM => format!("{:x}: mod r{}, {}", addr, dst_reg, imm),
            opcodes::MOD32_REG => format!("{:x}: mod r{}, r{}", addr, dst_reg, src_reg),
            opcodes::XOR32_IMM => format!("{:x}: xor r{}, {}", addr, dst_reg, imm),
            opcodes::XOR32_REG => format!("{:x}: xor r{}, r{}", addr, dst_reg, src_reg),
            opcodes::MOV32_IMM => format!("{:x}: mov r{}, {}", addr, dst_reg, imm),
            opcodes::MOV32_REG => format!("{:x}: mov r{}, r{}", addr, dst_reg, src_reg),
            opcodes::LDXW => format!("{:x}: ldxw r{}, [r{}+{}]", addr, dst_reg, src_reg, imm),
            opcodes::LDXH => format!("{:x}: ldxh r{}, [r{}+{}]", addr, dst_reg, src_reg, imm),
            opcodes::LDXB => format!("{:x}: ldxb r{}, [r{}+{}]", addr, dst_reg, src_reg, imm),
            opcodes::LDXDW => format!("{:x}: ldxdw r{}, [r{}+{}]", addr, dst_reg, src_reg, imm),
            opcodes::STW => format!("{:x}: stw [r{}+{}], r{}", addr, dst_reg, imm, src_reg),
            opcodes::STH => format!("{:x}: sth [r{}+{}], r{}", addr, dst_reg, imm, src_reg),
            opcodes::STB => format!("{:x}: stb [r{}+{}], r{}", addr, dst_reg, imm, src_reg),
            opcodes::STDW => format!("{:x}: stdw [r{}+{}], r{}", addr, dst_reg, imm, src_reg),
            opcodes::CALL => format!("{:x}: call {}", addr, imm),
            opcodes::EXIT => format!("{:x}: exit", addr),
            opcodes::JA => format!("{:x}: ja {}", addr, imm),
            opcodes::JEQ_IMM => format!("{:x}: jeq r{}, {}, {}", addr, dst_reg, imm, src_reg),
            opcodes::JEQ_REG => format!("{:x}: jeq r{}, r{}, {}", addr, dst_reg, src_reg, imm),
            opcodes::JGT_IMM => format!("{:x}: jgt r{}, {}, {}", addr, dst_reg, imm, src_reg),
            opcodes::JGT_REG => format!("{:x}: jgt r{}, r{}, {}", addr, dst_reg, src_reg, imm),
            opcodes::JGE_IMM => format!("{:x}: jge r{}, {}, {}", addr, dst_reg, imm, src_reg),
            opcodes::JGE_REG => format!("{:x}: jge r{}, r{}, {}", addr, dst_reg, src_reg, imm),
            opcodes::JLT_IMM => format!("{:x}: jlt r{}, {}, {}", addr, dst_reg, imm, src_reg),
            opcodes::JLT_REG => format!("{:x}: jlt r{}, r{}, {}", addr, dst_reg, src_reg, imm),
            opcodes::JLE_IMM => format!("{:x}: jle r{}, {}, {}", addr, dst_reg, imm, src_reg),
            opcodes::JLE_REG => format!("{:x}: jle r{}, r{}, {}", addr, dst_reg, src_reg, imm),
            opcodes::JSET_IMM => format!("{:x}: jset r{}, {}, {}", addr, dst_reg, imm, src_reg),
            opcodes::JSET_REG => format!("{:x}: jset r{}, r{}, {}", addr, dst_reg, src_reg, imm),
            opcodes::JNE_IMM => format!("{:x}: jne r{}, {}, {}", addr, dst_reg, imm, src_reg),
            opcodes::JNE_REG => format!("{:x}: jne r{}, r{}, {}", addr, dst_reg, src_reg, imm),
            _ => format!("{:x}: unknown opcode {:x}", addr, opcode),
        };
        
        result.push(insn_str);
        offset += 8;
    }
    
    Ok(result)
}

/// Disassemble a Solana program
pub fn disassemble_program(program_data: &[u8]) -> ExtractorResult<DisassembledProgram> {
    info!("Disassembling program...");
    
    // Use goblin crate to parse the ELF file
    let goblin_elf = match goblin::elf::Elf::parse(program_data) {
        Ok(elf) => elf,
        Err(e) => {
            warn!("Failed to parse ELF file with goblin: {}", e);
            return Err(ExtractorError::BytecodeAnalysis(
                format!("Failed to parse ELF file: {}", e)
            ));
        }
    };

    // Find the .text section
    let text_section_idx = goblin_elf.section_headers.iter()
        .position(|header| {
            goblin_elf.shdr_strtab.get_at(header.sh_name)
                .map(|name| name == ".text")
                .unwrap_or(false)
        })
        .ok_or_else(|| ExtractorError::BytecodeAnalysis("Failed to find .text section".to_string()))?;

    let text_section = &goblin_elf.section_headers[text_section_idx];
    let text_data = &program_data[text_section.sh_offset as usize..(text_section.sh_offset + text_section.sh_size) as usize];
    
    // Disassemble the text section
    let disassembled = match disassemble(text_data, text_section.sh_addr as usize) {
        Ok(disassembled) => disassembled,
        Err(e) => {
            warn!("Failed to disassemble program: {}", e);
            return Err(ExtractorError::BytecodeAnalysis(
                format!("Failed to disassemble program: {}", e)
            ));
        }
    };
    
    // Extract function entry points using the symbols from the ELF
    let functions = extract_function_entry_points(&disassembled, &goblin_elf);
    
    // Build control flow graph
    let cfg = build_control_flow_graph(&disassembled);
    
    // Analyze memory access patterns
    let memory_accesses = analyze_memory_accesses(&disassembled);
    
    Ok(DisassembledProgram {
        instructions: disassembled,
        functions,
        cfg,
        memory_accesses,
    })
}

/// Extract function entry points from disassembled code
fn extract_function_entry_points(
    disassembled: &[String],
    elf: &goblin::elf::Elf<'_>,
) -> HashMap<String, usize> {
    let mut functions = HashMap::new();
    
    // Access symbols directly from the symtab field
    for sym in &elf.syms {
        if sym.st_type() == goblin::elf::sym::STT_FUNC {
            // Get symbol name from strtab
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                let offset = sym.st_value as usize;
                
                // Find the corresponding instruction index
                for (i, insn) in disassembled.iter().enumerate() {
                    if insn.starts_with(&format!("{:x}:", offset)) {
                        functions.insert(name.to_string(), i);
                        break;
                    }
                }
            }
        }
    }
    
    // If no symbols found, try to identify functions heuristically
    if functions.is_empty() {
        for (i, insn) in disassembled.iter().enumerate() {
            // Look for function prologues (common patterns)
            if insn.contains("stw [r10-8], r6") || insn.contains("mov r6, r10") {
                // This is likely a function entry point
                functions.insert(format!("func_{:x}", i), i);
            }
        }
    }
    
    functions
}

/// Build a control flow graph from disassembled code
fn build_control_flow_graph(disassembled: &[String]) -> Vec<(usize, usize)> {
    let mut cfg = Vec::new();
    
    for (i, insn) in disassembled.iter().enumerate() {
        // Check if this is a branch instruction
        if insn.contains(" ja ") || insn.contains(" jeq ") || 
           insn.contains(" jne ") || insn.contains(" jlt ") ||
           insn.contains(" jle ") || insn.contains(" jgt ") ||
           insn.contains(" jge ") || insn.contains(" jset ") {
            
            // Extract the target address
            if let Some(target_str) = insn.split_whitespace().last() {
                if let Ok(offset) = target_str.parse::<isize>() {
                    let target = (i as isize + offset + 1) as usize;
                    if target < disassembled.len() {
                        cfg.push((i, target));
                    }
                }
            }
            
            // For conditional branches, also add the fall-through edge
            if !insn.contains(" ja ") && i + 1 < disassembled.len() {
                cfg.push((i, i + 1));
            }
        } else if !insn.contains(" exit ") && i + 1 < disassembled.len() {
            // Regular instruction, add fall-through edge
            cfg.push((i, i + 1));
        }
    }
    
    cfg
}

/// Analyze memory access patterns in disassembled code
fn analyze_memory_accesses(disassembled: &[String]) -> Vec<MemoryAccess> {
    let mut accesses = Vec::new();
    
    for (i, insn) in disassembled.iter().enumerate() {
        // Check for load instructions
        if insn.contains(" ldx") || insn.contains(" ldb") || 
           insn.contains(" ldh") || insn.contains(" ldw") || 
           insn.contains(" lddw") {
            
            // Extract memory address and size
            if let Some(addr_str) = insn.split('[').nth(1).and_then(|s| s.split(']').next()) {
                if let Ok(addr) = parse_address(addr_str) {
                    let size = if insn.contains(" ldb") {
                        1
                    } else if insn.contains(" ldh") {
                        2
                    } else if insn.contains(" ldw") {
                        4
                    } else if insn.contains(" lddw") {
                        8
                    } else {
                        4 // Default
                    };
                    
                    accesses.push(MemoryAccess {
                        offset: i,
                        access_type: AccessType::Read,
                        address: addr,
                        size,
                    });
                }
            }
        }
        
        // Check for store instructions
        if insn.contains(" stx") || insn.contains(" stb") || 
           insn.contains(" sth") || insn.contains(" stw") {
            
            // Extract memory address and size
            if let Some(addr_str) = insn.split('[').nth(1).and_then(|s| s.split(']').next()) {
                if let Ok(addr) = parse_address(addr_str) {
                    let size = if insn.contains(" stb") {
                        1
                    } else if insn.contains(" sth") {
                        2
                    } else if insn.contains(" stw") {
                        4
                    } else {
                        4 // Default
                    };
                    
                    accesses.push(MemoryAccess {
                        offset: i,
                        access_type: AccessType::Write,
                        address: addr,
                        size,
                    });
                }
            }
        }
    }
    
    accesses
}

/// Parse a memory address from a string
fn parse_address(addr_str: &str) -> Result<usize, ()> {
    // Handle different address formats
    if addr_str.contains('+') {
        // Format like "r1+16"
        let parts: Vec<&str> = addr_str.split('+').collect();
        if parts.len() == 2 {
            if let Ok(offset) = parts[1].trim().parse::<usize>() {
                return Ok(offset);
            }
        }
    } else if addr_str.contains('-') {
        // Format like "r10-8"
        let parts: Vec<&str> = addr_str.split('-').collect();
        if parts.len() == 2 {
            if let Ok(offset) = parts[1].trim().parse::<usize>() {
                return Ok(offset);
            }
        }
    } else {
        // Just a register, assume offset 0
        return Ok(0);
    }
    
    Err(())
}

/// Extract instructions from disassembled program
pub fn extract_instructions(
    disassembled: &DisassembledProgram,
    program_id: &str,
) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut seen_discriminators = HashSet::new();
    
    // Analyze each function
    for (name, entry_point) in &disassembled.functions {
        // Skip internal functions
        if name.starts_with("func_") {
            continue;
        }
        
        // Look for discriminator checks near the beginning of the function
        let discriminator = find_discriminator(disassembled, *entry_point);
        
        // Skip duplicate discriminators
        if let Some(disc) = discriminator {
            if seen_discriminators.contains(&disc) {
                continue;
            }
            seen_discriminators.insert(disc);
            
            // Create instruction
            let mut instruction = Instruction::new(
                name.clone(),
                disc
            );
            
            // Add arguments based on memory access patterns
            add_instruction_arguments(&mut instruction, disassembled, *entry_point);
            
            // Add accounts based on memory access patterns
            add_instruction_accounts(&mut instruction, disassembled, *entry_point);
            
            instructions.push(instruction);
        }
    }
    
    // If we couldn't find any instructions with discriminators,
    // try to create generic ones based on function entry points
    if instructions.is_empty() {
        for (i, (name, entry_point)) in disassembled.functions.iter().enumerate() {
            let mut instruction = Instruction::new(
                name.clone(),
                i as u8
            );
            
            // Add generic arguments and accounts
            instruction.add_arg("data".to_string(), "bytes".to_string());
            instruction.add_account("authority".to_string(), true, false, false);
            instruction.add_account("data".to_string(), false, true, false);
            
            instructions.push(instruction);
        }
    }
    
    instructions
}

/// Find discriminator check in a function
fn find_discriminator(disassembled: &DisassembledProgram, entry_point: usize) -> Option<u8> {
    // Look for discriminator checks in the first 20 instructions
    let end = std::cmp::min(entry_point + 20, disassembled.instructions.len());
    
    for i in entry_point..end {
        let insn = &disassembled.instructions[i];
        
        // Look for immediate comparison with a small value (likely a discriminator)
        if (insn.contains(" jeq ") || insn.contains(" jne ")) && insn.contains("r0, ") {
            // Extract the immediate value
            if let Some(imm_str) = insn.split("r0, ").nth(1).and_then(|s| s.split(',').next()) {
                if let Ok(imm) = imm_str.trim().parse::<u8>() {
                    return Some(imm);
                }
            }
        }
    }
    
    None
}

/// Add arguments to an instruction based on memory access patterns
fn add_instruction_arguments(
    instruction: &mut Instruction,
    disassembled: &DisassembledProgram,
    entry_point: usize,
) {
    // Look for memory accesses after the discriminator check
    let mut data_offsets = HashSet::new();
    
    for access in &disassembled.memory_accesses {
        if access.offset > entry_point && 
           matches!(access.access_type, AccessType::Read) {
            data_offsets.insert(access.address);
        }
    }
    
    // Create arguments based on unique data offsets
    for (i, offset) in data_offsets.iter().enumerate() {
        // Determine argument type based on access size
        let arg_type = if let Some(access) = disassembled.memory_accesses.iter()
            .find(|a| a.address == *offset) {
            match access.size {
                1 => "u8".to_string(),
                2 => "u16".to_string(),
                4 => "u32".to_string(),
                8 => "u64".to_string(),
                _ => "bytes".to_string(),
            }
        } else {
            "bytes".to_string()
        };
        
        instruction.add_arg(format!("arg_{}", i), arg_type);
    }
    
    // If no arguments were found, add a generic one
    if instruction.args.is_empty() {
        instruction.add_arg("data".to_string(), "bytes".to_string());
    }
}

/// Add accounts to an instruction based on memory access patterns
fn add_instruction_accounts(
    instruction: &mut Instruction,
    disassembled: &DisassembledProgram,
    entry_point: usize,
) {
    // Look for account loading patterns
    let mut has_authority = false;
    let mut has_data = false;
    
    // Check for syscalls that indicate account usage
    for i in entry_point..disassembled.instructions.len() {
        let insn = &disassembled.instructions[i];
        
        if insn.contains("syscall AccountInformation") {
            // This indicates account access
            has_data = true;
        } else if insn.contains("syscall SignatureVerification") {
            // This indicates signer verification
            has_authority = true;
        }
    }
    
    // Add accounts based on detected patterns
    if has_authority {
        instruction.add_account("authority".to_string(), true, false, false);
    }
    
    if has_data {
        instruction.add_account("data".to_string(), false, true, false);
    }
    
    // If no accounts were found, add generic ones
    if instruction.accounts.is_empty() {
        instruction.add_account("authority".to_string(), true, false, false);
        instruction.add_account("data".to_string(), false, true, false);
    }
}

/// Extract accounts from disassembled program
pub fn extract_accounts(
    disassembled: &DisassembledProgram,
    program_id: &str,
) -> Vec<Account> {
    let mut accounts = Vec::new();
    
    // Look for account structure patterns
    let mut account_fields = HashMap::new();
    
    // Analyze memory access patterns to identify account fields
    for access in &disassembled.memory_accesses {
        if matches!(access.access_type, AccessType::Read) {
            // This might be a field access
            account_fields.entry(access.address)
                .or_insert_with(Vec::new)
                .push((access.size, access.offset));
        }
    }
    
    // Create accounts based on field patterns
    let mut account_addresses = HashSet::new();
    for (addr, accesses) in &account_fields {
        // Skip if this doesn't look like an account (too few accesses)
        if accesses.len() < 2 {
            continue;
        }
        
        // Create a new account
        let account_name = format!("Account_{:x}", addr);
        if account_addresses.contains(&account_name) {
            continue;
        }
        account_addresses.insert(account_name.clone());
        
        let mut account = Account::new(account_name, "account".to_string());
        
        // Add fields based on access patterns
        let mut field_offsets = HashSet::new();
        for (size, _) in accesses {
            field_offsets.insert(*size);
        }
        
        for (i, size) in field_offsets.iter().enumerate() {
            let field_type = match size {
                1 => "u8".to_string(),
                2 => "u16".to_string(),
                4 => "u32".to_string(),
                8 => "u64".to_string(),
                _ => "bytes".to_string(),
            };
            
            account.add_field(format!("field_{}", i), field_type, *addr);
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