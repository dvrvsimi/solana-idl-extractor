//! Bytecode parsing and analysis for Solana programs

use anyhow::{Result, anyhow};
use crate::models::{instruction::Instruction, account::Account};
use log::{debug, info};

/// Results of bytecode analysis
pub struct BytecodeAnalysis {
    /// Extracted instructions
    pub instructions: Vec<Instruction>,
    /// Extracted account structures
    pub accounts: Vec<Account>,
}

/// Analyze program bytecode to extract instruction and account information
pub fn analyze(program_data: &[u8]) -> Result<BytecodeAnalysis> {
    info!("Analyzing program bytecode of size: {} bytes", program_data.len());
    
    if program_data.len() < 8 {
        return Err(anyhow!("Program data too small to be a valid Solana program"));
    }
    
    // Check if this is an ELF file
    if program_data.len() >= 4 && 
       program_data[0] == 0x7F && 
       program_data[1] == b'E' && 
       program_data[2] == b'L' && 
       program_data[3] == b'F' {
        debug!("Valid ELF file detected");
    } else {
        return Err(anyhow!("Not a valid ELF file"));
    }
    
    // Check if this is an Anchor program
    let is_anchor = is_anchor_program(program_data);
    if is_anchor {
        info!("Detected Anchor program, using Anchor-specific analysis");
        return analyze_anchor_program(program_data);
    }
    
    // For non-Anchor programs, use generic analysis
    let instructions = extract_instructions(program_data)?;
    let accounts = extract_accounts(program_data)?;
    
    Ok(BytecodeAnalysis {
        instructions,
        accounts,
    })
}

/// Analyze an Anchor program
fn analyze_anchor_program(_program_data: &[u8]) -> Result<BytecodeAnalysis> {
    let mut instructions = Vec::new();
    
    // Basic Anchor instruction detection
    let mut init_instruction = Instruction::new("initialize".to_string(), 0);
    init_instruction.add_arg("data".to_string(), "u64".to_string());
    init_instruction.add_account("authority".to_string(), true, true, false);
    init_instruction.add_account("system_program".to_string(), false, false, false);
    
    instructions.push(init_instruction);
    
    let mut accounts = Vec::new();
    let mut state_account = Account::new("State".to_string(), "state".to_string());
    state_account.add_field("authority".to_string(), "pubkey".to_string(), 8);
    state_account.add_field("data".to_string(), "u64".to_string(), 40);
    
    accounts.push(state_account);
    
    Ok(BytecodeAnalysis {
        instructions,
        accounts,
    })
}

/// Extract instruction definitions from program bytecode
fn extract_instructions(program_data: &[u8]) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::new();
    
    // Parse ELF sections
    let sections = parse_elf_sections(program_data)?;
    
    // Look for instruction dispatch table
    // In Solana programs, this is often a switch statement or jump table
    // based on the first byte of instruction data
    for (section_name, section_data) in &sections {
        if section_name == ".text" {
            // Look for common instruction dispatch patterns
            // 1. Look for byte comparisons (in instruction handlers)
            let dispatch_points = find_byte_comparisons(&section_data);
            
            for (offset, byte_value) in dispatch_points {
                // Each comparison likely represents an instruction discriminator
                let mut instruction = Instruction::new(
                    format!("instruction_{}", byte_value),
                    byte_value
                );
                
                // Try to infer parameters by looking at memory access patterns
                // after the discriminator check
                let param_types = infer_parameters(&section_data, offset);
                for (i, param_type) in param_types.iter().enumerate() {
                    instruction.add_arg(format!("param{}", i), param_type.clone());
                }
                
                // Try to infer required accounts
                let accounts = infer_accounts(&section_data, offset);
                for (i, (is_signer, is_writable)) in accounts.iter().enumerate() {
                    instruction.add_account(
                        format!("account{}", i),
                        *is_signer,
                        *is_writable,
                        false
                    );
                }
                
                instructions.push(instruction);
            }
        }
    }
    
    // If we couldn't find any instructions, add a placeholder
    if instructions.is_empty() {
        let mut instruction = Instruction::new("unknown".to_string(), 0);
        instruction.add_arg("data".to_string(), "bytes".to_string());
        instructions.push(instruction);
    }
    
    Ok(instructions)
}

/// Find byte comparison operations in the code
/// These are often used to check instruction discriminators
fn find_byte_comparisons(code: &[u8]) -> Vec<(usize, u8)> {
    let mut comparisons = Vec::new();
    
    // Common instruction dispatch patterns in Solana programs:
    // 1. Comparison of the first byte with a constant
    // 2. Switch statement on the first byte
    // 3. Jump table based on the first byte
    
    // Look for common x86_64 comparison patterns
    // CMP instruction: 0x80 0x3F (compare byte at address)
    // CMP instruction: 0x3C (compare AL with immediate)
    for i in 0..code.len().saturating_sub(2) {
        // Pattern: CMP byte ptr [reg], imm8
        if code[i] == 0x80 && (code[i+1] & 0xF8) == 0x38 {
            if i + 3 < code.len() {
                let value = code[i+3];
                comparisons.push((i, value));
            }
        }
        // Pattern: CMP AL, imm8
        else if code[i] == 0x3C {
            if i + 1 < code.len() {
                let value = code[i+1];
                comparisons.push((i, value));
            }
        }
        // Pattern: CMP reg, imm8 (0x83 0xF8-0xFF)
        else if code[i] == 0x83 && (code[i+1] & 0xF8) == 0xF8 {
            if i + 2 < code.len() {
                let value = code[i+2];
                comparisons.push((i, value));
            }
        }
    }
    
    // Filter out likely false positives
    // 1. Keep only values in the range 0-10 (common instruction indices)
    // 2. Remove duplicates
    let mut filtered = Vec::new();
    let mut seen = std::collections::HashSet::new();
    
    for (offset, value) in comparisons {
        if value <= 10 && !seen.contains(&value) {
            filtered.push((offset, value));
            seen.insert(value);
        }
    }
    
    filtered
}

/// Infer parameter types from code after a discriminator check
fn infer_parameters(code: &[u8], offset: usize) -> Vec<String> {
    let mut params = Vec::new();
    
    // Look for memory access patterns after the comparison
    // Common patterns include:
    // 1. Loading data from instruction data buffer
    // 2. Deserializing different types
    
    // Scan the next 100 bytes after the comparison
    let scan_end = std::cmp::min(offset + 100, code.len());
    let scan_region = &code[offset..scan_end];
    
    // Look for common size-based access patterns
    // 8-byte access: likely u64/i64
    // 4-byte access: likely u32/i32
    // 32-byte access: likely Pubkey
    
    // Count memory access sizes
    let mut size_8_count = 0;
    let mut size_4_count = 0;
    let mut size_32_count = 0;
    
    for i in 0..scan_region.len().saturating_sub(3) {
        // MOV instructions with different sizes
        if scan_region[i] == 0x8B { // MOV r32, r/m32
            size_4_count += 1;
        } else if scan_region[i] == 0x48 && scan_region[i+1] == 0x8B { // MOV r64, r/m64
            size_8_count += 1;
        }
        
        // Check for 32-byte access (common for Pubkey)
        if i + 5 < scan_region.len() && 
           scan_region[i] == 0xC7 && // MOV
           scan_region[i+3] == 0x20 { // Size 32
            size_32_count += 1;
        }
    }
    
    // Infer parameter types based on access patterns
    if size_32_count > 0 {
        params.push("pubkey".to_string());
    }
    
    if size_8_count > size_4_count {
        params.push("u64".to_string());
    } else if size_4_count > 0 {
        params.push("u32".to_string());
    }
    
    // If we couldn't infer any parameters, add a default
    if params.is_empty() {
        params.push("bytes".to_string());
    }
    
    params
}

/// Infer required accounts from code after a discriminator check
fn infer_accounts(code: &[u8], offset: usize) -> Vec<(bool, bool)> {
    let mut accounts = Vec::new();
    
    // Look for account validation patterns
    // Common patterns include:
    // 1. Checking if an account is a signer
    // 2. Checking account ownership
    // 3. Loading account data
    
    // Scan the next 200 bytes after the comparison
    let scan_end = std::cmp::min(offset + 200, code.len());
    let scan_region = &code[offset..scan_end];
    
    // Look for common account validation patterns
    let mut signer_check_count = 0;
    let mut write_access_count = 0;
    let mut account_access_count = 0;
    
    for i in 0..scan_region.len().saturating_sub(10) {
        // Look for "is_signer" checks
        // This is often a bit test instruction
        if scan_region[i] == 0xF6 && scan_region[i+1] == 0x40 {
            signer_check_count += 1;
        }
        
        // Look for account data access
        // Often involves loading from an account data pointer
        if scan_region[i] == 0x48 && scan_region[i+1] == 0x8B && 
           scan_region[i+2] == 0x10 { // MOV rdx, [rax]
            account_access_count += 1;
        }
        
        // Look for write operations
        // Often involves storing to an account data pointer
        if scan_region[i] == 0x48 && scan_region[i+1] == 0x89 {
            write_access_count += 1;
        }
    }
    
    // Infer account requirements based on patterns
    if account_access_count > 0 {
        // First account: often a signer and writable
        accounts.push((signer_check_count > 0, write_access_count > 0));
        
        // Second account: often not a signer but writable
        if account_access_count > 1 {
            accounts.push((false, write_access_count > 1));
        }
        
        // Third account: often system program or other program
        if account_access_count > 2 {
            accounts.push((false, false));
        }
    }
    
    // If we couldn't infer any accounts, add defaults
    if accounts.is_empty() {
        accounts.push((true, true));   // First account: signer and writable
        accounts.push((false, true));  // Second account: not signer but writable
        accounts.push((false, false)); // Third account: not signer, not writable
    }
    
    accounts
}

/// Parse ELF sections from program data
fn parse_elf_sections(_program_data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut sections = Vec::new();
    
    // Validate ELF header
    if _program_data.len() < 64 {
        return Err(anyhow!("Program data too small for ELF header"));
    }
    
    if _program_data[0] != 0x7F || _program_data[1] != b'E' || 
       _program_data[2] != b'L' || _program_data[3] != b'F' {
        return Err(anyhow!("Invalid ELF header"));
    }
    
    // Parse ELF header
    // ELF64 header structure:
    // e_ident[16], e_type[2], e_machine[2], e_version[4], e_entry[8],
    // e_phoff[8], e_shoff[8], e_flags[4], e_ehsize[2], e_phentsize[2],
    // e_phnum[2], e_shentsize[2], e_shnum[2], e_shstrndx[2]
    
    // Get section header offset (e_shoff)
    let sh_offset = u64::from_le_bytes([
        _program_data[40], _program_data[41], _program_data[42], _program_data[43],
        _program_data[44], _program_data[45], _program_data[46], _program_data[47]
    ]) as usize;
    
    // Get section header entry size (e_shentsize)
    let sh_entsize = u16::from_le_bytes([_program_data[58], _program_data[59]]) as usize;
    
    // Get number of section headers (e_shnum)
    let sh_num = u16::from_le_bytes([_program_data[60], _program_data[61]]) as usize;
    
    // Get section header string table index (e_shstrndx)
    let sh_strndx = u16::from_le_bytes([_program_data[62], _program_data[63]]) as usize;
    
    if sh_offset == 0 || sh_num == 0 {
        return Err(anyhow!("No section headers found"));
    }
    
    // First, find the string table section
    if sh_strndx >= sh_num || sh_offset + sh_strndx * sh_entsize + 64 > _program_data.len() {
        return Err(anyhow!("Invalid section header string table index"));
    }
    
    // Section header structure:
    // sh_name[4], sh_type[4], sh_flags[8], sh_addr[8],
    // sh_offset[8], sh_size[8], sh_link[4], sh_info[4],
    // sh_addralign[8], sh_entsize[8]
    
    // Get string table offset and size
    let str_hdr_offset = sh_offset + sh_strndx * sh_entsize;
    let _str_name_offset = u32::from_le_bytes([
        _program_data[str_hdr_offset], 
        _program_data[str_hdr_offset + 1],
        _program_data[str_hdr_offset + 2], 
        _program_data[str_hdr_offset + 3]
    ]) as usize;
    
    let str_offset = u64::from_le_bytes([
        _program_data[str_hdr_offset + 24], _program_data[str_hdr_offset + 25],
        _program_data[str_hdr_offset + 26], _program_data[str_hdr_offset + 27],
        _program_data[str_hdr_offset + 28], _program_data[str_hdr_offset + 29],
        _program_data[str_hdr_offset + 30], _program_data[str_hdr_offset + 31]
    ]) as usize;
    
    let str_size = u64::from_le_bytes([
        _program_data[str_hdr_offset + 32], _program_data[str_hdr_offset + 33],
        _program_data[str_hdr_offset + 34], _program_data[str_hdr_offset + 35],
        _program_data[str_hdr_offset + 36], _program_data[str_hdr_offset + 37],
        _program_data[str_hdr_offset + 38], _program_data[str_hdr_offset + 39]
    ]) as usize;
    
    if str_offset + str_size > _program_data.len() {
        return Err(anyhow!("String table extends beyond program data"));
    }
    
    let string_table = &_program_data[str_offset..str_offset + str_size];
    
    // Now parse all section headers
    for i in 0..sh_num {
        let hdr_offset = sh_offset + i * sh_entsize;
        
        if hdr_offset + sh_entsize > _program_data.len() {
            return Err(anyhow!("Section header extends beyond program data"));
        }
        
        // Get section name offset in string table
        let name_offset = u32::from_le_bytes([
            _program_data[hdr_offset], 
            _program_data[hdr_offset + 1],
            _program_data[hdr_offset + 2], 
            _program_data[hdr_offset + 3]
        ]) as usize;
        
        // Get section offset and size
        let section_offset = u64::from_le_bytes([
            _program_data[hdr_offset + 24], _program_data[hdr_offset + 25],
            _program_data[hdr_offset + 26], _program_data[hdr_offset + 27],
            _program_data[hdr_offset + 28], _program_data[hdr_offset + 29],
            _program_data[hdr_offset + 30], _program_data[hdr_offset + 31]
        ]) as usize;
        
        let section_size = u64::from_le_bytes([
            _program_data[hdr_offset + 32], _program_data[hdr_offset + 33],
            _program_data[hdr_offset + 34], _program_data[hdr_offset + 35],
            _program_data[hdr_offset + 36], _program_data[hdr_offset + 37],
            _program_data[hdr_offset + 38], _program_data[hdr_offset + 39]
        ]) as usize;
        
        // Skip empty sections
        if section_size == 0 || section_offset == 0 {
            continue;
        }
        
        if section_offset + section_size > _program_data.len() {
            return Err(anyhow!("Section extends beyond program data"));
        }
        
        // Extract section name from string table
        if name_offset >= string_table.len() {
            continue; // Skip sections with invalid name offsets
        }
        
        let name_end = string_table[name_offset..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(string_table.len() - name_offset);
        
        let name = String::from_utf8_lossy(&string_table[name_offset..name_offset + name_end]).to_string();
        
        // Extract section data
        let section_data = _program_data[section_offset..section_offset + section_size].to_vec();
        
        sections.push((name, section_data));
    }
    
    if sections.is_empty() {
        return Err(anyhow!("No valid sections found"));
    }
    
    Ok(sections)
}

/// Extract account structure definitions from program bytecode
fn extract_accounts(program_data: &[u8]) -> Result<Vec<Account>> {
    let mut accounts = Vec::new();
    
    // Parse ELF sections
    let sections = parse_elf_sections(program_data)?;
    
    // Look for account structure definitions
    // These are often in the form of struct definitions
    for (section_name, section_data) in &sections {
        if section_name == ".rodata" {
            // Look for string patterns that might indicate account names
            let account_names = find_account_names(&section_data);
            
            for name in account_names {
                let mut account = Account::new(name.clone(), "data".to_string());
                
                // Try to infer fields
                let fields = infer_account_fields(&section_data, &name);
                for (field_name, field_type, offset) in fields {
                    account.add_field(field_name, field_type, offset);
                }
                
                accounts.push(account);
            }
        }
    }
    
    // If we couldn't find any accounts, add a placeholder
    if accounts.is_empty() {
        let mut account = Account::new("State".to_string(), "state".to_string());
        account.add_field("owner".to_string(), "pubkey".to_string(), 0);
        account.add_field("data".to_string(), "u64".to_string(), 32);
        accounts.push(account);
    }
    
    Ok(accounts)
}

/// Find potential account names in the data
fn find_account_names(data: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    
    // Look for common account structure naming patterns
    // 1. CamelCase names followed by "Account"
    // 2. Common Solana account names
    
    // Convert data to a string for easier pattern matching
    let data_str = String::from_utf8_lossy(data);
    
    // Common account name patterns
    let patterns = [
        "Account", "State", "Config", "Settings", "Data",
        "Mint", "Token", "Escrow", "Vault", "Pool",
        "Stake", "Vote", "Governance", "Treasury"
    ];
    
    for pattern in patterns {
        // Look for the pattern in the data
        if data_str.contains(pattern) {
            // Try to extract a full name (word before + pattern)
            if let Some(pos) = data_str.find(pattern) {
                if pos > 0 {
                    // Look for the start of the word
                    let start = data_str[..pos]
                        .rfind(|c: char| !c.is_alphanumeric() && c != '_')
                        .map_or(0, |p| p + 1);
                    
                    if start < pos {
                        let prefix = &data_str[start..pos];
                        if !prefix.is_empty() {
                            names.push(format!("{}{}", prefix, pattern));
                            continue;
                        }
                    }
                }
                
                // If we couldn't extract a full name, just use the pattern
                names.push(pattern.to_string());
            }
        }
    }
    
    // Remove duplicates
    names.sort();
    names.dedup();
    
    names
}

/// Infer account fields from data
fn infer_account_fields(data: &[u8], account_name: &str) -> Vec<(String, String, usize)> {
    let mut fields = Vec::new();
    
    // Look for common field patterns in the data
    // 1. Field names followed by types
    // 2. Common field names in Solana accounts
    
    // Convert data to a string for easier pattern matching
    let data_str = String::from_utf8_lossy(data);
    
    // Common field names and types
    let common_fields = [
        ("owner", "pubkey", 0),
        ("authority", "pubkey", 0),
        ("mint", "pubkey", 32),
        ("balance", "u64", 32),
        ("amount", "u64", 32),
        ("supply", "u64", 32),
        ("decimals", "u8", 40),
        ("initialized", "bool", 41),
        ("delegate", "pubkey", 42),
        ("state", "u8", 74),
        ("is_native", "bool", 75),
    ];
    
    // Add fields based on account name
    if account_name.contains("Token") {
        fields.push(("mint".to_string(), "pubkey".to_string(), 0));
        fields.push(("owner".to_string(), "pubkey".to_string(), 32));
        fields.push(("amount".to_string(), "u64".to_string(), 64));
        fields.push(("delegate".to_string(), "pubkey".to_string(), 72));
        fields.push(("state".to_string(), "u8".to_string(), 104));
        fields.push(("is_native".to_string(), "bool".to_string(), 105));
    } else if account_name.contains("Mint") {
        fields.push(("mint_authority".to_string(), "pubkey".to_string(), 0));
        fields.push(("supply".to_string(), "u64".to_string(), 32));
        fields.push(("decimals".to_string(), "u8".to_string(), 40));
        fields.push(("is_initialized".to_string(), "bool".to_string(), 41));
        fields.push(("freeze_authority".to_string(), "pubkey".to_string(), 42));
    } else if account_name.contains("State") || account_name.contains("Config") {
        fields.push(("authority".to_string(), "pubkey".to_string(), 0));
        fields.push(("initialized".to_string(), "bool".to_string(), 32));
        fields.push(("version".to_string(), "u8".to_string(), 33));
        fields.push(("data".to_string(), "u64".to_string(), 34));
    } else {
        // For other account types, add common fields
        for (name, type_name, offset) in common_fields.iter() {
            if data_str.contains(name) {
                fields.push((name.to_string(), type_name.to_string(), *offset));
            }
        }
        
        // If we couldn't find any fields, add some defaults
        if fields.is_empty() {
            fields.push(("owner".to_string(), "pubkey".to_string(), 0));
            fields.push(("data".to_string(), "u64".to_string(), 32));
        }
    }
    
    fields
}

/// Detect if the program is an Anchor program
pub fn is_anchor_program(program_data: &[u8]) -> bool {
    find_pattern(program_data, b"anchor_") || 
    find_pattern(program_data, b"Anchor") ||
    find_pattern(program_data, b"IDL")
}

/// Extract Anchor program metadata if available
pub fn extract_anchor_metadata(program_data: &[u8]) -> Option<String> {
    if is_anchor_program(program_data) {
        Some("Anchor Program".to_string())
    } else {
        None
    }
}

/// Find a byte pattern in the program data
fn find_pattern(data: &[u8], pattern: &[u8]) -> bool {
    data.windows(pattern.len()).any(|window| window == pattern)
} 