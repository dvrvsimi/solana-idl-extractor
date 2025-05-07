//! Bytecode analysis for Solana programs
//!
//! This module provides functionality to analyze Solana program bytecode
//! and extract an IDL (Interface Description Language) representation.
//! It supports both Anchor and native Solana programs.

pub mod parser;
pub mod elf;
pub mod pattern;
pub mod account_analyzer;
pub mod cfg;
pub mod discriminator_detection;
pub mod dynamic_analysis;
pub mod disassembler;
pub mod instruction_analyzer;
pub mod error_analyzer;
pub mod string_analyzer;

// Re-export key components
use self::parser::{SbfInstruction, parse_instructions};
pub use elf::ElfAnalyzer;
pub use account_analyzer::extract_account_structures;
pub use cfg::{BasicBlock, Function, build_cfg};
pub use discriminator_detection::{AnchorDiscriminator, DiscriminatorKind, extract_discriminators};
pub use disassembler::{disassemble_program, DisassembledProgram};
pub use string_analyzer::analyze_strings;

use anyhow::{Result, Context, anyhow};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::collections::HashSet;

use crate::models::instruction::Instruction;
use crate::models::account::Account;
use crate::analyzer::bytecode::disassembler::AccessType;
use crate::analyzer::anchor::is_anchor_program;
use solana_pubkey::Pubkey;
use crate::errors::{ExtractorError, ExtractorResult, ErrorContext};



/// Results of bytecode analysis 
///
/// This struct contains all information extracted from a Solana program's bytecode,
/// including instructions, accounts, and error codes.
///
/// # Examples
///
/// ```
/// # use solana_idl_extractor::analyzer::bytecode::BytecodeAnalysis;
/// # let analysis = BytecodeAnalysis::default();
/// println!("Found {} instructions", analysis.instructions.len());
/// ```
#[derive(Debug, Clone)]
pub struct BytecodeAnalysis {
    /// Extracted instructions
    pub instructions: Vec<Instruction>,
    /// Extracted accounts
    pub accounts: Vec<Account>,
    /// Error codes
    pub error_codes: HashMap<u32, String>,
    /// Is this an Anchor program?
    pub is_anchor: bool,
    /// Disassembled program (if available)
    pub disassembled: Option<DisassembledProgram>,
}

impl Clone for DisassembledProgram {
    fn clone(&self) -> Self {
        Self {
            instructions: self.instructions.clone(),
            functions: self.functions.clone(),
            cfg: self.cfg.clone(),
            memory_accesses: self.memory_accesses.clone(),
        }
    }
}

impl Default for BytecodeAnalysis {
    fn default() -> Self {
        Self {
            instructions: Vec::new(),
            accounts: Vec::new(),
            error_codes: HashMap::new(),
            is_anchor: false,
            disassembled: None,
        }
    }
}

/// Analyze program bytecode to extract an IDL
///
/// This is the main entry point for bytecode analysis. It orchestrates
/// the various analysis steps and combines their results.
///
/// # Arguments
///
/// * `program_data` - The program's ELF binary data
/// * `program_id` - The program's ID as a string
///
/// # Returns
///
/// A result containing the bytecode analysis or an error
pub fn analyze(program_data: &[u8], program_id: &str) -> Result<BytecodeAnalysis> {
    info!("Analyzing program bytecode for {}", program_id);

    // program_data is now always the correct ELF bytes!
    let elf_bytes = program_data;
    log::info!("First 16 bytes of ELF: {:02x?}", &elf_bytes[..16.min(elf_bytes.len())]);
    let elf_parser = elf::ElfAnalyzer::from_bytes(elf_bytes.to_vec())
        .context("Failed to parse ELF file")?;

    // Use improved string analysis
    let string_analysis = improved_string_analyzer(elf_bytes)?;

    // Determine if this is an Anchor program
    let is_anchor = is_anchor_program(elf_bytes);
    info!("Program type: {}", if is_anchor { "Anchor" } else { "Native" });

    // Extract instruction boundaries
    let boundaries = extract_instruction_boundaries(&elf_parser)
        .context("Failed to extract instruction boundaries")?;

    // Extract instructions based on program type
    let instructions = if is_anchor {
        extract_anchor_instructions(elf_bytes, &boundaries, &string_analysis)
            .context("Failed to extract Anchor instructions")?
    } else {
        extract_native_instructions(elf_bytes, &boundaries, &string_analysis)
            .context("Failed to extract native instructions")?
    };

    // Extract accounts
    let elf_parser = elf::ElfAnalyzer::from_bytes(elf_bytes.to_vec())?;
    let text_section = elf_parser.get_text_section()?
        .ok_or_else(|| anyhow!("No text section found in program"))?;
    let parsed_instructions = parse_instructions(&text_section.data, text_section.address as usize)?;

    // Use account_analyzer directly instead of the extract_accounts wrapper
    let discriminators = if is_anchor {
        discriminator_detection::extract_discriminators(elf_bytes)?
    } else {
        Vec::new()
    };

    let accounts = account_analyzer::extract_account_structures(
        elf_bytes,
        &parsed_instructions,
        &discriminators
    ).context("Failed to extract accounts")?;

    // Extract error codes
    let error_codes = extract_error_codes(elf_bytes)
        .context("Failed to extract error codes")?;

    Ok(BytecodeAnalysis {
        instructions,
        accounts,
        error_codes,
        is_anchor,
        disassembled: None,
    })
}

/// Extract string constants from an ELF analyzer
fn extract_string_constants(elf_analyzer: &elf::ElfAnalyzer) -> Result<Vec<String>> {
    elf_analyzer.extract_strings()
}

/// Enhanced string analysis for better naming accuracy
pub fn enhanced_string_analysis(program_data: &[u8]) -> Result<HashMap<String, f64>> {
    // Get strings from the program
    let elf_analyzer = elf::ElfAnalyzer::from_bytes(program_data.to_vec())?;
    let string_constants = elf_analyzer.extract_strings()?;
    
    let mut name_scores = HashMap::new();
    
    // 1. Score strings based on naming conventions
    for string in &string_constants {
        let mut score = 0.0;
        
        // Prefer camelCase or snake_case names (common in Solana programs)
        if string.chars().any(|c| c.is_lowercase()) && string.chars().any(|c| c.is_uppercase()) {
            // Likely camelCase
            score += 0.5;
        } else if string.contains('_') {
            // Likely snake_case
            score += 0.4;
        }
        
        // Prefer strings that look like instruction names
        if string.starts_with("initialize") || 
           string.starts_with("create") || 
           string.starts_with("update") || 
           string.starts_with("delete") || 
           string.starts_with("process") ||
           string.starts_with("transfer") ||
           string.starts_with("mint") ||
           string.starts_with("burn") {
            score += 0.8;
        }
        
        // Penalize strings that are likely error messages
        if string.contains("error") || 
           string.contains("failed") || 
           string.contains("invalid") ||
           string.contains("expected") {
            score -= 0.7;
        }
        
        // Penalize overly long strings
        if string.len() > 30 {
            score -= 0.3;
        }
        
        // Penalize strings with special characters (except underscores)
        if string.chars().any(|c| !c.is_alphanumeric() && c != '_') {
            score -= 0.2;
        }
        
        // Only include strings with positive scores
        if score > 0.0 {
            name_scores.insert(string.clone(), score);
        }
    }
    
    Ok(name_scores)
}

/// Analyze string references in the code to find instruction names
pub fn analyze_instruction_strings(
    instructions: &[parser::SbfInstruction],
    string_constants: &[(usize, String)]
) -> HashMap<String, f64> {
    let mut instruction_names = HashMap::new();
    
    // Look for string loading patterns
    for window in instructions.windows(3) {
        // Common pattern: load address, then reference string
        if window[0].is_load_imm() && window[0].imm > 0 {
            let potential_addr = window[0].imm as usize;
            
            // Check if this address corresponds to a string constant
            for (addr, string) in string_constants {
                if *addr == potential_addr || (*addr >= potential_addr && *addr < potential_addr + 100) {
                    // This instruction is likely loading a string reference
                    
                    // Score the string as a potential instruction name
                    let mut score = 0.5;  // Base score
                    
                    // Check if the next instructions use this string in a meaningful way
                    if window[1].dst_reg == window[0].dst_reg || window[2].dst_reg == window[0].dst_reg {
                        score += 0.3;  // String is used in subsequent instructions
                    }
                    
                    // Check if the string looks like an instruction name
                    let lower_string = string.to_lowercase();
                    if lower_string.contains("instruction") || 
                       lower_string.contains("command") ||
                       lower_string.contains("action") {
                        score += 0.4;
                    }
                    
                    // Check for common instruction name patterns
                    if lower_string.starts_with("initialize") || 
                       lower_string.starts_with("create") || 
                       lower_string.starts_with("update") || 
                       lower_string.starts_with("delete") || 
                       lower_string.starts_with("process") {
                        score += 0.6;
                    }
                    
                    // Store the score for this potential instruction name
                    instruction_names.insert(string.clone(), score);
                }
            }
        }
    }
    
    instruction_names
}

/// Context-aware string analysis that considers code structure
pub fn context_aware_string_analysis(
    program_data: &[u8],
    functions: &[cfg::Function],
    blocks: &[cfg::BasicBlock],
    string_constants: &[(usize, String)]
) -> HashMap<String, f64> {
    let mut name_scores = HashMap::new();
    
    // Analyze each function
    for function in functions {
        // Skip functions without names
        if let Some(name) = &function.name {
            // Score the function name
            let mut score = 0.6;  // Base score for function names
            
            // Check if this looks like an instruction handler
            let lower_name = name.to_lowercase();
            if lower_name.contains("process") || 
               lower_name.contains("handle") || 
               lower_name.contains("instruction") ||
               lower_name.contains("command") {
                score += 0.4;
            }
            
            // Check for common instruction name patterns
            if lower_name.starts_with("initialize") || 
               lower_name.starts_with("create") || 
               lower_name.starts_with("update") || 
               lower_name.starts_with("delete") || 
               lower_name.starts_with("process") {
                score += 0.3;
            }
            
            // Store the score
            name_scores.insert(name.clone(), score);
        }
        
        // Analyze string references within this function
        let entry_block = &blocks[function.entry_block];
        for insn_idx in 0..entry_block.instructions.len() {
            // Skip if out of bounds
            if insn_idx >= program_data.len() {
                continue;
            }
            
            // Look for string references near the function entry
            for (addr, string) in string_constants {
                let addr_usize = *addr;
                
                if addr_usize >= insn_idx && addr_usize < insn_idx + 100 {
                    // This string is referenced near the function entry
                    
                    // Score the string
                    let mut score = 0.4;  // Base score
                    
                    // Check if the string looks like an instruction name
                    let lower_string = string.to_lowercase();
                    if lower_string.contains("instruction") || 
                       lower_string.contains("command") ||
                       lower_string.contains("action") {
                        score += 0.3;
                    }
                    
                    // Check for common instruction name patterns
                    if lower_string.starts_with("initialize") || 
                       lower_string.starts_with("create") || 
                       lower_string.starts_with("update") || 
                       lower_string.starts_with("delete") || 
                       lower_string.starts_with("process") {
                        score += 0.5;
                    }
                    
                    // Store the score
                    name_scores.insert(string.clone(), score);
                }
            }
        }
    }
    
    name_scores
}

/// Improved string analyzer that combines multiple techniques
pub fn improved_string_analyzer(program_data: &[u8]) -> Result<string_analyzer::StringAnalysisResult> {
    // Get strings from the program
    let elf_analyzer = elf::ElfAnalyzer::from_bytes(program_data.to_vec())?;
    let string_constants = elf_analyzer.extract_strings()?;
    
    // Convert to the format needed for other functions
    let indexed_strings: Vec<(usize, String)> = string_constants.iter()
        .enumerate()
        .map(|(i, s)| (i, s.clone()))
        .collect();
    
    // Get the text section for instruction analysis
    let text_section = elf_analyzer.get_text_section()?
        .ok_or_else(|| anyhow!("No text section found in program"))?;
    
    // Parse instructions
    let instructions = parse_instructions(&text_section.data, text_section.address as usize)?;
    
    // Build CFG
    let (blocks, functions) = cfg::build_cfg(&instructions)?;
    
    // Perform multiple types of string analysis
    let basic_scores = enhanced_string_analysis(program_data)?;
    let instruction_scores = analyze_instruction_strings(&instructions, &indexed_strings);
    let context_scores = context_aware_string_analysis(program_data, &functions, &blocks, &indexed_strings);
    
    // Combine scores from different analyses
    let mut combined_scores = HashMap::new();
    
    // Add scores from basic analysis
    for (name, score) in basic_scores {
        combined_scores.insert(name, score);
    }
    
    // Add scores from instruction analysis
    for (name, score) in instruction_scores {
        combined_scores.entry(name)
            .and_modify(|s| *s += score)
            .or_insert(score);
    }
    
    // Add scores from context analysis
    for (name, score) in context_scores {
        combined_scores.entry(name)
            .and_modify(|s| *s += score)
            .or_insert(score);
    }
    
    // Filter out low-scoring names
    let filtered_scores: HashMap<String, f64> = combined_scores.into_iter()
        .filter(|(name, score)| {
            // Filter out likely error messages and other non-instruction strings
            !name.contains("error") && 
            !name.contains("failed") && 
            !name.contains("invalid") &&
            !name.contains("expected") &&
            !name.contains("assert") &&
            name.len() < 40 &&
            *score > 0.5
        })
        .collect();
    
    // Create the result
    let result = string_analyzer::StringAnalysisResult {
        field_names: filtered_scores.clone(),
        account_names: HashMap::new(),  // You could implement similar analysis for account names
        instruction_names: filtered_scores,  // Add the missing field
    };
    
    Ok(result)
}

/// Detect native program instruction codes
pub fn detect_native_instruction_codes(program_data: &[u8]) -> Result<Vec<(u8, Option<String>)>> {
    let mut instruction_codes = Vec::new();
    let elf_parser = elf::ElfAnalyzer::from_bytes(extract_elf_bytes(program_data).to_vec())?;
    if let Ok(Some(text_section)) = elf_parser.get_text_section() {
        let instructions = parse_instructions(&text_section.data, text_section.address as usize)?;
        for window in instructions.windows(4) {
            if window[0].is_load() && window[0].size == 1 && window[0].offset == 0 &&
               window[1].is_branch() && window[1].is_cmp_imm() {
                let instruction_code = window[1].imm as u8;
                if !instruction_codes.iter().any(|(code, _)| *code == instruction_code) {
                    instruction_codes.push((instruction_code, None));
                }
            }
        }
    }
    match_native_instruction_codes(&mut instruction_codes);
    Ok(instruction_codes)
}

/// Match native instruction codes with known names for common programs
fn match_native_instruction_codes(instruction_codes: &mut Vec<(u8, Option<String>)>) {
    // Known instruction codes for the Token program
    let token_instructions = [
        (0, "InitializeMint"),
        (1, "InitializeAccount"),
        (2, "InitializeMultisig"),
        (3, "Transfer"),
        (4, "Approve"),
        (5, "Revoke"),
        (6, "SetAuthority"),
        (7, "MintTo"),
        (8, "Burn"),
        (9, "CloseAccount"),
        (10, "FreezeAccount"),
        (11, "ThawAccount"),
        (12, "TransferChecked"),
        (13, "ApproveChecked"),
        (14, "MintToChecked"),
        (15, "BurnChecked"),
        (16, "InitializeAccount2"),
        (17, "SyncNative"),
        (18, "InitializeAccount3"),
        (19, "InitializeMultisig2"),
        (20, "InitializeMint2"),
        // Add more as needed
    ];
    
    // Try to match instruction codes
    for (code, name) in instruction_codes.iter_mut() {
        if let Some((_, instruction_name)) = token_instructions.iter().find(|(c, _)| c == code) {
            *name = Some(instruction_name.to_string());
        }
    }
}

/// Analyze a native (non-Anchor) program
fn analyze_native_program(
    program_data: &[u8],
    program_id: &str,
    parsed_instructions: &[parser::SbfInstruction],
) -> Result<(BytecodeAnalysis, Vec<(usize, String)>)> {
    // First, detect native instruction codes
    let native_codes = detect_native_instruction_codes(program_data)?;
    info!("Detected {} native instruction codes", native_codes.len());
    
    let elf_parser = elf::ElfAnalyzer::from_bytes(program_data.to_vec())?;
    let string_constants = extract_string_constants(&elf_parser)?;
    let string_analysis = analyze_strings(&string_constants)?;
    
    let mut program_instructions = Vec::new();
    
    if !native_codes.is_empty() {
        // Create instructions based on detected native codes
        for (i, (code, name_opt)) in native_codes.iter().enumerate() {
            // Try to find a better name from string constants
            let name = if let Some(name) = name_opt {
                name.clone()
            } else {
                // Try to find a matching name in string analysis
                let mut best_name = format!("instruction_{}", i);
                
                // Use a reference to string_constants
                for (s, _) in &string_analysis.instruction_names {
                    // Check if this string contains the instruction code
                    if s.contains(&format!("_{}", code)) || s.contains(&format!("({}", code)) {
                        best_name = s.clone();
                        break;
                    }
                }
                
                best_name
            };
            
            let mut instruction = Instruction::new(name, *code);
            
            // Add generic accounts for now
            instruction.add_arg("data".to_string(), "bytes".to_string());
            instruction.add_account("authority".to_string(), true, false, false);
            instruction.add_account("account".to_string(), false, true, false);
            
            program_instructions.push(instruction);
        }
    } else {
        // Fallback to the original method if no native codes detected
        // Find instruction entry points
        let instruction_entries = extract_instruction_boundaries(&elf_parser)?;
        
        // Create instructions based on entry points
        for (i, &entry_point) in instruction_entries.iter().enumerate() {
            // Try to infer a meaningful name for this instruction
            let name = infer_instruction_name(parsed_instructions, entry_point, program_data)
                .unwrap_or_else(|| format!("instruction_{}", i));
            
            let mut instruction = Instruction::new(name, i as u8);
            
            // Add generic arguments
            instruction.add_arg("data".to_string(), "bytes".to_string());
            
            // Add standard accounts
            instruction.add_account("authority".to_string(), true, false, false);
            instruction.add_account("data".to_string(), false, true, false);
            
            program_instructions.push(instruction);
        }
    }
    
    // If we couldn't find any instructions, add a generic one
    if program_instructions.is_empty() {
        let mut instruction = Instruction::new("process".to_string(), 0);
        instruction.add_arg("data".to_string(), "bytes".to_string());
        instruction.add_account("authority".to_string(), true, false, false);
        instruction.add_account("data".to_string(), false, true, false);
        program_instructions.push(instruction);
    }
    
    // Extract accounts
    let accounts = account_analyzer::extract_account_structures(
        program_data,
        parsed_instructions,
        &[]  // Empty discriminator list for non-Anchor programs
    )?;
    
    // Extract error codes
    let error_codes = error_analyzer::extract_error_codes(parsed_instructions)
        .unwrap_or_default();
    
    // Create IDL with program name
    let program_name = extract_program_name(program_id, program_data);
    let mut idl = crate::models::idl::IDL::new(program_name, program_id.to_string());

    // Add instructions to IDL
    for instruction in &program_instructions {
        idl.add_instruction(instruction.clone());
    }

    // Add accounts to IDL
    for account in &accounts {
        idl.add_account(account.clone());
    }

    // Add error codes to IDL
    for (code, name) in &error_codes {
        idl.add_error(*code, name.clone(), name.clone());
    }

    // Create analysis result
    let analysis = BytecodeAnalysis {
        instructions: program_instructions,
        accounts,
        error_codes,
        is_anchor: false,
        disassembled: None,
    };
    
    info!("Bytecode analysis complete, found {} instructions, {} accounts, {} error codes",
        analysis.instructions.len(),
        analysis.accounts.len(),
        analysis.error_codes.len()
    );
    
    let indexed_strings = string_analysis.instruction_names.iter()
        .map(|(name, _)| (name.len(), name.clone()))
        .collect::<Vec<(usize, String)>>();
    Ok((analysis, indexed_strings))
}

/// Extract instruction boundaries from program bytecode
fn extract_instruction_boundaries(elf_parser: &elf::ElfAnalyzer) -> Result<Vec<usize>> {
    let text_section = elf_parser.get_text_section()?
        .ok_or_else(|| anyhow!("No text section found in program"))?;
    
    // Parse instructions from the text section
    let instructions = parse_instructions(&text_section.data, text_section.address as usize)?;
    
    // Build CFG for more advanced analysis
    let (blocks, functions) = cfg::build_cfg(&instructions)?;
    
    let mut boundaries = Vec::new();
    
    // 1. BPF Specific Patterns - Look for function prologues
    for (i, insn) in instructions.iter().enumerate() {
        // Check for common BPF function prologue pattern
        if insn.opcode == 0x0f && // ALU64_REG 
           insn.dst_reg == 11 && 
           insn.src_reg == 11 && 
           insn.imm < 0 {
            boundaries.push(i);
        }
        
        // Check for register r0 being set
        if i > 0 && 
           insn.dst_reg == 0 && 
           (insn.opcode == 0xb7 || // MOV_IMM
            insn.opcode == 0xbf) { // MOV_REG
            boundaries.push(i - 1);
        }
        
        // Look for instruction discriminator checks
        // Anchor programs use 8-byte discriminators at the start
        if i + 8 < instructions.len() {
            // Check for loading bytes from instruction data
            if insn.is_load() && i > 0 {
                // Check if the next few instructions compare these bytes
                let mut is_discriminator_check = false;
                for j in 1..4 {
                    if i + j < instructions.len() {
                        let next_insn = &instructions[i + j];
                        if next_insn.opcode == 0x55 || // JNE_IMM
                           next_insn.opcode == 0x15 {  // JEQ_IMM
                            is_discriminator_check = true;
                            break;
                        }
                    }
                }
                
                if is_discriminator_check {
                    // This is likely checking a discriminator
                    boundaries.push(i - 1);
                }
            }
        }
    }
    
    // 2. Control Flow Analysis - Look for "islands" in the code
    // Identify blocks that have no predecessors (except the entry block)
    for (i, block) in blocks.iter().enumerate() {
        if i > 0 && block.predecessors.is_empty() && !block.instructions.is_empty() {
            boundaries.push(i);
        }
        
        // Look for blocks that end with a return (setting r0 and then exit)
        if !block.instructions.is_empty() {
            let last_idx = block.instructions.len() - 1;
            let last_insn = &block.instructions[last_idx];
            
            if last_insn.opcode == 0x95 { // EXIT opcode
                // Check if r0 was set just before exit (common pattern for returns)
                if last_idx > 0 {
                    let prev_insn = &block.instructions[last_idx - 1];
                    if prev_insn.dst_reg == 0 {
                        // Found a function that sets return value and exits
                        if last_idx + 1 < instructions.len() {
                            boundaries.push(last_idx + 1);
                        }
                    }
                }
            }
        }
    }
    
    // Remove duplicates and sort
    boundaries.sort();
    boundaries.dedup();
    
    Ok(boundaries)
}

/// Improved instruction name inference using multiple heuristics
fn infer_instruction_name(
    instructions: &[parser::SbfInstruction],
    entry_point: usize,
    program_data: &[u8]
) -> Option<String> {
    // 1. Symbol Recovery - Look for string references near the entry point
    let window_size = 50.min(instructions.len() - entry_point);
    let instruction_window = &instructions[entry_point..entry_point + window_size];
    
    // Look for string loading patterns
    for insn in instruction_window.iter() {
        if insn.is_load_imm() && insn.imm > 0 {
            // This might be loading a string pointer
            let potential_str_addr = insn.imm as usize;
            
            // Try to extract a string from this address in the program data
            if potential_str_addr < program_data.len() {
                let max_len = 30.min(program_data.len() - potential_str_addr);
                let potential_str = &program_data[potential_str_addr..potential_str_addr + max_len];
                
                // Check if this looks like a valid string
                if let Ok(s) = std::str::from_utf8(potential_str) {
                    let s = s.split('\0').next().unwrap_or("").trim();
                    
                    // Filter out error messages and other non-instruction strings
                    if !s.is_empty() && 
                       s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) &&
                       !s.contains("error") && 
                       !s.contains("Error") && 
                       !s.contains("failed") && 
                       !s.contains("Failed") &&
                       !s.contains("assert") &&
                       !s.contains("Assert") &&
                       !s.contains("borrowed") &&
                       !s.contains("unreac") &&
                       !s.len() > 25 {  // Avoid overly long strings
                        // This looks like a valid instruction name
                        return Some(s.to_string());
                    }
                }
            }
        }
    }
    
    // 2. Syscall Analysis - Infer purpose from syscall usage
    for insn in instruction_window.iter() {
        if insn.opcode == 0x85 && insn.imm > 0 { // CALL opcode
            let syscall_hash = insn.imm as u32;
            
            // Map common syscalls to likely instruction names
            match syscall_hash {
                hash if hash == crate::constants::syscalls::hashes::SOL_INVOKE => {
                    return Some("invoke".to_string());
                },
                hash if hash == crate::constants::syscalls::hashes::SOL_INVOKE_SIGNED => {
                    return Some("invoke_signed".to_string());
                },
                hash if hash == crate::constants::syscalls::hashes::SOL_CREATE_PROGRAM_ADDRESS => {
                    return Some("create_address".to_string());
                },
                hash if hash == crate::constants::syscalls::hashes::SOL_TRY_FIND_PROGRAM_ADDRESS => {
                    return Some("find_address".to_string());
                },
                hash if hash == crate::constants::syscalls::hashes::SOL_SHA256 => {
                    return Some("hash".to_string());
                },
                _ => {}
            }
        }
    }
    
    // 3. Pattern-Based Naming - Look for common instruction patterns
    
    // Check for token transfer patterns (loading accounts, then invoking)
    let mut has_account_loading = false;
    let mut has_invoke = false;
    
    for insn in instruction_window.iter() {
        if insn.is_load() {
            has_account_loading = true;
        }
        
        if insn.opcode == 0x85 && // CALL
           insn.imm as u32 == crate::constants::syscalls::hashes::SOL_INVOKE {
            has_invoke = true;
        }
    }
    
    if has_account_loading && has_invoke {
        return Some("transfer".to_string());
    }
    
    // Check for account initialization patterns
    let mut has_memset = false;
    for insn in instruction_window.iter() {
        if insn.opcode == 0x85 && // CALL
           insn.imm as u32 == crate::constants::syscalls::hashes::SOL_MEMSET {
            has_memset = true;
            break;
        }
    }
    
    if has_memset {
        return Some("initialize".to_string());
    }
    
    // 4. Fallback - Use a generic name with the entry point address
    Some(format!("instruction_{:x}", entry_point))
}

/// Extract accounts from bytecode
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

/// Extract a better program name from the program data
fn extract_program_name(program_id: &str, program_data: &[u8]) -> String {
    // TODO: no hardcoding
    match program_id {
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" => return "SPL Token Program".to_string(),
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" => return "SPL Associated Token Account Program".to_string(),
        "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s" => return "Metaplex Token Metadata Program".to_string(),
        "cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK" => return "SPL Account Compression Program".to_string(),
        _ => {}
    }
    
    // Try to extract a name from the program data
    for i in 0..program_data.len().saturating_sub(30) {
        if let Ok(s) = std::str::from_utf8(&program_data[i..i+30]) {
            let s = s.split('\0').next().unwrap_or("").trim();
            if s.len() > 5 && s.len() < 25 && 
               s.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '_' || c == '-') &&
               !s.contains("error") && !s.contains("Error") {
                return s.to_string();
            }
        }
    }
    
    // Fallback to a generic name based on the program ID
    format!("{} program", program_id.chars().take(10).collect::<String>())
}

/// Analyze instruction parameters
fn analyze_instruction_params(
    instructions: &[SbfInstruction], 
    boundary_idx: usize
) -> Result<Vec<(String, String)>> {
    let mut parameters = Vec::new();
    
    // Define the window size for analysis
    let window_size = 50;
    let end_idx = (boundary_idx + window_size).min(instructions.len());
    
    // Extract the instruction window
    let instruction_window = &instructions[boundary_idx..end_idx];
    
    // Look for parameter loading patterns
    let mut offset = 0;
    for insn in instruction_window.iter() {
        // Look for loads from instruction data
        if insn.is_load() && insn.src_reg == 1 {  // r1 typically holds instruction data pointer
            // This might be loading a parameter
            let param_offset = insn.offset as usize;
            let param_size = match insn.size {
                1 => "u8",
                2 => "u16",
                4 => "u32",
                8 => "u64",
                _ => "bytes",
            };
            
            // Skip duplicates
            if !parameters.iter().any(|(_, ty)| ty == param_size && offset == param_offset) {
                parameters.push((format!("param_{}", offset), param_size.to_string()));
                offset += 1;
            }
        }
    }
    
    // If we couldn't find any parameters, add a generic one
    if parameters.is_empty() {
        parameters.push(("data".to_string(), "bytes".to_string()));
    }
    
    Ok(parameters)
}

/// Analyze account usage in instructions
fn analyze_account_usage(
    instructions: &[SbfInstruction],
    boundary_idx: usize
) -> Result<Vec<(String, bool, bool)>> {
    let mut accounts = Vec::new();
    
    // Define the window size for analysis
    let window_size = 50;
    let end_idx = (boundary_idx + window_size).min(instructions.len());
    
    // Extract the instruction window
    let instruction_window = &instructions[boundary_idx..end_idx];
    
    // Track account indices and properties
    let mut account_indices = HashSet::new();
    let mut signer_indices = HashSet::new();
    let mut writable_indices = HashSet::new();
    
    // Look for account access patterns
    for insn in instruction_window {
        // Look for account array access (accounts[i])
        if insn.is_load() && insn.src_reg == 2 {  // r2 typically holds accounts array
            let account_idx = insn.offset as usize / 8;  // Assuming 8-byte pointers
            account_indices.insert(account_idx);
        }
        
        // Look for is_signer checks
        if insn.is_branch() && insn.is_cmp_imm() && 
           (insn.opcode == 0x15 || insn.opcode == 0x55) {  // JEQ or JNE
            // This might be checking is_signer
            if let Some(prev_insn) = instruction_window.iter().rev().find(|i| i.dst_reg == insn.src_reg) {
                if prev_insn.is_load() && prev_insn.src_reg == 2 {
                    let account_idx = prev_insn.offset as usize / 8;
                    signer_indices.insert(account_idx);
                }
            }
        }
        
        // Look for is_writable checks (similar pattern)
        // This is a simplification; real analysis would be more complex
        if insn.is_branch() && insn.is_cmp_imm() && 
           (insn.opcode == 0x15 || insn.opcode == 0x55) {  // JEQ or JNE
            // This might be checking is_writable
            if let Some(prev_insn) = instruction_window.iter().rev().find(|i| i.dst_reg == insn.src_reg) {
                if prev_insn.is_load() && prev_insn.src_reg == 2 {
                    let account_idx = prev_insn.offset as usize / 8 + 1;  // +1 offset for is_writable
                    writable_indices.insert(account_idx);
                }
            }
        }
    }
    
    // Create accounts based on detected indices
    let account_indices_len = account_indices.len();  // Get the length before the loop
    for idx in account_indices {
        let is_signer = signer_indices.contains(&idx);
        let is_writable = writable_indices.contains(&idx);
        
        let is_last = account_indices_len == idx + 1;  // Use the stored length
        let name = if idx == 0 && is_signer {
            "authority".to_string()
        } else if is_writable {
            format!("account_{}", idx)
        } else if is_last {
            "systemProgram".to_string()
        } else {
            format!("account_{}", idx)
        };
        
        accounts.push((name, is_signer, is_writable));
    }
    
    // If we couldn't find any accounts, add generic ones
    if accounts.is_empty() {
        accounts.push(("authority".to_string(), true, false));
        accounts.push(("account".to_string(), false, true));
    }
    
    Ok(accounts)
}

/// Extract instructions from an Anchor program
fn extract_anchor_instructions(
    program_data: &[u8],
    boundaries: &[usize],
    string_analysis: &string_analyzer::StringAnalysisResult
) -> Result<Vec<Instruction>> {
    // Extract discriminators
    let discriminators = discriminator_detection::extract_discriminators(program_data)?;
    
    let mut instructions = Vec::new();
    
    // For each discriminator, create an instruction
    for (i, disc) in discriminators.iter().enumerate() {
        // Try to find a better name from string analysis
        let name = if let Some(disc_name) = &disc.name {
            // Use the discriminator name if available
            disc_name.clone()
        } else {
            // Try to find a matching name in string analysis
            let best_match = string_analysis.instruction_names.iter()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal));
            
            if let Some((name, _)) = best_match {
                name.clone()
            } else {
                format!("instruction_{}", disc.code.unwrap_or(i as u8))
            }
        };
        
        let mut instruction = Instruction::new(name, disc.code.unwrap_or(i as u8));
        
        // Set the discriminator bytes
        instruction.discriminator = Some(disc.bytes.clone());
        
        // Add parameters based on boundary analysis
        if let Some(boundary_idx) = boundaries.get(i) {
            // Parse instructions from the text section
            let elf_parser = elf::ElfAnalyzer::from_bytes(program_data.to_vec())?;
            let text_section = elf_parser.get_text_section()?
                .ok_or_else(|| anyhow!("No text section found in program"))?;
            let parsed_instructions = parse_instructions(&text_section.data, text_section.address as usize)?;
            
            // Analyze parameters
            if let Ok(params) = analyze_instruction_params(&parsed_instructions, *boundary_idx) {
                for (name, ty) in params {
                    instruction.add_arg(name, ty);
                }
            }
            
            // Analyze accounts
            if let Ok(accounts) = analyze_account_usage(&parsed_instructions, *boundary_idx) {
                for (name, is_signer, is_writable) in accounts {
                    instruction.add_account(name, is_signer, is_writable, false);
                }
            }
        }
        
        // If no accounts were added, add standard Anchor accounts
        if instruction.accounts.is_empty() {
            instruction.add_account("authority".to_string(), true, false, false);
            instruction.add_account("systemProgram".to_string(), false, false, false);
        }
        
        // Add instruction to list
        instructions.push(instruction);
    }
    
    // If we didn't find any discriminators, try to extract instructions from boundaries
    if instructions.is_empty() {
        info!("No discriminators found, extracting instructions from boundaries");
        for (i, &boundary) in boundaries.iter().enumerate().take(20) {
            // Try to find a good name from string analysis
            let name = string_analysis.instruction_names.iter()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(name, _)| name.clone())
                .unwrap_or_else(|| format!("instruction_{}", i));
            
            let mut instruction = Instruction::new(name, i as u8);
            
            // Add generic arguments
            instruction.add_arg("data".to_string(), "bytes".to_string());
            
            // Add standard accounts
            instruction.add_account("authority".to_string(), true, false, false);
            instruction.add_account("data".to_string(), false, true, false);
            
            // Add instruction to list
            instructions.push(instruction);
        }
    }
    
    Ok(instructions)
}

/// Extract instructions from a native (non-Anchor) program
fn extract_native_instructions(
    program_data: &[u8],
    boundaries: &[usize],
    string_analysis: &string_analyzer::StringAnalysisResult
) -> Result<Vec<Instruction>> {
    // First, detect native instruction codes
    let native_codes = detect_native_instruction_codes(program_data)?;
    info!("Detected {} native instruction codes", native_codes.len());
    
    let mut instructions = Vec::new();
    
    if !native_codes.is_empty() {
        // Create instructions based on detected native codes
        for (i, (code, name_opt)) in native_codes.iter().enumerate() {
            // Try to find a better name from string analysis or use the provided one
            let name = if let Some(name) = name_opt {
                name.clone()
            } else {
                // Try to find a matching name in string analysis
                let mut best_name = format!("instruction_{}", i);
                
                // Use a reference to string_constants
                for (s, _) in &string_analysis.instruction_names {
                    // Check if this string contains the instruction code
                    if s.contains(&format!("_{}", code)) || s.contains(&format!("({}", code)) {
                        best_name = s.clone();
                        break;
                    }
                }
                
                best_name
            };
            
            let mut instruction = Instruction::new(name, *code);
            
            // Add generic arguments
            instruction.add_arg("data".to_string(), "bytes".to_string());
            
            // Add standard accounts
            instruction.add_account("authority".to_string(), true, false, false);
            instruction.add_account("account".to_string(), false, true, false);
            
            instructions.push(instruction);
        }
    } else {
        // Fallback to boundary-based instruction extraction
        for (i, &boundary) in boundaries.iter().enumerate() {
            // Try to find a good name from string analysis
            let name = string_analysis.instruction_names.iter()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(name, _)| name.clone())
                .unwrap_or_else(|| format!("instruction_{}", i));
            
            let mut instruction = Instruction::new(name, i as u8);
            
            // Add generic arguments
            instruction.add_arg("data".to_string(), "bytes".to_string());
            
            // Add standard accounts
            instruction.add_account("authority".to_string(), true, false, false);
            instruction.add_account("data".to_string(), false, true, false);
            
            instructions.push(instruction);
        }
    }
    
    // If we couldn't find any instructions, add a generic one
    if instructions.is_empty() {
        let mut instruction = Instruction::new("process".to_string(), 0);
        instruction.add_arg("data".to_string(), "bytes".to_string());
        instruction.add_account("authority".to_string(), true, false, false);
        instruction.add_account("data".to_string(), false, true, false);
        instructions.push(instruction);
    }
    
    Ok(instructions)
}

/// Extract error codes from program data
fn extract_error_codes(program_data: &[u8]) -> Result<HashMap<u32, String>> {
    // Try to parse the ELF file
    let elf_parser = elf::ElfAnalyzer::from_bytes(program_data.to_vec())?;
    let text_section = elf_parser.get_text_section()?
        .ok_or_else(|| anyhow!("No text section found in program"))?;
    
    // Parse instructions
    let instructions = parse_instructions(&text_section.data, text_section.address as usize)?;
    
    // Use the error_analyzer to extract error codes
    let error_codes = error_analyzer::extract_error_codes(&instructions)
        .unwrap_or_default();
    
    // For Anchor programs, also try to extract custom error codes
    if crate::analyzer::anchor::is_anchor_program(program_data) {
        let anchor_errors = crate::analyzer::anchor::extract_custom_error_codes(program_data)
            .unwrap_or_default();
        
        // Merge the error codes
        let mut merged_errors = error_codes;
        for (code, name) in anchor_errors {
            merged_errors.insert(code, name);
        }
        
        Ok(merged_errors)
    } else {
        Ok(error_codes)
    }
}

/// Add this function to your code:
fn identify_instruction_boundaries(
    parsed_instructions: &[SbfInstruction], 
    blocks: &[BasicBlock], 
    program_data: &[u8]
) -> Vec<usize> {
    // Implementation here
    // For now, just call the existing function
    let elf_parser = elf::ElfAnalyzer::from_bytes(program_data.to_vec()).unwrap();
    extract_instruction_boundaries(&elf_parser).unwrap_or_default()
}

/// Given raw Solana account data, return a slice containing only the ELF binary.
/// This handles both upgradeable and non-upgradeable program accounts.
pub fn extract_elf_bytes(account_data: &[u8]) -> &[u8] {
    const ELF_MAGIC: &[u8; 4] = b"\x7FELF";
    // Try offset 8 (legacy assumption)
    if account_data.len() >= 12 && &account_data[8..12] == ELF_MAGIC {
        return &account_data[8..];
    }
    // Try offset 44 (most common for upgradeable loader)
    if account_data.len() >= 48 && &account_data[44..48] == ELF_MAGIC {
        return &account_data[44..];
    }
    // Try offset 0 (non-upgradeable)
    if account_data.len() >= 4 && &account_data[0..4] == ELF_MAGIC {
        return account_data;
    }
    // Fallback: search for ELF magic in the first 256 bytes
    if let Some(pos) = account_data.windows(4).position(|w| w == ELF_MAGIC) {
        return &account_data[pos..];
    }
    // Not found, return original (will error)
    account_data
}