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
pub mod heuristics;

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
use crate::analyzer::anchor::is_anchor_program;
use crate::utils::find_elf_start;
pub use string_analyzer::{
    extract_string_constants,
    enhanced_string_analysis,
    analyze_instruction_strings,
    context_aware_string_analysis,
    improved_string_analyzer,
    StringAnalysisResult,
};

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
    
    // Dump text section first
    dump_text_section(program_data)?;
    
    // Parse ELF file once
    let elf_parser = elf::ElfAnalyzer::from_bytes(program_data.to_vec())
        .context("Failed to parse ELF file")?;

    // Get text section once
    let text_section = elf_parser.get_text_section()?
        .ok_or_else(|| anyhow!("No text section found in program"))?;
    
    // Parse instructions once
    let parsed_instructions = parse_instructions(&text_section.data, text_section.address as usize)?;
    
    // Determine if this is an Anchor program
    let is_anchor = is_anchor_program(program_data);
    
    // Extract string constant
    let string_analysis = string_analyzer::analyze_strings(&extract_string_constants(&elf_parser)?)?;
    
    // Extract instruction boundaries
    let boundaries = instruction_analyzer::find_instruction_boundaries(&parsed_instructions)?;
    
    // Extract discriminators
    let discriminators = discriminator_detection::extract_discriminators(program_data)?;
    
    // Extract instructions based on program type
    let instructions = if is_anchor {
        extract_anchor_instructions(program_data, &boundaries, &string_analysis)?
    } else {
        extract_native_instructions(program_data, &boundaries, &string_analysis)?
    };
    
    // Extract accounts
    let accounts = account_analyzer::extract_account_structures(
        program_data,
        &parsed_instructions,
        &discriminators
    )?;
    
    // Extract error codes
    let error_codes = error_analyzer::extract_error_codes(&parsed_instructions)?;

    Ok(BytecodeAnalysis {
        instructions,
        accounts,
        error_codes,
        is_anchor,
        disassembled: None,
    })
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

/// Extract instructions from an Anchor program
fn extract_anchor_instructions(
    program_data: &[u8],
    boundaries: &[usize],
    string_analysis: &string_analyzer::StringAnalysisResult
) -> Result<Vec<Instruction>> {
    // Extract discriminators
    let discriminators = discriminator_detection::extract_discriminators(program_data)?;
    
    let mut instructions = Vec::new();
    let mut seen_discriminators = HashSet::new();
    
    // For each discriminator, create an instruction
    for (i, disc) in discriminators.iter().enumerate() {
        // Skip if we've seen this discriminator before
        if !seen_discriminators.insert(disc.bytes.clone()) {
            continue;
        }
        
        // Skip invalid discriminators (all zeros or too short)
        if disc.bytes.iter().all(|&b| b == 0) || disc.bytes.len() < 8 {
            continue;
        }
        
        // Try to find a better name from string analysis
        let name = if let Some(disc_name) = &disc.name {
            disc_name.clone()
        } else {
            // Try to find a matching name in string analysis
            let best_match = string_analysis.instruction_names.iter()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal));
            
            if let Some((name, _)) = best_match {
                name.clone()
            } else {
                format!("instruction_{}", i)
            }
        };
        
        let mut instruction = Instruction::new(name, i as u8);
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
        
        instructions.push(instruction);
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

/// Given raw Solana account data, return a slice containing only the ELF binary.
/// This handles both upgradeable and non-upgradeable program accounts.
pub fn extract_elf_bytes(account_data: &[u8]) -> &[u8] {
    match find_elf_start(account_data) {
        Ok(offset) => &account_data[offset..],
        Err(e) => {
            log::warn!("Failed to find ELF header: {}", e);
            account_data
        }
    }
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

/// Add this function to mod.rs
pub fn dump_text_section(program_data: &[u8]) -> Result<()> {
    let elf_analyzer = ElfAnalyzer::from_bytes(program_data.to_vec())?;
    if let Ok(Some(text_section)) = elf_analyzer.get_text_section() {
        info!("Text section size: {} bytes", text_section.data.len());
        info!("Text section address: 0x{:x}", text_section.address);
        
        // Dump first 100 bytes in hex
        let preview = text_section.data.iter()
            .take(100)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join(" ");
        info!("Text section preview (first 100 bytes):\n{}", preview);
        
        // Parse and show instructions
        let instructions = parse_instructions(&text_section.data, text_section.address as usize)?;
        info!("First 10 instructions:");
        for (i, insn) in instructions.iter().take(10).enumerate() {
            info!("{:4}: {:?}", i, insn);
        }
    }
    Ok(())
}