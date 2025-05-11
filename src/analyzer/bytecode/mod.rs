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
use std::collections::{HashMap, HashSet};
use solana_sbpf::{
    static_analysis::Analysis,
    program::SBPFVersion,
    vm::Config,
};

use crate::models::instruction::Instruction;
use crate::models::account::Account;
use crate::analyzer::anchor::is_anchor_program;
use crate::utils::find_elf_start;
use crate::utils::dynamic_analysis::{analyze_dynamic, DynamicAnalysisResult, get_account_access_patterns, get_instruction_frequency, AccessType};
use crate::utils::error_analysis::{extract_error_codes, ErrorAnalysis};

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
    /// Dynamic analysis results
    pub dynamic_analysis: Option<DynamicAnalysisResult>,
    /// Control flow graph
    pub cfg: Option<Vec<BasicBlock>>,
    /// Functions
    pub functions: Option<Vec<Function>>,
    /// String analysis results
    pub strings: Option<Vec<String>>,
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
            dynamic_analysis: None,
            cfg: None,
            functions: None,
            strings: None,
        }
    }
}

/// Analyze program bytecode
pub fn analyze(
    program_data: &[u8],
    program_id: &str,
) -> Result<BytecodeAnalysis> {
    // Parse instructions
    let instructions = parse_instructions(program_data, 0)?;
    
    // Create SBPF analysis
    let elf_bytes = crate::analyzer::bytecode::extract_elf_bytes(program_data)?;
    let analysis = Analysis::from_executable(&elf_bytes)?; // TODO: is this mine or sbpf's?, also see how to replace with anyhow
    
    // Check if this is an Anchor program
    let is_anchor = is_anchor_program(program_data);
    
    // Extract accounts using dynamic analysis
    let accounts = if let Ok(dynamic_result) = analyze_dynamic(
        &instructions,
        &analysis,
        SBPFVersion::V3,
        &Config::default(),
    ) {
        // Use account access patterns from dynamic analysis
        let account_patterns = get_account_access_patterns(&dynamic_result);
        extract_account_structures_with_patterns(program_data, &analysis, &account_patterns)?
    } else {
        extract_account_structures(program_data, &analysis)? // TODO: replace with anyhow, Box seems to lack some traits?
    };
    
    // Extract error codes
    let error_codes = extract_error_codes(&instructions, &analysis)?;
    
    // Build control flow graph
    let (blocks, functions) = build_cfg(&instructions, &analysis)?;
    
    // Extract discriminators
    let discriminators = extract_discriminators(program_data)?;
    
    // Analyze strings
    let string_analysis = analyze_strings(program_data)?; // TODO: this expects String from initial definition, which one is correct?
    let strings: Vec<String> = string_analysis.instruction_names.keys().cloned().collect();
    
    // Perform dynamic analysis
    let dynamic_analysis = analyze_dynamic(
        &instructions,
        &analysis,
        SBPFVersion::V3,
        &Config::default(),
    ).ok();
    
    // Create instructions
    let program_instructions = instruction_analyzer::extract_program_instructions(
        &instructions,
        &blocks.iter().map(|b| b.start).collect::<Vec<_>>(),
        &discriminators,
    )?;
    
    // Disassemble program
    let disassembled = disassemble_program(program_data).ok();
    
    Ok(BytecodeAnalysis {
        instructions: program_instructions,
        accounts,
        error_codes,
        is_anchor,
        disassembled,
        dynamic_analysis,
        cfg: Some(blocks),
        functions: Some(functions),
        strings: Some(strings),
    })
}

/// Extract accounts with access patterns from dynamic analysis
fn extract_account_structures_with_patterns(
    program_data: &[u8],
    analysis: &Analysis,
    account_patterns: &HashMap<usize, Vec<AccessType>>,
) -> Result<Vec<Account>> {
    let mut accounts = extract_account_structures(program_data, analysis)?; //TODO: this shit again
    
    // Enhance accounts with access patterns
    for (idx, patterns) in account_patterns {
        if let Some(account) = accounts.get_mut(*idx) {
            // Add access pattern information
            account.add_metadata("access_patterns".to_string(), format!("{:?}", patterns));
            
            // Infer account type based on access patterns
            if patterns.iter().any(|p| matches!(p, AccessType::Write)) {
                account.add_metadata("is_writable".to_string(), "true".to_string());
            }
        }
    }
    
    Ok(accounts)
}

/// Extract program name from bytecode
pub fn extract_program_name(program_data: &[u8]) -> Result<String> {
    // Try to find program name in strings
    let string_analysis = analyze_strings(program_data)?; // TODO
    for name in string_analysis.instruction_names.keys() {
        if name.len() > 3 && name.len() < 50 && 
           name.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '_' || c == '-') {
            return Ok(name.clone());
        }
    }
    
    // Fallback to a generic name
    Ok("Unknown Program".to_string())
}

/// Dump text section for debugging
pub fn dump_text_section(program_data: &[u8]) -> Result<()> {
    let elf_analyzer = ElfAnalyzer::from_bytes(extract_elf_bytes(program_data)?)?; // TODO: convert to vec
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

/// Detect native program instruction codes
pub fn detect_native_instruction_codes(program_data: &[u8]) -> Result<Vec<(u8, Option<String>)>> {
    let mut instruction_codes = Vec::new();
    let elf_parser = elf::ElfAnalyzer::from_bytes(extract_elf_bytes(program_data)?.to_vec())?;
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
        // Convert disc.bytes to a fixed-size array first if it's a Vec<u8>
        // This avoids type mismatches with the HashSet and when assigning to instruction.discriminator
        let disc_array: [u8; 8] = if disc.bytes.len() >= 8 {
            let mut array = [0u8; 8];
            array.copy_from_slice(&disc.bytes[0..8]);
            array
        } else {
            // Skip invalid discriminators that are too short
            continue;
        };

        // Skip if we've seen this discriminator before
        if !seen_discriminators.insert(disc_array) {
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
        instruction.discriminator = Some(disc_array);
        
        // Add parameters based on boundary analysis
        if let Some(boundary_idx) = boundaries.get(i) {
            // Parse instructions from the text section
            let elf_bytes = extract_elf_bytes(program_data)?;
            let elf_parser = elf::ElfAnalyzer::from_bytes(elf_bytes.to_vec())?;
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

/// Given raw Solana account data, return a slice containing only the ELF binary.
/// This handles both upgradeable and non-upgradeable program accounts.
pub fn extract_elf_bytes(account_data: &[u8]) -> Result<&[u8]> {
    match find_elf_start(account_data) {
        Ok(offset) => {
            // Validate ELF header
            if offset + 4 <= account_data.len() {
                let magic = &account_data[offset..offset + 4];
                if magic == [0x7f, b'E', b'L', b'F'] {
                    return Ok(&account_data[offset..]);
                }
            }
            Err(anyhow!("Invalid ELF header"))
        }
        Err(e) => {
            log::warn!("Failed to find ELF header: {}", e);
            Err(anyhow!("No valid ELF binary found"))
        }
    }
}

/// Analyze instruction parameters with improved pattern detection
pub fn analyze_instruction_params(
    instructions: &[SbfInstruction],
    start_idx: usize,
) -> Result<Vec<(String, String)>> {
    let mut params = Vec::new();
    let mut offset = 0;
    
    // Look at the next 50 instructions
    for i in start_idx..(start_idx + 50).min(instructions.len()) {
        let insn = &instructions[i];
        
        // Look for parameter loading patterns
        if insn.is_load() && insn.src_reg == 1 { // r1 typically holds instruction data
            let size = match insn.size {
                1 => "u8",
                2 => "u16",
                4 => "u32",
                8 => "u64",
                _ => "bytes",
            };
            
            let name = format!("param_{}", offset);
            params.push((name, size.to_string()));
            offset += insn.size as usize;
        }
        
        // Look for array/vector patterns
        if insn.is_mov_imm() && insn.imm > 0 && insn.imm < 1000 {
            params.push((format!("array_{}", offset), "Vec<u8>".to_string()));
        }
    }
    
    Ok(params)
}

/// Analyze account usage patterns in instructions
pub fn analyze_account_usage(
    instructions: &[SbfInstruction],
    start_idx: usize,
) -> Result<Vec<(String, bool, bool)>> {
    let mut accounts = Vec::new();
    let mut account_indices = HashSet::new();
    let mut signer_indices = HashSet::new();
    let mut writable_indices = HashSet::new();
    
    // Look at the next 100 instructions
    for i in start_idx..(start_idx + 100).min(instructions.len()) {
        let insn = &instructions[i];
        
        // Look for account array access
        if insn.is_load() && insn.src_reg == 2 { // r2 typically holds accounts array
            let account_idx = insn.offset as usize / 8;
            account_indices.insert(account_idx);
            
            // Check if this is a signer check
            if let Some(next_insn) = instructions.get(i + 1) {
                if next_insn.is_branch() && next_insn.is_cmp_imm() {
                    signer_indices.insert(account_idx);
                }
            }
            
            // Check if this is a writable check
            if let Some(next_insn) = instructions.get(i + 2) {
                if next_insn.is_branch() && next_insn.is_cmp_imm() {
                    writable_indices.insert(account_idx);
                }
            }
        }
    }
    
    // Create accounts based on detected indices
    for idx in account_indices {
        let is_signer = signer_indices.contains(&idx);
        let is_writable = writable_indices.contains(&idx);
        
        let name = if idx == 0 && is_signer {
            "authority".to_string()
        } else if is_writable {
            format!("account_{}", idx)
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