//! Enhanced string analysis for better naming in IDL extraction

use anyhow::{Result, anyhow};
use log::{debug, info};
use std::collections::HashMap;
use super::ElfAnalyzer;
use super::parser;
use super::cfg;
use super::parser::parse_instructions;


/// String analysis result
#[derive(Debug, Clone)]
pub struct StringAnalysisResult {
    /// Potential instruction names
    pub instruction_names: HashMap<String, f64>, // name -> confidence score
    /// Potential account names
    pub account_names: HashMap<String, f64>,     // name -> confidence score
    /// Potential field names
    pub field_names: HashMap<String, f64>,       // name -> confidence score
}

/// Analyze strings to extract meaningful names
pub fn analyze_strings(strings: &[String]) -> Result<StringAnalysisResult> { //TODO: what string exactly? should i just pass the .text section?
    let mut result = StringAnalysisResult {
        instruction_names: HashMap::new(),
        account_names: HashMap::new(),
        field_names: HashMap::new(),
    };
    
    // Process each string
    for string in strings {
        process_string(&mut result, string);
    }
    
    // Apply heuristics to improve confidence scores
    apply_naming_heuristics(&mut result);
    
    Ok(result)
}

/// Process a single string to categorize it
fn process_string(result: &mut StringAnalysisResult, string: &str) {
    // Skip strings that are too short or too long
    if string.len() < 3 || string.len() > 50 {
        return;
    }
    
    // Clean the string (remove non-alphanumeric chars, etc.)
    let cleaned = clean_string(string);
    
    // Check for instruction name patterns
    if is_likely_instruction_name(&cleaned) {
        let confidence = calculate_instruction_name_confidence(&cleaned);
        result.instruction_names.insert(cleaned.clone(), confidence);
    }
    
    // Check for account name patterns
    if is_likely_account_name(&cleaned) {
        let confidence = calculate_account_name_confidence(&cleaned);
        result.account_names.insert(cleaned.clone(), confidence);
    }
    
    // Check for field name patterns
    if is_likely_field_name(&cleaned) {
        let confidence = calculate_field_name_confidence(&cleaned);
        result.field_names.insert(cleaned.clone(), confidence);
    }
}

/// Clean a string for analysis
fn clean_string(string: &str) -> String {
    // Remove common prefixes/suffixes
    let mut cleaned = string.trim().to_string();
    
    // Remove quotes
    if (cleaned.starts_with('"') && cleaned.ends_with('"')) || 
       (cleaned.starts_with('\'') && cleaned.ends_with('\'')) {
        cleaned = cleaned[1..cleaned.len()-1].to_string();
    }
    
    // Convert to camelCase or snake_case if mixed
    if cleaned.contains('_') && cleaned.contains(char::is_uppercase) {
        cleaned = to_snake_case(&cleaned);
    }
    
    cleaned
}

/// Check if a string is likely an instruction name
fn is_likely_instruction_name(string: &str) -> bool {
    // Common instruction name patterns
    let instruction_patterns = [
        "initialize", "create", "update", "delete", "set", "get",
        "add", "remove", "transfer", "mint", "burn", "swap",
        "deposit", "withdraw", "stake", "unstake", "claim",
        "approve", "revoke", "freeze", "thaw", "close",
        "redeem", "liquidate", "harvest", "compound",
        "delegate", "undelegate", "redelegate"
    ];
    
    // Check if string starts with or exactly matches an instruction pattern
    instruction_patterns.iter().any(|&pattern| {
        string == pattern || 
        string.starts_with(&format!("{}_", pattern)) ||
        string.starts_with(&format!("{} ", pattern))
    })
}

/// Calculate confidence score for an instruction name
pub fn calculate_instruction_name_confidence(name: &str) -> f64 {
    let mut confidence: f64 = 0.5; // Base confidence
    
    // Boost confidence for common instruction verbs
    let instruction_verbs = [
        "initialize", "create", "update", "delete", "set", "get",
        "add", "remove", "transfer", "mint", "burn", "swap",
        "deposit", "withdraw", "stake", "unstake", "claim",
    ];
    
    for verb in instruction_verbs {
        if name.to_lowercase().contains(verb) {
            confidence += 0.2;
            break;
        }
    }
    
    // Boost for camelCase or PascalCase naming (common in Solana)
    if name.chars().any(|c| c.is_uppercase()) && name.chars().any(|c| c.is_lowercase()) {
        confidence += 0.1;
    }
    
    // Penalize very long names (likely not instruction names)
    if name.len() > 25 {
        confidence -= 0.2;
    }
    
    // Cap confidence between 0.0 and 1.0
    confidence.max(0.0).min(1.0)
}

/// Check if a string is likely an account name
pub fn is_likely_account_name(name: &str) -> bool {
    // Common account name patterns
    let account_patterns = [
        "account", "state", "config", "data", "info", "metadata",
        "token", "mint", "vault", "pool", "authority", "signer",
    ];
    
    // Account names are typically nouns
    account_patterns.iter().any(|&pattern| {
        name.to_lowercase().contains(pattern)
    }) || 
    // Account names often end with "Account"
    name.ends_with("Account") || 
    // PDA accounts often have descriptive names
    (name.len() > 3 && !name.contains(|c: char| c.is_ascii_punctuation() && c != '_'))
}

/// Calculate confidence score for an account name
pub fn calculate_account_name_confidence(name: &str) -> f64 {
    let mut confidence: f64 = 0.5; // Base confidence
    
    // Boost confidence for common account name patterns
    let account_patterns = [
        "account", "state", "config", "data", "info", "metadata",
        "token", "mint", "vault", "pool", "authority", "signer",
    ];
    
    for pattern in account_patterns {
        if name.to_lowercase().contains(pattern) {
            confidence += 0.2;
            break;
        }
    }
    
    // Boost for names ending with "Account"
    if name.ends_with("Account") {
        confidence += 0.3;
    }
    
    // Boost for PascalCase naming (common for account types in Solana)
    if name.chars().next().map_or(false, |c| c.is_uppercase()) {
        confidence += 0.1;
    }
    
    // Cap confidence between 0.0 and 1.0
    confidence.max(0.0).min(1.0)
}

/// Check if a string is likely a field name
pub fn is_likely_field_name(name: &str) -> bool {
    // Field names are typically short and descriptive
    if name.len() < 3 || name.len() > 30 {
        return false;
    }
    
    // Field names shouldn't contain spaces
    if name.contains(' ') {
        return false;
    }
    
    // Field names are typically camelCase or snake_case
    let is_camel_case = name.chars().next().map_or(false, |c| c.is_lowercase()) && 
                        name.chars().any(|c| c.is_uppercase());
    let is_snake_case = name.contains('_') && !name.contains(char::is_uppercase);
    
    is_camel_case || is_snake_case || 
    // Common field name patterns
    ["amount", "balance", "count", "id", "name", "value", "address", "key", "data"]
        .iter()
        .any(|&pattern| name.to_lowercase() == pattern)
}

/// Calculate confidence score for a field name
pub fn calculate_field_name_confidence(name: &str) -> f64 {
    let mut confidence: f64 = 0.5; // Base confidence
    
    // Boost for camelCase (common for fields in Solana)
    let is_camel_case = name.chars().next().map_or(false, |c| c.is_lowercase()) && 
                        name.chars().any(|c| c.is_uppercase());
    if is_camel_case {
        confidence += 0.2;
    }
    
    // Boost for snake_case (common in Rust)
    let is_snake_case = name.contains('_') && !name.contains(char::is_uppercase);
    if is_snake_case {
        confidence += 0.2;
    }
    
    // Boost for common field name patterns
    let field_patterns = ["amount", "balance", "count", "id", "name", "value", "address", "key", "data"];
    for pattern in field_patterns {
        if name.to_lowercase() == pattern {
            confidence += 0.3;
            break;
        }
    }
    
    // Penalize very short names (likely not meaningful)
    if name.len() < 3 {
        confidence -= 0.2;
    }
    
    // Cap confidence between 0.0 and 1.0
    confidence.max(0.0).min(1.0)
}

/// Apply heuristics to improve confidence scores
fn apply_naming_heuristics(result: &mut StringAnalysisResult) {
    // Boost scores for common Solana naming patterns
    for (name, score) in &mut result.instruction_names {
        // Boost CamelCase names that look like instructions
        if name.chars().next().unwrap_or('_').is_uppercase() && 
           name.contains(char::is_lowercase) {
            *score *= 1.2;
        }
        
        // Boost scores for verb-noun patterns (e.g., "createAccount")
        if let Some(verb_idx) = find_verb_in_camel_case(name) {
            if verb_idx > 0 {
                *score *= 1.3;
            }
        }
    }
    
    // Similar heuristics for account names and field names
    // ...
}

/// Find a verb in a camelCase string
fn find_verb_in_camel_case(s: &str) -> Option<usize> {
    // Common verbs in Solana instructions
    let verbs = ["create", "update", "delete", "set", "get", "add", "remove"];
    
    // Convert to lowercase for comparison
    let lower = s.to_lowercase();
    
    // Find the first verb
    verbs.iter()
        .filter_map(|&verb| lower.find(verb).map(|idx| (verb, idx)))
        .min_by_key(|&(_, idx)| idx)
        .map(|(_, idx)| idx)
}

/// Convert a string to snake_case
fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    let mut prev_is_lowercase = false;
    
    for c in s.chars() {
        if c.is_uppercase() && prev_is_lowercase {
            result.push('_');
        }
        result.push(c.to_lowercase().next().unwrap());
        prev_is_lowercase = c.is_lowercase();
    }
    
    result
}



/// Extract string constants from an ELF analyzer
pub fn extract_string_constants(elf_analyzer: &ElfAnalyzer) -> Result<Vec<String>> {
    elf_analyzer.extract_strings()
}

/// Enhanced string analysis
pub fn enhanced_string_analysis(strings: &[String]) -> Result<StringAnalysisResult> {
    let mut name_scores = HashMap::new();
    
    // 1. Score strings based on naming conventions
    for string in strings {
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
    
    Ok(StringAnalysisResult {
        instruction_names: name_scores,
        account_names: HashMap::new(),
        field_names: HashMap::new(),
    })

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
pub fn improved_string_analyzer(program_data: &[u8]) -> Result<StringAnalysisResult> {
    // Get strings from the program
    let elf_analyzer = ElfAnalyzer::from_bytes(program_data.to_vec())?;
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
    let (blocks, functions) = cfg::build_cfg(&instructions)?; // this too
    
    // Perform multiple types of string analysis
    let basic_scores = enhanced_string_analysis(&string_constants)?;
    let instruction_scores = analyze_instruction_strings(&instructions, &indexed_strings);
    let context_scores = context_aware_string_analysis(program_data, &functions, &blocks, &indexed_strings);
    
    // Combine scores from different analyses
    let mut combined_scores = HashMap::new();
    
    // Add scores from basic analysis
    for (name, score) in basic_scores.instruction_names {
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
            // Filter out error messages and other non-instruction strings
            !name.contains("error") && 
            !name.contains("failed") && 
            !name.contains("invalid") &&
            !name.contains("expected") &&
            !name.contains("assert") &&
            !name.contains("overflow") &&
            !name.contains("attempt") &&
            !name.contains("panic") &&
            !name.contains("unwrap") &&
            name.len() < 40 &&
            *score > 0.5
        })
        .collect();
    
    // Create the result
    let result = StringAnalysisResult {
        field_names: filtered_scores.clone(),
        account_names: HashMap::new(),  // You could implement similar analysis for account names
        instruction_names: filtered_scores,  // Add the missing field
    };
    
    Ok(result)
} 