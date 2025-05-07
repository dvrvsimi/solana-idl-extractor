//! Enhanced string analysis for better naming in IDL extraction

use anyhow::{Result, anyhow};
use log::{debug, info};
use std::collections::HashMap;

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
pub fn analyze_strings(strings: &[String]) -> Result<StringAnalysisResult> {
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
        result.field_names.insert(cleaned, confidence);
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
    ];
    
    // Check if string contains any instruction pattern
    instruction_patterns.iter().any(|&pattern| {
        string.contains(pattern) || 
        string.starts_with(pattern) || 
        string.ends_with(pattern)
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