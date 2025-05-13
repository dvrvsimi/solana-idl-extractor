//! Anchor-related utility functions for Solana IDL extraction
//! 

use crate::utils::pattern::extract_after_pattern;
use crate::constants::anchor::INSTRUCTION_PREFIX;
use anyhow::Result;
use log::debug;

/// Extract Anchor version from program data
pub fn extract_anchor_version(program_data: &[u8], anchor_version_prefix: &[u8]) -> Option<String> {
    // Look for version pattern in .rodata section
    extract_after_pattern(program_data, anchor_version_prefix, &[0, b'\n', b' '])
}

/// Helper function to find string patterns
pub fn find_string(data: &[u8], pattern: &[u8]) -> bool {
    data.windows(pattern.len())
        .any(|window| window == pattern)
}

/// Extract instruction handlers from an Anchor program
pub fn extract_instruction_handlers(program_data: &[u8]) -> Result<Vec<String>> {
    let mut handlers = Vec::new();
    // Find all occurrences of "Instruction: X" in the program data
    for (i, window) in program_data.windows(INSTRUCTION_PREFIX.len()).enumerate() {
        if window == INSTRUCTION_PREFIX {
            // Extract the instruction name
            let start = i + INSTRUCTION_PREFIX.len();
            let mut end = start;
            while end < program_data.len() && program_data[end] != 0 && program_data[end] != b'\n' {
                end += 1;
            }
            if let Ok(name) = std::str::from_utf8(&program_data[start..end]) {
                if !name.is_empty() && !handlers.contains(&name.to_string()) {
                    handlers.push(name.to_string());
                }
            }
        }
    }
    debug!("Found {} instruction handlers", handlers.len());
    Ok(handlers)
}

