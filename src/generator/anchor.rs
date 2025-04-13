//! Anchor IDL format generation

use anyhow::Result;
use crate::models::idl::IDL;

/// Generate an Anchor-compatible IDL
pub fn generate(idl: &IDL) -> Result<String> {
    // Convert our internal IDL to Anchor's IDL format
    let json = serde_json::to_string_pretty(idl)?;
    Ok(json)
}

/// Convert our internal IDL to Anchor's IDL format
pub fn to_anchor_format(idl: &IDL) -> Result<serde_json::Value> {
    // Placeholder implementation
    // In a real implementation, this would convert our internal IDL
    // to Anchor's IDL format
    
    let json = serde_json::to_value(idl)?;
    Ok(json)
} 