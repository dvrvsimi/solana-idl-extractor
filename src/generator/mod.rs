//! IDL generation for Solana programs

mod anchor;
mod custom;

use std::path::Path;
use std::fs;
use anyhow::Result;
use crate::models::idl::IDL;

/// Save the IDL to a file
pub fn save_idl(idl: &IDL, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(idl)?;
    fs::write(path, json)?;
    Ok(())
}

/// Generate an Anchor-compatible IDL
pub fn generate_anchor_idl(idl: &IDL) -> Result<String> {
    anchor::generate(idl)
}

/// Generate a custom IDL format
pub fn generate_custom_idl(idl: &IDL) -> Result<String> {
    custom::generate(idl)
} 