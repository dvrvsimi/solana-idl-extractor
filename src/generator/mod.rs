//! IDL generation for Solana programs

mod anchor;
mod custom;

use std::path::Path;
use std::fs;
use anyhow::Result;
use crate::models::idl::IDL;
use std::fs::File;
use std::io::Write;
use anyhow::Context;
use log::{info, debug, error};

/// Save the IDL to a file
pub fn save_idl(idl: &IDL, path: &Path) -> Result<()> {
    // Log the absolute path
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    
    info!("Saving IDL to absolute path: {}", absolute_path.display());
    
    // Create parent directories if they don't exist
    if let Some(parent) = absolute_path.parent() {
        if !parent.exists() {
            info!("Creating directory: {}", parent.display());
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }
    }
    
    // Serialize IDL to JSON
    let json = serde_json::to_string_pretty(idl)
        .with_context(|| "Failed to serialize IDL to JSON")?;
    
    info!("Serialized IDL to JSON ({} bytes)", json.len());
    
    // Write to file
    let mut file = match File::create(&absolute_path) {
        Ok(f) => {
            info!("Successfully created file: {}", absolute_path.display());
            f
        },
        Err(e) => {
            error!("Failed to create file: {} - Error: {}", absolute_path.display(), e);
            return Err(anyhow::anyhow!("Failed to create file: {} - Error: {}", absolute_path.display(), e));
        }
    };
    
    match file.write_all(json.as_bytes()) {
        Ok(_) => {
            info!("Successfully wrote {} bytes to file: {}", json.len(), absolute_path.display());
        },
        Err(e) => {
            error!("Failed to write to file: {} - Error: {}", absolute_path.display(), e);
            return Err(anyhow::anyhow!("Failed to write to file: {} - Error: {}", absolute_path.display(), e));
        }
    }
    
    info!("IDL saved successfully to: {}", absolute_path.display());
    
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

/// Generate IDL in Anchor format
pub fn to_anchor_format(idl: &IDL) -> Result<serde_json::Value> {
    anchor::to_anchor_format(idl)
}

/// Generate TypeScript client code
pub fn generate_typescript(idl: &IDL) -> Result<String> {
    custom::generate_typescript(idl)
} 