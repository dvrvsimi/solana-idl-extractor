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
    info!("Saving IDL to {}", path.display());
    
    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }
    
    // Serialize IDL to JSON
    let json = serde_json::to_string_pretty(idl)
        .context("Failed to serialize IDL to JSON")?;
    
    // Write to file
    let mut file = File::create(path)
        .with_context(|| format!("Failed to create file: {}", path.display()))?;
    
    file.write_all(json.as_bytes())
        .with_context(|| format!("Failed to write to file: {}", path.display()))?;
    
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
    // This is a placeholder for TypeScript client code generation
    // In a real implementation, this would generate TypeScript code based on the IDL
    
    let mut ts_code = String::new();
    
    // Add imports
    ts_code.push_str("import * as web3 from '@solana/web3.js';\n");
    ts_code.push_str("import * as borsh from 'borsh';\n\n");
    
    // Add program ID
    ts_code.push_str(&format!("export const PROGRAM_ID = new web3.PublicKey('{}');\n\n", idl.metadata.address));
    
    // Add instruction enum
    ts_code.push_str("export enum Instructions {\n");
    for instruction in &idl.instructions {
        ts_code.push_str(&format!("  {} = {},\n", instruction.name, instruction.index));
    }
    ts_code.push_str("}\n\n");
    
    // Add account classes
    for account in &idl.accounts {
        ts_code.push_str(&format!("export class {} {{\n", account.name));
        
        // Add fields
        for field in &account.fields {
            ts_code.push_str(&format!("  {}?: {};\n", field.name, ts_type_for_rust_type(&field.ty)));
        }
        
        ts_code.push_str("}\n\n");
    }
    
    // Add client class
    ts_code.push_str(&format!("export class {}Client {{\n", idl.name));
    ts_code.push_str("  constructor(private connection: web3.Connection, private programId: web3.PublicKey = PROGRAM_ID) {}\n\n");
    
    // Add instruction methods
    for instruction in &idl.instructions {
        ts_code.push_str(&format!("  async {}(", instruction.name));
        
        // Add parameters
        let mut params = Vec::new();
        for arg in &instruction.args {
            params.push(format!("{}: {}", arg.name, ts_type_for_rust_type(&arg.ty)));
        }
        
        // Add accounts parameter
        params.push("accounts: Array<web3.AccountMeta>".to_string());
        params.push("payer: web3.Keypair".to_string());
        
        ts_code.push_str(&params.join(", "));
        ts_code.push_str("): Promise<string> {\n");
        
        // Method implementation
        ts_code.push_str("    // Create instruction data\n");
        ts_code.push_str(&format!("    const data = Buffer.from([{}]);\n", instruction.index));
        
        ts_code.push_str("    // Create transaction\n");
        ts_code.push_str("    const instruction = new web3.TransactionInstruction({\n");
        ts_code.push_str("      keys: accounts,\n");
        ts_code.push_str("      programId: this.programId,\n");
        ts_code.push_str("      data,\n");
        ts_code.push_str("    });\n\n");
        
        ts_code.push_str("    const transaction = new web3.Transaction().add(instruction);\n");
        ts_code.push_str("    return await web3.sendAndConfirmTransaction(this.connection, transaction, [payer]);\n");
        ts_code.push_str("  }\n\n");
    }
    
    ts_code.push_str("}\n");
    
    Ok(ts_code)
}

/// Convert Rust type to TypeScript type
fn ts_type_for_rust_type(rust_type: &str) -> String {
    match rust_type {
        "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | "f32" | "f64" => "number".to_string(),
        "bool" => "boolean".to_string(),
        "String" | "str" => "string".to_string(),
        "Pubkey" => "web3.PublicKey".to_string(),
        "bytes" => "Buffer".to_string(),
        _ if rust_type.starts_with("[") && rust_type.ends_with("]") => "Array<number>".to_string(),
        _ if rust_type.starts_with("Vec<") && rust_type.ends_with(">") => {
            let inner = &rust_type[4..rust_type.len()-1];
            format!("Array<{}>", ts_type_for_rust_type(inner))
        },
        _ => "any".to_string(),
    }
} 