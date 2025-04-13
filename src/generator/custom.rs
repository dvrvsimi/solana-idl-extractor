//! Custom IDL format generation

use anyhow::Result;
use crate::models::idl::IDL;

/// Generate a custom IDL format
pub fn generate(idl: &IDL) -> Result<String> {
    // Convert our internal IDL to a custom format
    let json = serde_json::to_string_pretty(idl)?;
    Ok(json)
}

/// Generate TypeScript client code from the IDL
pub fn generate_typescript(idl: &IDL) -> Result<String> {
    // Placeholder implementation
    // In a real implementation, this would generate TypeScript client code
    // from the IDL
    
    let mut ts_code = String::new();
    
    ts_code.push_str(&format!("// Generated TypeScript client for {}\n\n", idl.name));
    ts_code.push_str("import * as web3 from '@solana/web3.js';\n");
    ts_code.push_str("import * as borsh from 'borsh';\n\n");
    
    // Generate instruction interfaces
    for instruction in &idl.instructions {
        ts_code.push_str(&format!("export interface {}Args {{\n", instruction.name));
        for arg in &instruction.args {
            ts_code.push_str(&format!("  {}: {};\n", arg.name, ts_type_for(&arg.ty)));
        }
        ts_code.push_str("}\n\n");
    }
    
    // Generate account interfaces
    for account in &idl.accounts {
        ts_code.push_str(&format!("export interface {} {{\n", account.name));
        for field in &account.fields {
            ts_code.push_str(&format!("  {}: {};\n", field.name, ts_type_for(&field.ty)));
        }
        ts_code.push_str("}\n\n");
    }
    
    Ok(ts_code)
}

/// Convert a Solana type to a TypeScript type
fn ts_type_for(ty: &str) -> &str {
    match ty {
        "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" => "number",
        "bool" => "boolean",
        "string" => "string",
        "pubkey" => "web3.PublicKey",
        _ if ty.starts_with("vec<") => "Array<any>",
        _ => "any",
    }
} 