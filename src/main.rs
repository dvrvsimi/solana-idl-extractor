use anyhow::Result;
use clap::{App, Arg};
use solana_idl_extractor::{extract_idl, VERSION};
use solana_sdk::pubkey::Pubkey;
use std::path::PathBuf;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    env_logger::init();
    
    // Parse command line arguments
    let matches = App::new("Solana IDL Extractor")
        .version(VERSION)
        .author("Solana IDL Extractor Team")
        .about("A tool to extract Interface Description Language (IDL) from Solana programs")
        .arg(
            Arg::with_name("PROGRAM_ID")
                .help("Program ID to extract IDL for")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("FILE")
                .help("Output file path")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cluster")
                .short("c")
                .long("cluster")
                .value_name("CLUSTER")
                .help("Solana cluster to use (mainnet, devnet, testnet, localhost)")
                .takes_value(true)
                .default_value("mainnet"),
        )
        .arg(
            Arg::with_name("url")
                .short("u")
                .long("url")
                .value_name("URL")
                .help("Custom RPC URL (overrides cluster)")
                .takes_value(true),
        )
        .get_matches();
    
    // Get program ID
    let program_id_str = matches.value_of("PROGRAM_ID").unwrap();
    let program_id = Pubkey::from_str(program_id_str)?;
    
    // Get output path
    let output_path = matches.value_of("output").map(PathBuf::from);
    
    // Get RPC URL based on cluster or custom URL
    let rpc_url = if let Some(url) = matches.value_of("url") {
        url.to_string()
    } else {
        let cluster = matches.value_of("cluster").unwrap();
        match cluster {
            "mainnet" => "https://api.mainnet-beta.solana.com".to_string(),
            "devnet" => "https://api.devnet.solana.com".to_string(),
            "testnet" => "https://api.testnet.solana.com".to_string(),
            "localhost" => "http://localhost:8899".to_string(),
            _ => {
                eprintln!("Unknown cluster: {}", cluster);
                eprintln!("Using mainnet as fallback");
                "https://api.mainnet-beta.solana.com".to_string()
            }
        }
    };
    
    println!("Extracting IDL for program: {}", program_id);
    println!("Using RPC URL: {}", rpc_url);
    
    // Extract IDL
    let idl = extract_idl(
        &program_id,
        &rpc_url,
        output_path.as_deref(),
    ).await?;
    
    // Print summary
    println!("Extracted IDL for program: {}", idl.name);
    println!("Instructions: {}", idl.instructions.len());
    println!("Accounts: {}", idl.accounts.len());
    
    if let Some(path) = output_path {
        println!("IDL saved to: {}", path.display());
    } else {
        // Print IDL to stdout
        println!("\nIDL:");
        println!("{}", serde_json::to_string_pretty(&idl)?);
    }
    
    Ok(())
} 