use anyhow::Result;
use solana_idl_extractor::{extract_idl, cache::Cache};
use solana_sdk::pubkey::Pubkey;
use std::path::PathBuf;
use std::str::FromStr;
use env_logger::Builder;
use log::{LevelFilter, info};
use std::io::Write;

// Simple CLI without clap
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] - {}",
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                record.level(),
                record.args()
            )
        })
        .filter(None, LevelFilter::Info)
        .init();
    
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    
    // Check for --clear-cache command first, before any other processing
    if args.len() > 1 && args[1] == "--clear-cache" {
        if args.len() > 2 {
            match Pubkey::from_str(&args[2]) {
                Ok(cache_program_id) => {
                    Cache::clear(&cache_program_id)?;
                    println!("Cleared cache for program: {}", cache_program_id);
                },
                Err(_) => {
                    Cache::clear_all()?;
                    println!("Cleared all cached IDLs");
                }
            }
        } else {
            Cache::clear_all()?;
            println!("Cleared all cached IDLs");
        }
        return Ok(());
    }
    
    // Regular command processing for IDL extraction
    if args.len() < 2 {
        println!("Usage: {} <PROGRAM_ID> [--output PATH] [--cluster URL] [--no-cache]", args[0]);
        println!("       {} --clear-cache [PROGRAM_ID]", args[0]);
        return Ok(());
    }
    
    let program_id_str = &args[1];
    let program_id = Pubkey::from_str(program_id_str)?;
    
    // Parse optional arguments
    let mut output_path = None;
    let mut cluster = "https://api.mainnet-beta.solana.com".to_string();
    let mut no_cache = false;
    
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    output_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    println!("Error: Missing value for --output");
                    return Ok(());
                }
            },
            "--cluster" | "-c" => {
                if i + 1 < args.len() {
                    cluster = args[i + 1].clone();
                    i += 2;
                } else {
                    println!("Error: Missing value for --cluster");
                    return Ok(());
                }
            },
            "--no-cache" => {
                no_cache = true;
                i += 1;
            },
            _ => {
                println!("Unknown argument: {}", args[i]);
                i += 1;
            }
        }
    }
    
    // Show progress message
    println!("Extracting IDL for program: {}", program_id);
    
    // Extract IDL
    let idl = extract_idl(&program_id, &cluster, output_path.as_deref(), !no_cache).await?;
    
    // Print IDL if no output path specified
    if output_path.is_none() {
        println!("{}", serde_json::to_string_pretty(&idl)?);
    } else {
        println!("Successfully extracted IDL for program: {}", program_id);
        println!("Saved to: {}", output_path.unwrap().display());
    }
    
    Ok(())
} 