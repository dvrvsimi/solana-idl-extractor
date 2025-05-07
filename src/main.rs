use anyhow::Result;
use solana_idl_extractor::{extract_idl, extract_idl_with_simulation, cache::Cache};
use solana_pubkey::Pubkey;
use std::path::PathBuf;
use std::str::FromStr;
use env_logger::Builder;
use log::LevelFilter;
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
    
    // Check for --version command
    if args.len() > 1 && (args[1] == "--version" || args[1] == "-v") {
        println!("Solana IDL Extractor v{}", solana_idl_extractor::VERSION);
        return Ok(());
    }
    
    // Check for --clear-cache command
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
        println!("Solana IDL Extractor v{}", solana_idl_extractor::VERSION);
        println!("\nUsage:");
        println!("  {} <PROGRAM_ID> [--output PATH] [--cluster URL] [--no-cache] [--simulate]", args[0]);
        println!("  {} --clear-cache [PROGRAM_ID]", args[0]);
        println!("  {} --version", args[0]);
        println!("\nOptions:");
        println!("  --output, -o PATH    Save IDL to the specified file path");
        println!("  --cluster, -c URL    Use the specified RPC URL (default: mainnet-beta)");
        println!("  --no-cache           Don't use cached results");
        println!("  --simulate, -s       Enhance IDL with transaction simulation");
        println!("  --clear-cache        Clear the cache for all programs or a specific program");
        println!("  --version, -v        Show version information");
        println!("  --file, -f PATH      Use the specified file as the program data");
        return Ok(());
    }
    
    let program_id_str = &args[1];
    let program_id = match Pubkey::from_str(program_id_str) {
        Ok(id) => id,
        Err(e) => {
            // If we're using a file, we can use a dummy program ID
            if args.len() > 2 && (args[2] == "--file" || args[2] == "-f") {
                // Use a dummy program ID for file analysis
                Pubkey::new_unique()
            } else {
                // Otherwise, return the error
                return Err(anyhow::anyhow!("Invalid program ID: {}", e));
            }
        }
    };
    
    // Parse optional arguments
    let mut output_path = None;
    let mut cluster = "https://api.mainnet-beta.solana.com".to_string();
    let mut no_cache = false;
    let mut simulate = false;
    let mut file_path = None;
    
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
            "--file" | "-f" => {
                if i + 1 < args.len() {
                    file_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    println!("Error: Missing value for --file");
                    return Ok(());
                }
            },
            "--no-cache" => {
                no_cache = true;
                i += 1;
            },
            "--simulate" | "-s" => {
                simulate = true;
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
    let idl = if let Some(path) = file_path {
        println!("Using local file: {}", path.display());
        // Read the file
        let program_data = std::fs::read(&path)
            .map_err(|e| anyhow::anyhow!("Failed to read file {}: {}", path.display(), e))?;
        
        // Analyze the program data directly
        let bytecode_analysis = solana_idl_extractor::analyzer::bytecode::analyze(&program_data, &program_id.to_string())
            .map_err(|e| anyhow::anyhow!("Failed to analyze bytecode: {}", e))?;
        
        // Create a basic IDL
        let mut idl = solana_idl_extractor::models::idl::IDL::new(
            format!("program_{}", program_id.to_string().chars().take(10).collect::<String>()), 
            program_id.to_string()
        );
        
        // Add instructions
        for instruction in bytecode_analysis.instructions {
            idl.add_instruction(instruction);
        }
        
        // Add accounts
        for account in bytecode_analysis.accounts {
            idl.add_account(account);
        }
        
        // Set metadata
        idl.metadata.address = program_id.to_string();
        idl.metadata.origin = "file".to_string();
        
        idl
    } else if simulate {
        println!("Using transaction simulation to enhance IDL...");
        extract_idl_with_simulation(&program_id, &cluster, output_path.as_deref(), !no_cache).await?
    } else {
        extract_idl(&program_id, &cluster, output_path.as_deref(), !no_cache).await?
    };
    
    // Print IDL if no output path specified
    if output_path.is_none() {
        println!("{}", serde_json::to_string_pretty(&idl)?);
    } else {
        println!("Successfully extracted IDL for program: {}", program_id);
        println!("Saved to: {}", output_path.unwrap().display());
    }
    
    Ok(())
} 