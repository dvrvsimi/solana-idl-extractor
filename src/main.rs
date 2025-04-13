use std::path::PathBuf;
use anyhow::Result;
use clap::Parser;
use solana_sdk::pubkey::Pubkey;
use solana_idl_extractor::extract_idl;

/// A tool to extract Interface Description Language (IDL) from Solana programs
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Program ID to extract IDL from
    #[clap(short, long)]
    program_id: String,
    
    /// RPC URL to use
    #[clap(short, long, default_value = "https://api.mainnet-beta.solana.com")]
    rpc_url: String,
    
    /// Output file path
    #[clap(short, long)]
    output: Option<PathBuf>,
    
    /// Generate TypeScript client code
    #[clap(short, long)]
    typescript: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    let args = Args::parse();
    
    // Parse program ID
    let program_id = args.program_id.parse::<Pubkey>()?;
    
    println!("Extracting IDL for program: {}", program_id);
    println!("Using RPC URL: {}", args.rpc_url);
    
    // Extract IDL
    let idl = extract_idl(&program_id, &args.rpc_url, args.output.as_deref()).await?;
    
    println!("Successfully extracted IDL with {} instructions and {} accounts",
        idl.instructions.len(),
        idl.accounts.len()
    );
    
    // Generate TypeScript client code if requested
    if args.typescript {
        if let Some(output) = &args.output {
            let ts_path = output.with_extension("ts");
            let ts_code = solana_idl_extractor::generator::custom::generate_typescript(&idl)?;
            std::fs::write(ts_path, ts_code)?;
            println!("Generated TypeScript client code: {}", ts_path.display());
        } else {
            println!("Cannot generate TypeScript client code without an output path");
        }
    }
    
    Ok(())
}
