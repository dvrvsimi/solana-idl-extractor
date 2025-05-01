# Solana IDL Extractor

A tool to extract Interface Description Language (IDL) from Solana programs through bytecode analysis and instruction parsing.

## Features

- Extracts instructions, accounts, and error codes from Solana programs
- Works with both Anchor and native Solana programs
- Uses advanced bytecode analysis techniques:
  - Instruction boundary identification
  - Discriminator detection
  - Symbol recovery
  - Syscall analysis
  - Pattern-based naming

## Installation

```bash
# Clone the repository
git clone https://github.com/dvrvsimi/solana-idl-extractor.git
cd solana-idl-extractor

# Build the project
cargo build --release

# Install globally (optional)
cargo install --path .
```

## Usage

```bash
solana-idl-extractor <PROGRAM_ID> [--output PATH] [--cluster URL] [--no-cache] [--simulate]
```

### Options

- `--output, -o PATH` - Save IDL to the specified file path
- `--cluster, -c URL` - Use the specified RPC URL (default: mainnet-beta)
- `--no-cache` - Don't use cached results
- `--simulate, -s` - Enhance IDL with transaction simulation
- `--clear-cache` - Clear the cache for all programs or a specific program
- `--version, -v` - Show version information

### Examples

```bash
# Extract IDL for the Token program and print to console
solana-idl-extractor TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA

# Extract IDL and save to a file
solana-idl-extractor TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA --output token_idl.json

# Use a different RPC endpoint
solana-idl-extractor TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA --cluster https://api.devnet.solana.com

# Use simulation to enhance IDL accuracy
solana-idl-extractor TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA --simulate

# Clear cache for a specific program
solana-idl-extractor --clear-cache TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA

# Clear all cached IDLs
solana-idl-extractor --clear-cache
```

## Library Usage

You can also use Solana IDL Extractor as a library in your Rust projects:

```rust
use solana_idl_extractor::{extract_idl, extract_idl_with_simulation};
use solana_pubkey::Pubkey;
use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let program_id = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?;
    let rpc_url = "https://api.mainnet-beta.solana.com";
    
    // Basic IDL extraction
    let idl = extract_idl(&program_id, rpc_url, None, true).await?;
    println!("{}", serde_json::to_string_pretty(&idl)?);
    
    // Enhanced IDL extraction with simulation
    let enhanced_idl = extract_idl_with_simulation(&program_id, rpc_url, None, true).await?;
    
    Ok(())
}
```

## Generated Output

The extracted IDL includes:

- Program instructions with their parameters and accounts
- Account structures and their fields
- Error codes and messages
- Metadata about the program (Anchor vs. native, etc.)

## How It Works

Solana IDL Extractor uses several techniques to analyze Solana programs:

1. **Bytecode Analysis**: Disassembles the program's ELF binary to identify instruction boundaries, control flow, and memory access patterns.

2. **Discriminator Detection**: Identifies Anchor discriminators and other instruction identifiers.

3. **Transaction Pattern Analysis**: Analyzes historical transactions to understand instruction usage patterns.

4. **Simulation**: Optionally simulates transactions to gather more accurate information about instruction parameters and accounts.

5. **Symbol Recovery**: Attempts to recover meaningful names from strings and patterns in the program.

## Limitations

- Not all program instructions may be detected, especially for complex or obfuscated programs
- Parameter types may be inferred incorrectly in some cases
- Account structure detection is best-effort and may not be complete
- Anchor programs are more accurately analyzed than native programs

## License

This project is licensed under either of:

- MIT License
- Apache License, Version 2.0

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.