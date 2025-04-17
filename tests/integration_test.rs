use solana_idl_extractor::{extract_idl, models::idl::IDL};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use tempfile::tempdir;

#[tokio::test]
async fn test_extract_idl() {
    // Use a known program ID for testing
    let program_id = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
    
    // Use a public RPC endpoint for testing
    let rpc_url = "https://api.mainnet-beta.solana.com";
    
    // Create a temporary directory for the output
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("token_program_idl.json");
    
    // Extract the IDL
    let result = extract_idl(&program_id, rpc_url, Some(&output_path)).await;
    
    // This might fail in CI environments without network access
    if result.is_ok() {
        let idl = result.unwrap();
        
        // Verify basic properties
        assert_eq!(idl.program_id, program_id.to_string());
        
        // Verify the file was created
        assert!(output_path.exists());
    }
} 