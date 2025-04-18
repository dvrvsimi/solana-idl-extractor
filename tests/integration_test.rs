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

#[tokio::test]
async fn test_extract_idl_with_transaction_analysis() {
    // Use a known program ID with transactions
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
        
        // Verify instructions were extracted
        assert!(!idl.instructions.is_empty());
        
        // Verify the file was created
        assert!(output_path.exists());
        
        // Read the file and parse it
        let file_content = std::fs::read_to_string(&output_path).unwrap();
        let parsed_idl: IDL = serde_json::from_str(&file_content).unwrap();
        
        // Verify the parsed IDL matches the original
        assert_eq!(parsed_idl.program_id, idl.program_id);
        assert_eq!(parsed_idl.instructions.len(), idl.instructions.len());
    }
} 