#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::pubkey::Pubkey;
    use solana_transaction_status::EncodedTransaction;
    
    #[test]
    fn test_transaction_analysis_empty() {
        let program_id = Pubkey::new_unique();
        let transactions = Vec::new();
        
        let result = transaction::analyze(&program_id, &transactions);
        assert!(result.is_ok());
        
        let analysis = result.unwrap();
        assert!(analysis.instructions.is_empty());
        assert!(analysis.frequencies.is_empty());
    }
} 