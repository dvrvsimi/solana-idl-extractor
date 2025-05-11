//! Account structure analysis from bytecode

use crate::models::account::Account;
use super::parser::{SbfInstruction, parse_instructions};
use super::elf::ElfAnalyzer;
use super::discriminator_detection::{AnchorDiscriminator, DiscriminatorKind};
use crate::utils::account_analysis::{
    extract_native_account_validations,
    NativeAccountValidation,
    AccountValidationType,
    ConstraintType,
};
use solana_sbpf::static_analysis::Analysis;

/// Extract account structures from bytecode
pub fn extract_account_structures(
    program_data: &[u8],
    analysis: &Analysis,
) -> Result<Vec<Account>, Box<dyn std::error::Error>> { // confirm if this is correct
    let mut accounts = Vec::new();
    
    // Try to parse the ELF file
    let elf_analyzer = ElfAnalyzer::from_bytes(program_data.to_vec())?;
    
    // Get the text section (code)
    if let Ok(Some(text_section)) = elf_analyzer.get_text_section() {
        // Parse instructions
        let instructions = parse_instructions(&text_section.data, text_section.address as usize)?;
        
        // Extract native account validations
        let validations = extract_native_account_validations(&instructions);
        
        // Create accounts based on validations
        for validation in &validations {
            match validation.validation_type {
                AccountValidationType::DataSize => {
                    // Create account with size constraints
                    let mut account = Account::new(format!("account_{}", accounts.len()), "account".to_string());
                    
                    // Add size constraints
                    for constraint in &validation.constraints {
                        match constraint.constraint_type {
                            ConstraintType::MinSize => {
                                if let Some(size) = constraint.value {
                                    account.add_metadata("min_size".to_string(), size.to_string());
                                }
                            }
                            ConstraintType::MaxSize => {
                                if let Some(size) = constraint.value {
                                    account.add_metadata("max_size".to_string(), size.to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                    
                    // Add program ID if known
                    if let Some(program_id) = &validation.program_id {
                        account.add_metadata("owner".to_string(), program_id.clone());
                    }
                    
                    accounts.push(account);
                }
                AccountValidationType::Ownership => {
                    // Create account with ownership constraint
                    let mut account = Account::new(format!("account_{}", accounts.len()), "account".to_string());
                    
                    // Add ownership constraint
                    account.add_metadata("constraints".to_string(), "must_be_program_owned".to_string());
                    
                    // Add program ID if known
                    if let Some(program_id) = &validation.program_id {
                        account.add_metadata("owner".to_string(), program_id.clone());
                    }
                    
                    accounts.push(account);
                }
                AccountValidationType::Signer => {
                    // Create account with signer constraint
                    let mut account = Account::new(format!("account_{}", accounts.len()), "account".to_string());
                    
                    // Add signer constraint
                    account.add_metadata("constraints".to_string(), "must_be_signer".to_string());
                    
                    accounts.push(account);
                }
                _ => {}
            }
        }
        
        // Analyze account relationships
        analyze_account_relationships(&mut accounts, analysis, &instructions);
        
        // Add common fields based on program type
        add_common_fields(&mut accounts, &validations);
    }
    
    Ok(accounts)
}

/// Analyze relationships between accounts
fn analyze_account_relationships(
    accounts: &mut Vec<Account>,
    analysis: &Analysis,
    instructions: &[SbfInstruction]
) {
    // Create a list of mint accounts first
    let mint_accounts: Vec<String> = accounts.iter()
        .filter(|a| a.name.to_lowercase().contains("mint"))
        .map(|a| a.name.clone())
        .collect();
    
    // Then update token accounts
    for account in accounts.iter_mut() {
        if account.name.to_lowercase().contains("token") {
            // Token accounts are related to mints
            if !mint_accounts.is_empty() {
                account.add_field("related_mint".to_string(), "pubkey".to_string(), 8);
            }
        }
    }
}

/// Add common fields based on program type
fn add_common_fields(accounts: &mut Vec<Account>, validations: &[NativeAccountValidation]) {
    // Check if this is a token program
    let is_token_program = validations.iter().any(|v| 
        v.program_id.as_deref() == Some("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
    );
    
    // Check if this is a system program
    let is_system_program = validations.iter().any(|v| 
        v.program_id.as_deref() == Some("11111111111111111111111111111111")
    );
    
    for account in accounts {
        if is_token_program {
            // Add token account fields
            account.add_field("mint".to_string(), "pubkey".to_string(), 8);
            account.add_field("owner".to_string(), "pubkey".to_string(), 40);
            account.add_field("amount".to_string(), "u64".to_string(), 72);
            account.add_field("delegate".to_string(), "pubkey".to_string(), 80);
            account.add_field("state".to_string(), "u8".to_string(), 112);
            account.add_field("is_native".to_string(), "u64".to_string(), 113);
            account.add_field("delegated_amount".to_string(), "u64".to_string(), 121);
            account.add_field("close_authority".to_string(), "pubkey".to_string(), 129);
        } else if is_system_program {
            // Add system account fields
            account.add_field("lamports".to_string(), "u64".to_string(), 0);
            account.add_field("owner".to_string(), "pubkey".to_string(), 8);
            account.add_field("executable".to_string(), "bool".to_string(), 40);
            account.add_field("rent_epoch".to_string(), "u64".to_string(), 41);
        } else {
            // Generic account structure
            account.add_field("authority".to_string(), "pubkey".to_string(), 8);
            account.add_field("data".to_string(), "bytes".to_string(), 40);
        }
    }
} 