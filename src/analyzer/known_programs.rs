//! Analysis for known Solana programs

use anyhow::Result;
use solana_sdk::pubkey::Pubkey;
use crate::models::idl::IDL;
use crate::models::instruction::Instruction;
use crate::models::account::Account;
use log::info;

/// Analyze the Token program
pub fn analyze_token_program(program_id: &Pubkey) -> Result<IDL> {
    info!("Using specialized analysis for Token program");
    
    // Create IDL
    let mut idl = IDL::new("TokenProgram".to_string(), program_id.to_string());
    
    // Add instructions
    let mut init_mint = Instruction::new("initializeMint".to_string(), 0);
    init_mint.add_arg("decimals".to_string(), "u8".to_string());
    init_mint.add_arg("mintAuthority".to_string(), "pubkey".to_string());
    init_mint.add_arg("freezeAuthority".to_string(), "pubkey".to_string());
    init_mint.add_account("mint".to_string(), false, true, false);
    init_mint.add_account("rent".to_string(), false, false, false);
    
    let mut init_account = Instruction::new("initializeAccount".to_string(), 1);
    init_account.add_account("account".to_string(), false, true, false);
    init_account.add_account("mint".to_string(), false, false, false);
    init_account.add_account("owner".to_string(), false, false, false);
    init_account.add_account("rent".to_string(), false, false, false);
    
    let mut transfer = Instruction::new("transfer".to_string(), 3);
    transfer.add_arg("amount".to_string(), "u64".to_string());
    transfer.add_account("source".to_string(), false, true, false);
    transfer.add_account("destination".to_string(), false, true, false);
    transfer.add_account("authority".to_string(), true, false, false);
    
    let mut approve = Instruction::new("approve".to_string(), 4);
    approve.add_arg("amount".to_string(), "u64".to_string());
    approve.add_account("source".to_string(), false, true, false);
    approve.add_account("delegate".to_string(), false, false, false);
    approve.add_account("owner".to_string(), true, false, false);
    
    let mut revoke = Instruction::new("revoke".to_string(), 5);
    revoke.add_account("source".to_string(), false, true, false);
    revoke.add_account("owner".to_string(), true, false, false);
    
    let mut set_authority = Instruction::new("setAuthority".to_string(), 6);
    set_authority.add_arg("authorityType".to_string(), "u8".to_string());
    set_authority.add_arg("newAuthority".to_string(), "pubkey".to_string());
    set_authority.add_account("account".to_string(), false, true, false);
    set_authority.add_account("currentAuthority".to_string(), true, false, false);
    
    let mut mint_to = Instruction::new("mintTo".to_string(), 7);
    mint_to.add_arg("amount".to_string(), "u64".to_string());
    mint_to.add_account("mint".to_string(), false, true, false);
    mint_to.add_account("destination".to_string(), false, true, false);
    mint_to.add_account("authority".to_string(), true, false, false);
    
    let mut burn = Instruction::new("burn".to_string(), 8);
    burn.add_arg("amount".to_string(), "u64".to_string());
    burn.add_account("account".to_string(), false, true, false);
    burn.add_account("mint".to_string(), false, true, false);
    burn.add_account("owner".to_string(), true, false, false);
    
    let mut close_account = Instruction::new("closeAccount".to_string(), 9);
    close_account.add_account("account".to_string(), false, true, false);
    close_account.add_account("destination".to_string(), false, true, false);
    close_account.add_account("owner".to_string(), true, false, false);
    
    idl.add_instruction(init_mint);
    idl.add_instruction(init_account);
    idl.add_instruction(transfer);
    idl.add_instruction(approve);
    idl.add_instruction(revoke);
    idl.add_instruction(set_authority);
    idl.add_instruction(mint_to);
    idl.add_instruction(burn);
    idl.add_instruction(close_account);
    
    // Add accounts
    let mut token_account = Account::new("Token".to_string(), "token".to_string());
    token_account.add_field("mint".to_string(), "pubkey".to_string(), 0);
    token_account.add_field("owner".to_string(), "pubkey".to_string(), 32);
    token_account.add_field("amount".to_string(), "u64".to_string(), 64);
    token_account.add_field("delegate".to_string(), "pubkey".to_string(), 72);
    token_account.add_field("state".to_string(), "u8".to_string(), 104);
    token_account.add_field("is_native".to_string(), "bool".to_string(), 105);
    
    let mut mint_account = Account::new("Mint".to_string(), "mint".to_string());
    mint_account.add_field("mint_authority".to_string(), "pubkey".to_string(), 0);
    mint_account.add_field("supply".to_string(), "u64".to_string(), 32);
    mint_account.add_field("decimals".to_string(), "u8".to_string(), 40);
    mint_account.add_field("is_initialized".to_string(), "bool".to_string(), 41);
    mint_account.add_field("freeze_authority".to_string(), "pubkey".to_string(), 42);
    
    idl.add_account(token_account);
    idl.add_account(mint_account);
    
    // Add metadata
    idl.metadata.address = program_id.to_string();
    idl.metadata.origin = "spl-token".to_string();
    
    Ok(idl)
} 