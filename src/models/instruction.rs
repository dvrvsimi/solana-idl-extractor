//! Instruction metadata for Solana programs

use serde::{Serialize, Deserialize};
// Remove conflicting imports
// use solana_instruction::account_meta::AccountMeta;
// use crate::models::instruction::{Instruction, Argument};

/// Represents a program instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    /// Instruction name
    pub name: String,
    /// Instruction index/discriminator byte
    pub index: u8,
    /// Anchor discriminator (8 bytes)
    pub discriminator: Option<[u8; 8]>,
    /// Required accounts
    pub accounts: Vec<AccountMeta>,
    /// Instruction arguments
    pub args: Vec<Argument>,
    /// Documentation
    pub docs: Option<String>,
}

/// Represents an instruction argument
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argument {
    /// Argument name
    pub name: String,
    /// Argument type
    pub ty: String,
    /// Documentation
    pub docs: Option<String>,
}

/// Represents an account used by an instruction
/// This is our own AccountMeta, not solana_instruction::AccountMeta
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountMeta {
    /// Account name
    pub name: String,
    /// Is this account a signer?
    pub is_signer: bool,
    /// Is this account writable?
    pub is_writable: bool,
    /// Is this account optional?
    pub is_optional: bool,
    /// Documentation
    pub docs: Option<String>,
}

impl Instruction {
    /// Create a new instruction
    pub fn new(name: String, index: u8) -> Self {
        Self {
            name,
            index,
            discriminator: None,
            accounts: Vec::new(),
            args: Vec::new(),
            docs: None,
        }
    }
    
    /// Add an account to the instruction
    pub fn add_account(&mut self, name: String, is_signer: bool, is_writable: bool, is_optional: bool) {
        self.accounts.push(AccountMeta {
            name,
            is_signer,
            is_writable,
            is_optional,
            docs: None,
        });
    }
    
    /// Add an argument to the instruction
    pub fn add_arg(&mut self, name: String, ty: String) {
        self.args.push(Argument {
            name,
            ty,
            docs: None,
        });
    }
}

impl AccountMeta {
    /// Convert to solana_instruction::AccountMeta
    pub fn to_solana_account_meta(&self, pubkey: &solana_pubkey::Pubkey) -> solana_instruction::AccountMeta {
        if self.is_writable {
            if self.is_signer {
                solana_instruction::AccountMeta::new(*pubkey, true)
            } else {
                solana_instruction::AccountMeta::new_readonly(*pubkey, false)
            }
        } else {
            if self.is_signer {
                solana_instruction::AccountMeta::new(*pubkey, true)
            } else {
                solana_instruction::AccountMeta::new_readonly(*pubkey, false)
            }
        }
    }
    
    /// Create from solana_instruction::AccountMeta
    pub fn from_solana_account_meta(
        meta: &solana_instruction::AccountMeta, 
        name: String, 
        is_optional: bool
    ) -> Self {
        Self {
            name,
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
            is_optional,
            docs: None,
        }
    }
} 