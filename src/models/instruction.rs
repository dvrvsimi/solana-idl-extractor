//! Instruction metadata for Solana programs

use serde::{Serialize, Deserialize};

/// Represents a program instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    /// Instruction name
    pub name: String,
    /// Instruction index/discriminator
    pub index: u8,
    /// Instruction arguments
    pub args: Vec<InstructionArg>,
    /// Instruction accounts
    pub accounts: Vec<InstructionAccount>,
}

/// Represents an instruction argument
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionArg {
    /// Argument name
    pub name: String,
    /// Argument type
    pub ty: String,
}

/// Represents an instruction account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionAccount {
    /// Account name
    pub name: String,
    /// Is the account a signer
    pub is_signer: bool,
    /// Is the account writable
    pub is_writable: bool,
    /// Is the account optional
    pub is_optional: bool,
}

impl Instruction {
    /// Create a new instruction
    pub fn new(name: String, index: u8) -> Self {
        Self {
            name,
            index,
            args: Vec::new(),
            accounts: Vec::new(),
        }
    }
    
    /// Add an argument to the instruction
    pub fn add_arg(&mut self, name: String, ty: String) {
        self.args.push(InstructionArg { name, ty });
    }
    
    /// Add an account to the instruction
    pub fn add_account(&mut self, name: String, is_signer: bool, is_writable: bool, is_optional: bool) {
        self.accounts.push(InstructionAccount {
            name,
            is_signer,
            is_writable,
            is_optional,
        });
    }
} 