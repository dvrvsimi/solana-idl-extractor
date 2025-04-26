//! Transaction pattern model

use serde::{Serialize, Deserialize};

/// Pattern for a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionPattern {
    /// Instruction discriminator
    pub discriminator: u8,
    /// Account patterns
    pub account_patterns: Vec<AccountPattern>,
    /// Data patterns
    pub data_patterns: Vec<DataPattern>,
    /// Frequency of this pattern
    pub frequency: usize,
}

/// Pattern for an account in a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountPattern {
    /// Account index
    pub index: usize,
    /// Whether the account is a signer
    pub is_signer: bool,
    /// Whether the account is writable
    pub is_writable: bool,
    /// Frequency of this pattern
    pub frequency: usize,
}

/// Pattern for data in a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPattern {
    /// Data index
    pub index: usize,
    /// Type hint
    pub type_hint: String,
    /// Frequency of this pattern
    pub frequency: usize,
} 