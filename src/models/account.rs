//! Account structure metadata for Solana programs

use serde::{Serialize, Deserialize};

/// Represents a program account structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Account name
    pub name: String,
    /// Account type (e.g., "state", "data")
    pub ty: String,
    /// Account fields
    pub fields: Vec<AccountField>,
    /// Discriminator for this account
    pub discriminator: Option<Vec<u8>>,
}

/// Represents an account field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountField {
    /// Field name
    pub name: String,
    /// Field type
    pub ty: String,
    /// Field offset in the account data
    pub offset: usize,
}

impl Account {
    /// Create a new account
    pub fn new(name: String, ty: String) -> Self {
        Self {
            name,
            ty,
            fields: Vec::new(),
            discriminator: None,
        }
    }
    
    /// Add a field to the account
    pub fn add_field(&mut self, name: String, ty: String, offset: usize) {
        self.fields.push(AccountField { name, ty, offset });
    }
    
    /// Set the discriminator for this account
    pub fn set_discriminator(&mut self, discriminator: Vec<u8>) {
        self.discriminator = Some(discriminator);
    }
    
    /// Get the discriminator for this account
    pub fn discriminator(&self) -> Option<&Vec<u8>> {
        self.discriminator.as_ref()
    }
} 