//! Account structure metadata for Solana programs

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

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
    /// Related accounts
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub related_accounts: Vec<String>,
    /// Child accounts (for hierarchical relationships)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub child_accounts: Vec<String>,
    /// Usage statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_stats: Option<AccountUsageStats>,
    /// metadata
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub metadata: HashMap<String, String>,
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

/// Account usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountUsageStats {
    /// How often this account appears in transactions
    pub frequency: usize,
    /// How often this account is a signer
    pub signer_frequency: usize,
    /// How often this account is writable
    pub writable_frequency: usize,
    /// Most common position in the accounts array
    pub common_position: usize,
}

impl Account {
    /// Create a new account
    pub fn new(name: String, ty: String) -> Self {
        Self {
            name,
            ty,
            fields: Vec::new(),
            discriminator: None,
            related_accounts: Vec::new(),
            child_accounts: Vec::new(),
            usage_stats: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Get the account name
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Get the account type
    pub fn ty(&self) -> &str {
        &self.ty
    }
    
    /// Get the account fields
    pub fn fields(&self) -> &[AccountField] {
        &self.fields
    }
    
    /// Get a mutable reference to the account fields
    pub fn fields_mut(&mut self) -> &mut Vec<AccountField> {
        &mut self.fields
    }
    
    /// Set the discriminator for this account
    pub fn set_discriminator(&mut self, discriminator: Vec<u8>) {
        self.discriminator = Some(discriminator);
    }
    
    /// Get the discriminator for this account
    pub fn discriminator(&self) -> Option<&Vec<u8>> {
        self.discriminator.as_ref()
    }
    
    /// Add a field to the account
    pub fn add_field(&mut self, name: String, ty: String, offset: usize) {
        self.fields.push(AccountField { name, ty, offset });
    }
    
    /// Add a related account
    pub fn add_related_account(&mut self, account_name: String) {
        if !self.related_accounts.contains(&account_name) {
            self.related_accounts.push(account_name);
        }
    }
    
    /// Add a child account
    pub fn add_child_account(&mut self, account_name: String) {
        if !self.child_accounts.contains(&account_name) {
            self.child_accounts.push(account_name);
        }
    }

    /// Add metadata to the account
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
    
    /// Set usage statistics
    pub fn set_usage_stats(&mut self, frequency: usize, signer_frequency: usize, writable_frequency: usize, common_position: usize) {
        self.usage_stats = Some(AccountUsageStats {
            frequency,
            signer_frequency,
            writable_frequency,
            common_position,
        });
    }

    
} 