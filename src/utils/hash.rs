//! Hashing utilities

use sha2::{Sha256, Digest};
use crate::constants::discriminator::{ANCHOR_DISCRIMINATOR_NAMESPACE, ANCHOR_ACCOUNT_NAMESPACE};

/// Generate an Anchor instruction discriminator from a name
pub fn generate_anchor_discriminator(name: &str) -> [u8; 8] {
    let namespace = format!("{}{}", ANCHOR_DISCRIMINATOR_NAMESPACE, name);
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    let hash = hasher.finalize();
    
    let mut result = [0u8; 8];
    result.copy_from_slice(&hash[..8]);
    result
}

/// Generate an Anchor account discriminator from an account name
pub fn generate_anchor_account_discriminator(name: &str) -> [u8; 8] {
    let namespace = format!("{}{}", ANCHOR_ACCOUNT_NAMESPACE, name);
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    let hash = hasher.finalize();
    
    let mut result = [0u8; 8];
    result.copy_from_slice(&hash[..8]);
    result
} 