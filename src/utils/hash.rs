//! Hashing utilities

use sha2::{Sha256, Digest};

/// Generate an Anchor discriminator from a name
pub fn generate_anchor_discriminator(name: &str) -> [u8; 8] {
    let namespace = format!("{}:{}", crate::constants::discriminators::ANCHOR_DISCRIMINATOR_NAMESPACE, name);
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    let hash = hasher.finalize();
    
    let mut result = [0u8; 8];
    result.copy_from_slice(&hash[..8]);
    result
} 