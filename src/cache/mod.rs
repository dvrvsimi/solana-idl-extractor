//! Caching module for IDL extraction results

use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Result, Context};
use solana_pubkey::Pubkey;
use crate::models::idl::IDL;
use log::{debug, warn};

/// Cache for IDL extraction results
pub struct Cache;

impl Cache {
    /// Get the cache directory
    fn cache_dir() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".solana").join("idl_cache")
    }
    
    /// Get the cache file path for a program
    fn cache_path(program_id: &Pubkey) -> PathBuf {
        let cache_dir = Self::cache_dir();
        cache_dir.join(format!("{}.json", program_id))
    }
    
    /// Get a cached IDL for a program
    pub fn get_idl(program_id: &Pubkey) -> Result<Option<IDL>> {
        let path = Self::cache_path(program_id);
        
        if !path.exists() {
            debug!("No cache found for program: {}", program_id);
            return Ok(None);
        }
        
        debug!("Found cache for program: {}", program_id);
        let json = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read cache file: {}", path.display()))?;
        
        let idl: IDL = serde_json::from_str(&json)
            .with_context(|| format!("Failed to parse cached IDL for program: {}", program_id))?;
        
        Ok(Some(idl))
    }
    
    /// Save an IDL to the cache
    pub fn save_idl(program_id: &Pubkey, idl: &IDL) -> Result<()> {
        let cache_dir = Self::cache_dir();
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir)
                .with_context(|| format!("Failed to create cache directory: {}", cache_dir.display()))?;
        }
        
        let path = Self::cache_path(program_id);
        let json = serde_json::to_string_pretty(idl)
            .with_context(|| format!("Failed to serialize IDL for program: {}", program_id))?;
        
        fs::write(&path, json)
            .with_context(|| format!("Failed to write cache file: {}", path.display()))?;
        
        debug!("Cached IDL for program: {}", program_id);
        Ok(())
    }
    
    /// Clear the cache for a program
    pub fn clear(program_id: &Pubkey) -> Result<()> {
        let path = Self::cache_path(program_id);
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("Failed to remove cache file: {}", path.display()))?;
            debug!("Cleared cache for program: {}", program_id);
        } else {
            debug!("No cache to clear for program: {}", program_id);
        }
        
        Ok(())
    }
    
    /// Clear all cached IDLs
    pub fn clear_all() -> Result<()> {
        let cache_dir = Self::cache_dir();
        if cache_dir.exists() {
            fs::remove_dir_all(&cache_dir)
                .with_context(|| format!("Failed to remove cache directory: {}", cache_dir.display()))?;
            fs::create_dir_all(&cache_dir)
                .with_context(|| format!("Failed to recreate cache directory: {}", cache_dir.display()))?;
            debug!("Cleared all cached IDLs");
        } else {
            debug!("No cache directory to clear");
        }
        
        Ok(())
    }
} 