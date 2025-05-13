//! Utility functions and helpers

pub mod hash;
pub mod pattern;
pub mod transaction_parser;
pub mod instruction_patterns;
pub mod memory_analysis;
pub mod account_analysis;
pub mod control_flow;
pub mod error_analysis;
pub mod dynamic_analysis;
pub mod discriminator_detection;
pub mod anchor;

use solana_pubkey::Pubkey;

use std::convert::TryFrom;

/// Returns the ELF bytes for a Solana program, handling both upgradeable and non-upgradeable programs.
/// `fetch_account_data` should be a closure that takes a Pubkey and returns the account data as Vec<u8>.
pub fn get_program_elf_bytes<F>(
    program_pubkey: &Pubkey,
    program_account_data: &[u8],
    program_account_owner: &Pubkey,
    fetch_account_data: F,
) -> Option<Vec<u8>>
where
    F: Fn(&Pubkey) -> Option<Vec<u8>>,
{
    // Upgradeable loader address
    let upgradeable_loader: Pubkey = "BPFLoaderUpgradeab1e11111111111111111111111".parse().unwrap();
    // Legacy loader address
    let legacy_loader: Pubkey = "BPFLoader2111111111111111111111111111111111".parse().unwrap();

    if program_account_owner == &upgradeable_loader {
        // Upgradeable: parse the programdata address from the account data
        // Layout: 8 bytes (enum) + 32 bytes (programdata pubkey) + ...
        if program_account_data.len() >= 40 {
            if let Ok(programdata_pubkey) = Pubkey::try_from(&program_account_data[8..40]) {
                if let Some(programdata_data) = fetch_account_data(&programdata_pubkey) {
                    return Some(crate::analyzer::bytecode::extract_elf_bytes(&programdata_data).unwrap().to_vec());
                }
            }
        }
        None
    } else if program_account_owner == &legacy_loader {
        // Non-upgradeable: ELF is in this account
        Some(crate::analyzer::bytecode::extract_elf_bytes(program_account_data).unwrap().to_vec())
    } else {
        // Not a program account
        None
    }
}

/// Find the start of an ELF file in program data
pub fn find_elf_start(data: &[u8]) -> Result<usize, anyhow::Error> {
    const ELF_MAGIC: &[u8; 4] = b"\x7FELF";
    
    // First try common offsets
    let offsets = [8, 44, 0];
    for &offset in &offsets {
        if data.len() >= offset + 4 && &data[offset..offset + 4] == ELF_MAGIC {
            log::info!("Found ELF header at offset {}", offset);
            return Ok(offset);
        }
    }
    
    // If that fails, scan the entire data
    for i in 0..data.len().saturating_sub(4) {
        if &data[i..i + 4] == ELF_MAGIC {
            log::info!("Found ELF header at offset {} by scanning", i);
            return Ok(i);
        }
    }
    
    // If still no ELF header found, try fallback to 8-byte offset
    if data.len() > 8 {
        log::warn!("No ELF header found, using fallback offset of 8 bytes");
        return Ok(8);
    } // TODO: Add more fallback options
    
    Err(anyhow::anyhow!("No ELF header found in program data"))
}