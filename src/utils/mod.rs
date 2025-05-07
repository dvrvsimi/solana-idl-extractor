//! Utility functions and helpers

pub mod hash;
pub mod pattern;
pub mod transaction_parser;

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
                    return Some(crate::analyzer::bytecode::extract_elf_bytes(&programdata_data).to_vec());
                }
            }
        }
        None
    } else if program_account_owner == &legacy_loader {
        // Non-upgradeable: ELF is in this account
        Some(crate::analyzer::bytecode::extract_elf_bytes(program_account_data).to_vec())
    } else {
        // Not a program account
        None
    }
}