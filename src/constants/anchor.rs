//! Anchor-specific constants

use std::collections::HashMap;

/// Common Anchor error codes
pub fn error_codes() -> HashMap<u32, String> {
    let mut codes = HashMap::new();
    
    // Constraint errors (2000-2999)
    codes.insert(2000, "ConstraintMut".to_string());
    codes.insert(2001, "ConstraintHasOne".to_string());
    codes.insert(2002, "ConstraintSigner".to_string());
    codes.insert(2003, "ConstraintRaw".to_string());
    codes.insert(2004, "ConstraintOwner".to_string());
    codes.insert(2005, "ConstraintRentExempt".to_string());
    codes.insert(2006, "ConstraintSeeds".to_string());
    codes.insert(2007, "ConstraintExecutable".to_string());
    codes.insert(2008, "ConstraintState".to_string());
    codes.insert(2009, "ConstraintAssociated".to_string());
    codes.insert(2010, "ConstraintAssociatedInit".to_string());
    codes.insert(2011, "ConstraintClose".to_string());
    codes.insert(2012, "ConstraintAddress".to_string());
    codes.insert(2013, "ConstraintZero".to_string());
    codes.insert(2014, "ConstraintTokenMint".to_string());
    codes.insert(2015, "ConstraintTokenOwner".to_string());
    codes.insert(2016, "ConstraintMintMintAuthority".to_string());
    codes.insert(2017, "ConstraintMintFreezeAuthority".to_string());
    codes.insert(2018, "ConstraintMintDecimals".to_string());
    codes.insert(2019, "ConstraintSpace".to_string());
    
    // Account errors (3000-3999)
    codes.insert(3000, "AccountDiscriminatorAlreadySet".to_string());
    codes.insert(3001, "AccountDiscriminatorNotFound".to_string());
    codes.insert(3002, "AccountDiscriminatorMismatch".to_string());
    codes.insert(3003, "AccountDidNotDeserialize".to_string());
    codes.insert(3004, "AccountDidNotSerialize".to_string());
    codes.insert(3005, "AccountNotEnoughKeys".to_string());
    codes.insert(3006, "AccountNotMutable".to_string());
    codes.insert(3007, "AccountOwnedByWrongProgram".to_string());
    codes.insert(3008, "InvalidProgramId".to_string());
    codes.insert(3009, "InvalidProgramExecutable".to_string());
    codes.insert(3010, "AccountNotSigner".to_string());
    codes.insert(3011, "AccountNotSystemOwned".to_string());
    codes.insert(3012, "AccountNotInitialized".to_string());
    codes.insert(3013, "AccountNotProgramData".to_string());
    codes.insert(3014, "AccountNotAssociatedTokenAccount".to_string());
    codes.insert(3015, "AccountSysvarMismatch".to_string());
    
    // State errors (4000-4999)
    codes.insert(4000, "StateInvalidAddress".to_string());
    
    // Used error codes (5000-5999)
    codes.insert(5000, "Deprecated".to_string());
    
    codes
}

/// Common Anchor string patterns
pub const INSTRUCTION_PREFIX: &[u8] = b"Instruction: ";
pub const ANCHOR_VERSION_PREFIX: &[u8] = b"anchor-";
pub const ANCHOR_PATTERNS: &[&[u8]] = &[
    b"Instruction: ",
    b"anchor",
    b"Anchor",
    b"AccountDiscriminator",
    b"InstructionDiscriminator",
]; 