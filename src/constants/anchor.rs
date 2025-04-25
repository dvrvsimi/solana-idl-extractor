//! Anchor-specific constants

use std::collections::HashMap;

/// Common Anchor error codes
pub fn error_codes() -> HashMap<u32, String> {
    let mut codes = HashMap::new();
    
    // Instructions (100-199)
    codes.insert(100, "InstructionMissing".to_string());
    codes.insert(101, "InstructionFallbackNotFound".to_string());
    codes.insert(102, "InstructionDidNotDeserialize".to_string());
    codes.insert(103, "InstructionDidNotSerialize".to_string());
    
    // IDL instructions (1000-1499)
    codes.insert(1000, "IdlInstructionStub".to_string());
    codes.insert(1001, "IdlInstructionInvalidProgram".to_string());
    codes.insert(1002, "IdlAccountNotEmpty".to_string());
    
    // Event instructions (1500-1999)
    codes.insert(1500, "EventInstructionStub".to_string());
    
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
    codes.insert(2020, "ConstraintAccountIsNone".to_string());
    codes.insert(2021, "ConstraintTokenTokenProgram".to_string());
    codes.insert(2022, "ConstraintMintTokenProgram".to_string());
    codes.insert(2023, "ConstraintAssociatedTokenTokenProgram".to_string());
    codes.insert(2024, "ConstraintMintGroupPointerExtension".to_string());
    codes.insert(2025, "ConstraintMintGroupPointerExtensionAuthority".to_string());
    codes.insert(2026, "ConstraintMintGroupPointerExtensionGroupAddress".to_string());
    codes.insert(2027, "ConstraintMintGroupMemberPointerExtension".to_string());
    codes.insert(2028, "ConstraintMintGroupMemberPointerExtensionAuthority".to_string());
    codes.insert(2029, "ConstraintMintGroupMemberPointerExtensionMemberAddress".to_string());
    codes.insert(2030, "ConstraintMintMetadataPointerExtension".to_string());
    codes.insert(2031, "ConstraintMintMetadataPointerExtensionAuthority".to_string());
    codes.insert(2032, "ConstraintMintMetadataPointerExtensionMetadataAddress".to_string());
    codes.insert(2033, "ConstraintMintCloseAuthorityExtension".to_string());
    codes.insert(2034, "ConstraintMintCloseAuthorityExtensionAuthority".to_string());
    codes.insert(2035, "ConstraintMintPermanentDelegateExtension".to_string());
    codes.insert(2036, "ConstraintMintPermanentDelegateExtensionDelegate".to_string());
    codes.insert(2037, "ConstraintMintTransferHookExtension".to_string());
    codes.insert(2038, "ConstraintMintTransferHookExtensionAuthority".to_string());
    codes.insert(2039, "ConstraintMintTransferHookExtensionProgramId".to_string());
    
    // Require errors (2500-2999)
    codes.insert(2500, "RequireViolated".to_string());
    codes.insert(2501, "RequireEqViolated".to_string());
    codes.insert(2502, "RequireKeysEqViolated".to_string());
    codes.insert(2503, "RequireNeqViolated".to_string());
    codes.insert(2504, "RequireKeysNeqViolated".to_string());
    codes.insert(2505, "RequireGtViolated".to_string());
    codes.insert(2506, "RequireGteViolated".to_string());
    
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
    codes.insert(3016, "AccountReallocExceedsLimit".to_string());
    codes.insert(3017, "AccountDuplicateReallocs".to_string());
    
    // Miscellaneous errors (4100-4999)
    codes.insert(4100, "DeclaredProgramIdMismatch".to_string());
    codes.insert(4101, "TryingToInitPayerAsProgramAccount".to_string());
    codes.insert(4102, "InvalidNumericConversion".to_string());
    
    // Deprecated errors (5000-5999)
    codes.insert(5000, "Deprecated".to_string());
    
    // The starting point for user-defined errors is 6000
    
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