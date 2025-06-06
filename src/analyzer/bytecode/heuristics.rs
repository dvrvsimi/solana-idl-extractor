//! Documentation of heuristics and assumptions used in IDL extraction
//!
//! NOTE: This file is for documentation purposes only and is not used in the codebase.
//! The actual heuristics are implemented in the following modules:
//!   - `src/analyzer/patterns.rs` (transaction and instruction pattern analysis)
//!   - `src/analyzer/bytecode/string_analyzer.rs` (string and name extraction)
//!   - `src/analyzer/bytecode/parser.rs` (bytecode parsing and instruction detection)
//!   - `src/analyzer/bytecode/account_analyzer.rs` (account structure extraction)
//!   - `src/analyzer/bytecode/discriminator_detection.rs` (discriminator logic)
//!   - `src/utils/instruction_patterns.rs` (instruction pattern heuristics)
//!   - `src/utils/error_analysis.rs` (error code heuristics)
//!   - `src/utils/account_analysis.rs` (account heuristics)
//!   - `src/utils/pattern.rs` (pattern matching utilities)
//!
//! This file is a living document to help developers understand and locate the heuristics used throughout the codebase.
//!
//! Understanding these is crucial for interpreting the results and improving the extraction algorithms.

/// # Instruction Detection Heuristics
///
/// The following heuristics are used to detect instructions in program bytecode:
///
/// 1. **Function Entry Points**: We identify potential function entry points by looking for:
///    - Function prologues (stack setup instructions)
///    - References from the instruction dispatch table
///    - Call instructions targeting these addresses
///
/// 2. **Discriminator Detection**: For Anchor programs, we look for:
///    - 8-byte discriminator comparisons at the beginning of functions
///    - Anchor-style discriminator generation patterns (Sha256 of "instruction:X")
///
/// 3. **Instruction Boundaries**: We determine instruction boundaries by:
///    - Analyzing the control flow graph
///    - Identifying dispatch table patterns
///    - Looking for switch/case patterns on the first byte of instruction data
///
/// ## Assumptions
///
/// - Programs follow common Solana patterns for instruction dispatch
/// - Anchor programs use the standard 8-byte discriminator pattern
/// - Native programs typically use a single byte as instruction code
///
/// ## Limitations
///
/// - Custom dispatch mechanisms might not be detected
/// - Heavily optimized code may confuse the boundary detection
/// - Obfuscated programs may intentionally hide instruction boundaries

/// # Account Detection Heuristics
///
/// The following heuristics are used to detect accounts and their properties:
///
/// 1. **Account References**: We identify accounts by looking for:
///    - References to the accounts array parameter
///    - Index-based access patterns (accounts[i])
///    - Anchor-style account deserialization
///
/// 2. **Account Properties**: We determine account properties by:
///    - Analyzing is_signer and is_writable checks
///    - Looking for owner checks (AccountInfo::owner)
///    - Identifying PDA derivation patterns
///
/// 3. **Account Structures**: We infer account data structures by:
///    - Analyzing memory access patterns to account data
///    - Looking for deserialization code patterns
///    - Identifying Anchor account discriminators
///
/// ## Assumptions
///
/// - Programs follow standard Solana patterns for account validation
/// - Account data follows common serialization patterns
/// - Programs check account constraints before using them
///
/// ## Limitations
///
/// - Custom validation logic may not be detected
/// - Complex account relationships might be missed
/// - Dynamic account usage patterns are difficult to analyze statically

/// # String Analysis Heuristics
///
/// The following heuristics are used to extract meaningful names:
///
/// 1. **Name Extraction**: We extract potential names from:
///    - String literals in the .rodata section
///    - Error messages and debug prints
///    - Anchor discriminator strings
///
/// 2. **Name Classification**: We classify strings as:
///    - Instruction names (verb-based, command-like)
///    - Account names (noun-based, entity-like)
///    - Field names (property-like, attribute-like)
///
/// 3. **Name Matching**: We match names to program elements by:
///    - Proximity in the binary
///    - Usage patterns in the code
///    - Similarity to common Solana naming patterns
///
/// ## Assumptions
///
/// - Programs contain meaningful string literals
/// - Names follow common programming conventions
/// - Similar functionality has similar naming across programs
///
/// ## Limitations
///
/// - Stripped binaries contain few or no strings
/// - Generic names may be misclassified
/// - Names might be misleading or intentionally obfuscated 

// The program data account layout for BPF Upgradeable Loader is:
// - First 8 bytes: Header
// - Remaining bytes: Program binary (ELF file)

// The tool should:
// 1. Skip the first 8 bytes of the program data account
// 2. Then try to parse the remaining bytes as an ELF file

// program dump cmd: solana program dump TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb ./dumped.so hexdump -C ./dumped.so | head


pub fn _dummy() {} 