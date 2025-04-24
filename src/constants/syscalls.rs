/// Solana syscall hash values
/// 
/// 
pub mod syscalls {
    // Core Solana Syscalls
    pub const SOL_PANIC: u32 = 0x686093bb;
    pub const SOL_LOG: u32 = 0x3d082901;
    pub const SOL_LOG_64: u32 = 0x8af3d277;
    pub const SOL_LOG_COMPUTE_UNITS: u32 = 0x6a1a479c;
    pub const SOL_LOG_PUBKEY: u32 = 0x7ef088ca;

    // Memory Syscalls
    pub const SOL_ALLOC_FREE: u32 = 0x98d320c8;
    pub const SOL_SHA256: u32 = 0x5a51024e;
    pub const SOL_KECCAK256: u32 = 0x905ff6e9;
    pub const SOL_BLAKE3: u32 = 0xd0a3f097;

    // Program Invocation Syscalls
    pub const SOL_CREATE_PROGRAM_ADDRESS: u32 = 0x9377323c;
    pub const SOL_TRY_FIND_PROGRAM_ADDRESS: u32 = 0x48504a38;
    
    // CPI (Cross-Program Invocation) Syscalls
    pub const SOL_INVOKE_SIGNED_C: u32 = 0xa22b9c85;
    pub const SOL_INVOKE_SIGNED_RUST: u32 = 0xd7449092;
    pub const SOL_INVOKE: u32 = 0x9fd8e6e8;
    
    // Account Data Syscalls
    pub const SOL_GET_CLOCK_SYSVAR: u32 = 0xc040e937;
    pub const SOL_GET_EPOCH_SCHEDULE_SYSVAR: u32 = 0xd7a447cd;
    pub const SOL_GET_FEES_SYSVAR: u32 = 0x819e2be0;
    pub const SOL_GET_RENT_SYSVAR: u32 = 0x9f41bb7d;
    
    // Elliptic Curve Syscalls
    pub const SOL_ECDSA_VERIFY: u32 = 0x98c0b93c;
    pub const SOL_ECDSA_RECOVER: u32 = 0xb172f8c7;
    pub const SOL_SECP256K1_RECOVER: u32 = 0x7ac2d3e1;
    
    // BPF Loader Upgradeable Syscalls
    pub const SOL_SET_RETURN_DATA: u32 = 0x87ef0d9f;
    pub const SOL_GET_RETURN_DATA: u32 = 0x9e0ddbc9;
    
    // Alt_BN128 Syscalls (Added in v1.14)
    pub const SOL_ALT_BN128_ADDITION: u32 = 0x1722c9df;
    pub const SOL_ALT_BN128_MULTIPLICATION: u32 = 0x4c5fbbb8;
    pub const SOL_ALT_BN128_PAIRING: u32 = 0x64d16383;
    
    // Poseidon Syscalls (Added in v1.16)
    pub const SOL_POSEIDON: u32 = 0x3a1a3080;
    
    // Memory Comparison Syscalls (Added in v1.17)
    pub const SOL_MEMCMP: u32 = 0xa0e67aca;
    pub const SOL_MEMCPY: u32 = 0xb718494d;
    pub const SOL_MEMMOVE: u32 = 0xb0d50d1f;
    pub const SOL_MEMSET: u32 = 0xd184ab34;
    
    // Big Integer Syscalls (Added in v1.17)
    pub const SOL_BIG_INTEGER_ADD: u32 = 0x5b5c38c0;
    pub const SOL_BIG_INTEGER_SUBTRACT: u32 = 0xc24ced63;
    pub const SOL_BIG_INTEGER_MULTIPLY: u32 = 0x927dfe6b;
    pub const SOL_BIG_INTEGER_DIVIDE: u32 = 0x92c5d5a9;
    pub const SOL_BIG_INTEGER_MODULO: u32 = 0xf3a5e9de;
}

/// Common Sealevel syscall hashes
pub mod hashes {
    pub const SOL_LOG: u32 = 0x3a6ed8;
    pub const SOL_LOG_64: u32 = 0xb166;
    pub const SOL_LOG_COMPUTE_UNITS: u32 = 0xd89;
    pub const SOL_LOG_PUBKEY: u32 = 0x20a;
    pub const SOL_CREATE_PROGRAM_ADDRESS: u32 = 0x10;
    pub const SOL_TRY_FIND_PROGRAM_ADDRESS: u32 = 0x11;
    pub const SOL_SHA256: u32 = 0x2;
    pub const SOL_KECCAK256: u32 = 0x5;
    pub const SOL_INVOKE_SIGNED: u32 = 0x12;
    pub const SOL_INVOKE: u32 = 0x14;
    pub const SOL_ALLOC_FREE: u32 = 0x15;
    pub const SOL_MEMCPY: u32 = 0x16;
    pub const SOL_MEMCMP: u32 = 0x17;
    pub const SOL_MEMMOVE: u32 = 0x18;
    pub const SOL_MEMSET: u32 = 0x19;
}