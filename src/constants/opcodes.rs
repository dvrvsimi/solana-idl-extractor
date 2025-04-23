/// SBF Instruction opcodes based on official Solana SBPF specification
pub mod opcodes {
    // Memory Load or 32-bit ALU operations (Class 0)
    pub const LDDW: u8 = 0x18;        // Load double word immediate
    pub const ADD32_IMM: u8 = 0x04;   // 32-bit add immediate
    pub const ADD32_REG: u8 = 0x0c;   // 32-bit add register
    pub const SUB32_IMM: u8 = 0x14;   // 32-bit subtract immediate
    pub const SUB32_REG: u8 = 0x1c;   // 32-bit subtract register
    pub const MUL32_IMM: u8 = 0x24;   // 32-bit multiply immediate
    pub const MUL32_REG: u8 = 0x2c;   // 32-bit multiply register
    pub const DIV32_IMM: u8 = 0x34;   // 32-bit divide immediate
    pub const DIV32_REG: u8 = 0x3c;   // 32-bit divide register
    pub const OR32_IMM: u8 = 0x44;    // 32-bit OR immediate
    pub const OR32_REG: u8 = 0x4c;    // 32-bit OR register
    pub const AND32_IMM: u8 = 0x54;   // 32-bit AND immediate
    pub const AND32_REG: u8 = 0x5c;   // 32-bit AND register
    pub const LSH32_IMM: u8 = 0x64;   // 32-bit left shift immediate
    pub const LSH32_REG: u8 = 0x6c;   // 32-bit left shift register
    pub const RSH32_IMM: u8 = 0x74;   // 32-bit right shift immediate
    pub const RSH32_REG: u8 = 0x7c;   // 32-bit right shift register
    pub const NEG32: u8 = 0x84;       // 32-bit negate
    pub const MOD32_IMM: u8 = 0x94;   // 32-bit modulo immediate
    pub const MOD32_REG: u8 = 0x9c;   // 32-bit modulo register
    pub const XOR32_IMM: u8 = 0xa4;   // 32-bit XOR immediate
    pub const XOR32_REG: u8 = 0xac;   // 32-bit XOR register
    pub const MOV32_IMM: u8 = 0xb4;   // 32-bit move immediate
    pub const MOV32_REG: u8 = 0xbc;   // 32-bit move register
    pub const ARSH32_IMM: u8 = 0xc4;  // 32-bit arithmetic right shift immediate
    pub const ARSH32_REG: u8 = 0xcc;  // 32-bit arithmetic right shift register
    pub const LE: u8 = 0xd4;          // Endian conversion (little endian)
    pub const BE: u8 = 0xdc;          // Endian conversion (big endian)

    // Memory Store or 64-bit ALU operations (Class 1)
    pub const ADD64_IMM: u8 = 0x07;   // 64-bit add immediate
    pub const ADD64_REG: u8 = 0x0f;   // 64-bit add register
    pub const SUB64_IMM: u8 = 0x17;   // 64-bit subtract immediate
    pub const SUB64_REG: u8 = 0x1f;   // 64-bit subtract register
    pub const MUL64_IMM: u8 = 0x27;   // 64-bit multiply immediate
    pub const MUL64_REG: u8 = 0x2f;   // 64-bit multiply register
    pub const DIV64_IMM: u8 = 0x37;   // 64-bit divide immediate
    pub const DIV64_REG: u8 = 0x3f;   // 64-bit divide register
    pub const OR64_IMM: u8 = 0x47;    // 64-bit OR immediate
    pub const OR64_REG: u8 = 0x4f;    // 64-bit OR register
    pub const AND64_IMM: u8 = 0x57;   // 64-bit AND immediate
    pub const AND64_REG: u8 = 0x5f;   // 64-bit AND register
    pub const LSH64_IMM: u8 = 0x67;   // 64-bit left shift immediate
    pub const LSH64_REG: u8 = 0x6f;   // 64-bit left shift register
    pub const RSH64_IMM: u8 = 0x77;   // 64-bit right shift immediate
    pub const RSH64_REG: u8 = 0x7f;   // 64-bit right shift register
    pub const NEG64: u8 = 0x87;       // 64-bit negate
    pub const MOD64_IMM: u8 = 0x97;   // 64-bit modulo immediate
    pub const MOD64_REG: u8 = 0x9f;   // 64-bit modulo register
    pub const XOR64_IMM: u8 = 0xa7;   // 64-bit XOR immediate
    pub const XOR64_REG: u8 = 0xaf;   // 64-bit XOR register
    pub const MOV64_IMM: u8 = 0xb7;   // 64-bit move immediate
    pub const MOV64_REG: u8 = 0xbf;   // 64-bit move register
    pub const ARSH64_IMM: u8 = 0xc7;  // 64-bit arithmetic right shift immediate
    pub const ARSH64_REG: u8 = 0xcf;  // 64-bit arithmetic right shift register
    pub const HOR64: u8 = 0xf7;       // High-OR immediate (from V2)

    // Jump and Control Flow instructions
    pub const JA: u8 = 0x05;          // Jump always
    pub const JEQ_IMM: u8 = 0x15;     // Jump if equal immediate
    pub const JEQ_REG: u8 = 0x1d;     // Jump if equal register
    pub const JGT_IMM: u8 = 0x25;     // Jump if greater than immediate
    pub const JGT_REG: u8 = 0x2d;     // Jump if greater than register
    pub const JGE_IMM: u8 = 0x35;     // Jump if greater or equal immediate
    pub const JGE_REG: u8 = 0x3d;     // Jump if greater or equal register
    pub const JLT_IMM: u8 = 0xa5;     // Jump if less than immediate
    pub const JLT_REG: u8 = 0xad;     // Jump if less than register
    pub const JLE_IMM: u8 = 0xb5;     // Jump if less or equal immediate
    pub const JLE_REG: u8 = 0xbd;     // Jump if less or equal register
    pub const JSET_IMM: u8 = 0x45;    // Jump if bits set immediate
    pub const JSET_REG: u8 = 0x4d;    // Jump if bits set register
    pub const JNE_IMM: u8 = 0x55;     // Jump if not equal immediate
    pub const JNE_REG: u8 = 0x5d;     // Jump if not equal register
    pub const JSGT_IMM: u8 = 0x65;    // Jump if signed greater than immediate
    pub const JSGT_REG: u8 = 0x6d;    // Jump if signed greater than register
    pub const JSGE_IMM: u8 = 0x75;    // Jump if signed greater or equal immediate
    pub const JSGE_REG: u8 = 0x7d;    // Jump if signed greater or equal register
    pub const JSLT_IMM: u8 = 0xc5;    // Jump if signed less than immediate
    pub const JSLT_REG: u8 = 0xcd;    // Jump if signed less than register
    pub const JSLE_IMM: u8 = 0xd5;    // Jump if signed less or equal immediate
    pub const JSLE_REG: u8 = 0xdd;    // Jump if signed less or equal register

    // Function Call instructions
    pub const CALL: u8 = 0x85;        // Call function immediate
    pub const CALLX: u8 = 0x8d;       // Call function register
    pub const EXIT: u8 = 0x95;        // Exit (return)
    pub const SYSCALL: u8 = 0x95;     // System call (same as EXIT in v0-v2, separate in v3+)
    pub const RETURN: u8 = 0x9d;      // Return (from v3)

    // Memory instructions (in V2+ format)
    pub const LDXB: u8 = 0x71;        // Load byte
    pub const LDXH: u8 = 0x69;        // Load half word
    pub const LDXW: u8 = 0x61;        // Load word
    pub const LDXDW: u8 = 0x79;       // Load double word
    pub const STB: u8 = 0x72;         // Store byte immediate
    pub const STH: u8 = 0x6a;         // Store half word immediate
    pub const STW: u8 = 0x62;         // Store word immediate
    pub const STDW: u8 = 0x7a;        // Store double word immediate
    pub const STXB: u8 = 0x73;        // Store byte register
    pub const STXH: u8 = 0x6b;        // Store half word register
    pub const STXW: u8 = 0x63;        // Store word register
    pub const STXDW: u8 = 0x7b;       // Store double word register

    // Product/Quotient/Remainder operations (from V2)
    pub const LMUL32_IMM: u8 = 0x86;  // Signed 32-bit multiply immediate (low bits)
    pub const LMUL32_REG: u8 = 0x8e;  // Signed 32-bit multiply register (low bits)
    pub const LMUL64_IMM: u8 = 0x96;  // Signed 64-bit multiply immediate (low bits)
    pub const LMUL64_REG: u8 = 0x9e;  // Signed 64-bit multiply register (low bits)
    pub const UHMUL64_IMM: u8 = 0x36; // Unsigned 64-bit multiply immediate (high bits)
    pub const UHMUL64_REG: u8 = 0x3e; // Unsigned 64-bit multiply register (high bits)
    pub const SHMUL64_IMM: u8 = 0xb6; // Signed 64-bit multiply immediate (high bits)
    pub const SHMUL64_REG: u8 = 0xbe; // Signed 64-bit multiply register (high bits)
    pub const UDIV32_IMM: u8 = 0x46;  // Unsigned 32-bit divide immediate
    pub const UDIV32_REG: u8 = 0x4e;  // Unsigned 32-bit divide register
    pub const UDIV64_IMM: u8 = 0x56;  // Unsigned 64-bit divide immediate
    pub const UDIV64_REG: u8 = 0x5e;  // Unsigned 64-bit divide register
    pub const UREM32_IMM: u8 = 0x66;  // Unsigned 32-bit remainder immediate
    pub const UREM32_REG: u8 = 0x6e;  // Unsigned 32-bit remainder register
    pub const UREM64_IMM: u8 = 0x76;  // Unsigned 64-bit remainder immediate
    pub const UREM64_REG: u8 = 0x7e;  // Unsigned 64-bit remainder register
    pub const SDIV32_IMM: u8 = 0xc6;  // Signed 32-bit divide immediate
    pub const SDIV32_REG: u8 = 0xce;  // Signed 32-bit divide register
    pub const SDIV64_IMM: u8 = 0xd6;  // Signed 64-bit divide immediate
    pub const SDIV64_REG: u8 = 0xde;  // Signed 64-bit divide register
    pub const SREM32_IMM: u8 = 0xe6;  // Signed 32-bit remainder immediate
    pub const SREM32_REG: u8 = 0xee;  // Signed 32-bit remainder register
    pub const SREM64_IMM: u8 = 0xf6;  // Signed 64-bit remainder immediate
    pub const SREM64_REG: u8 = 0xfe;  // Signed 64-bit remainder register
}