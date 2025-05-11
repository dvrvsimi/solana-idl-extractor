//! Dynamic analysis utilities for Solana programs

use anyhow::Result;
use solana_sbpf::{
    static_analysis::Analysis,
    program::SBPFVersion,
    vm::{Config, DynamicAnalysis as SbpDynamicAnalysis},
};
use crate::analyzer::bytecode::parser::SbfInstruction;
use std::collections::{HashMap, HashSet};

/// Results of dynamic analysis
#[derive(Debug, Clone)]
pub struct DynamicAnalysisResult {
    /// Instruction trace
    pub instruction_trace: Vec<InstructionTrace>,
    /// Account access patterns
    pub account_accesses: Vec<AccountAccess>,
    /// Memory access patterns
    pub memory_accesses: Vec<MemoryAccess>,
    /// Compute units used
    pub compute_units: u64,
    /// Error if simulation failed
    pub error: Option<String>,
}

/// Instruction trace entry
#[derive(Debug, Clone)]
pub struct InstructionTrace {
    /// Instruction index
    pub index: usize,
    /// Instruction
    pub instruction: SbfInstruction,
    /// Stack state
    pub stack_state: Vec<u64>,
    /// Register state
    pub register_state: HashMap<u8, u64>,
    /// Compute units used
    pub compute_units: u64,
}

/// Account access entry
#[derive(Debug, Clone)]
pub struct AccountAccess {
    /// Account index
    pub index: usize,
    /// Access type
    pub access_type: AccessType,
    /// Instruction index
    pub instruction_index: usize,
    /// Account data before
    pub data_before: Vec<u8>,
    /// Account data after
    pub data_after: Vec<u8>,
}

/// Memory access entry
#[derive(Debug, Clone)]
pub struct MemoryAccess {
    /// Address
    pub address: u64,
    /// Access type
    pub access_type: AccessType,
    /// Size
    pub size: usize,
    /// Instruction index
    pub instruction_index: usize,
}

/// Access type
#[derive(Debug, Clone, Copy)]
pub enum AccessType {
    /// Read access
    Read,
    /// Write access
    Write,
}

/// Analyze program execution dynamically
pub fn analyze_dynamic(
    instructions: &[SbfInstruction],
    analysis: &Analysis,
    version: SBPFVersion,
    config: &Config,
) -> Result<DynamicAnalysisResult> {
    let mut result = DynamicAnalysisResult {
        instruction_trace: Vec::new(),
        account_accesses: Vec::new(),
        memory_accesses: Vec::new(),
        compute_units: 0,
        error: None,
    };

    // Create SBPF dynamic analysis
    let sbp_analysis = SbpDynamicAnalysis::new(&[], analysis);

    // Track instruction execution
    for (i, insn) in instructions.iter().enumerate() {
        let trace = trace_instruction(insn, i, &sbp_analysis)?;
        result.instruction_trace.push(trace);
    }

    // Derive account and memory accesses from static analysis
    result.account_accesses = derive_account_accesses(instructions);
    result.memory_accesses = derive_memory_accesses(instructions);
    result.compute_units = instructions.len() as u64; // Estimate

    Ok(result)
}

/// Trace a single instruction
fn trace_instruction(
    instruction: &SbfInstruction,
    index: usize,
    _analysis: &SbpDynamicAnalysis,
) -> Result<InstructionTrace> {
    // Create a trace with static information only, for now
    let trace = InstructionTrace {
        index,
        instruction: instruction.clone(),
        stack_state: Vec::new(),
        register_state: HashMap::new(),
        compute_units: 1, // Estimate 1 unit per instruction
    };
    
    Ok(trace)
}

/// Get account access patterns
pub fn get_account_access_patterns(analysis: &DynamicAnalysisResult) -> HashMap<usize, Vec<AccessType>> {
    let mut patterns = HashMap::new();
    
    for access in &analysis.account_accesses {
        patterns
            .entry(access.index)
            .or_insert_with(Vec::new)
            .push(access.access_type);
    }
    
    patterns
}

/// Get memory access patterns
pub fn get_memory_access_patterns(analysis: &DynamicAnalysisResult) -> HashMap<u64, Vec<AccessType>> {
    let mut patterns = HashMap::new();
    
    for access in &analysis.memory_accesses {
        patterns
            .entry(access.address)
            .or_insert_with(Vec::new)
            .push(access.access_type);
    }
    
    patterns
}

/// Get instruction execution frequency
pub fn get_instruction_frequency(analysis: &DynamicAnalysisResult) -> HashMap<usize, u64> {
    let mut frequency = HashMap::new();
    
    for trace in &analysis.instruction_trace {
        *frequency.entry(trace.index).or_insert(0) += 1;
    }
    
    frequency
}

/// Derive account accesses from static analysis
fn derive_account_accesses(instructions: &[SbfInstruction]) -> Vec<AccountAccess> {
    let mut accesses = Vec::new();
    for (i, insn) in instructions.iter().enumerate() {
        if insn.is_load() && insn.src_reg == 0 {
            accesses.push(AccountAccess {
                index: (insn.imm / 8) as usize,
                access_type: AccessType::Read,
                instruction_index: i,
                data_before: Vec::new(),
                data_after: Vec::new(),
            });
        }
    }
    accesses
}

/// Derive memory accesses from static analysis
fn derive_memory_accesses(instructions: &[SbfInstruction]) -> Vec<MemoryAccess> {
    let mut accesses = Vec::new();
    for (i, insn) in instructions.iter().enumerate() {
        if insn.is_load() {
            accesses.push(MemoryAccess {
                address: insn.imm as u64,
                access_type: AccessType::Read,
                size: insn.size,
                instruction_index: i,
            });
        } else if insn.is_store() {
            accesses.push(MemoryAccess {
                address: insn.imm as u64,
                access_type: AccessType::Write,
                size: insn.size,
                instruction_index: i,
            });
        }
    }
    accesses
} 