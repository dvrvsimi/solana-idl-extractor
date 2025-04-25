//! Transaction simulation for IDL enhancement

use anyhow::{Result, Context, anyhow};
use log::{debug, info, warn};
use reqwest::Client;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::Duration;
use sha2::{Sha256, Digest};

use solana_pubkey::Pubkey;
use solana_instruction::Instruction;
use solana_instruction::account_meta::AccountMeta;
use solana_message::Message;
use solana_transaction::Transaction;
use solana_signature::keypair::Keypair;
use solana_signature::signature::Signer;

use crate::models::idl::IDL;
use crate::models::instruction::Instruction as IdlInstruction;
use crate::models::account::Account as IdlAccount;
use crate::constants::discriminator::ANCHOR_DISCRIMINATOR_LENGTH;
use crate::utils::hash::generate_anchor_discriminator;
use crate::errors::{ExtractorError, ExtractorResult, ErrorExt, ErrorContext};

/// Simulation result for a single instruction
#[derive(Debug, Clone)]
pub struct SimulationResult {
    /// Instruction that was simulated
    pub instruction: IdlInstruction,
    /// Logs from the simulation
    pub logs: Vec<String>,
    /// Account changes observed
    pub account_changes: Vec<AccountChange>,
    /// Error message if simulation failed
    pub error: Option<String>,
    /// Compute units used
    pub compute_units: u64,
}

/// Account change observed during simulation
#[derive(Debug, Clone)]
pub struct AccountChange {
    /// Account address
    pub address: String,
    /// Account data before simulation
    pub data_before: Vec<u8>,
    /// Account data after simulation
    pub data_after: Vec<u8>,
    /// Is this a new account?
    pub is_new: bool,
    /// Is this account owned by the program?
    pub owned_by_program: bool,
}

/// RPC response for simulation
#[derive(Debug, Deserialize)]
struct SimulateResponse {
    result: SimulateResult,
    id: u64,
    jsonrpc: String,
}

/// Simulation result from RPC
#[derive(Debug, Deserialize)]
struct SimulateResult {
    context: RpcContext,
    value: SimulateResultValue,
}

/// RPC context
#[derive(Debug, Deserialize)]
struct RpcContext {
    slot: u64,
}

/// Simulation result value
#[derive(Debug, Deserialize)]
struct SimulateResultValue {
    err: Option<Value>,
    logs: Option<Vec<String>>,
    accounts: Option<Vec<Option<AccountInfo>>>,
    units_consumed: Option<u64>,
}

/// Account info from simulation
#[derive(Debug, Deserialize)]
struct AccountInfo {
    data: Vec<String>,
    executable: bool,
    lamports: u64,
    owner: String,
    rent_epoch: u64,
}

/// Transaction simulator
pub struct TransactionSimulator {
    /// HTTP client
    client: Client,
    /// RPC URL
    rpc_url: String,
    /// Program ID
    program_id: Pubkey,
    /// Payer keypair for simulations
    payer: Keypair,
    /// Current IDL
    idl: IDL,
}

impl TransactionSimulator {
    /// Create a new transaction simulator
    pub fn new(rpc_url: &str, program_id: &Pubkey, idl: IDL) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        
        // Generate a random keypair for simulation
        let payer = Keypair::new();
        
        Ok(Self {
            client,
            rpc_url: rpc_url.to_string(),
            program_id: *program_id,
            payer,
            idl,
        })
    }
    
    /// Simulate all instructions in the IDL
    pub async fn simulate_all(&self) -> Result<Vec<SimulationResult>> {
        let mut results = Vec::new();
        
        for instruction in &self.idl.instructions {
            match self.simulate_instruction(instruction).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    warn!("Failed to simulate instruction {}: {}", instruction.name, e);
                    // Add a failed result
                    results.push(SimulationResult {
                        instruction: instruction.clone(),
                        logs: Vec::new(),
                        account_changes: Vec::new(),
                        error: Some(e.to_string()),
                        compute_units: 0,
                    });
                }
            }
        }
        
        Ok(results)
    }
    
    /// Simulate a specific instruction with improved error handling
    pub async fn simulate_instruction(&self, instruction: &IdlInstruction) -> ExtractorResult<SimulationResult> {
        let context = ErrorContext {
            program_id: Some(self.program_id.to_string()),
            component: "transaction_simulator".to_string(),
            operation: format!("simulate_instruction_{}", instruction.name),
            details: None,
        };
        
        info!("Simulating instruction: {}", instruction.name);
        
        // Generate mock accounts for the instruction
        let (accounts, account_data) = self.generate_mock_accounts(instruction)
            .map_err(|e| ExtractorError::Simulation(format!("Failed to generate mock accounts: {}", e)))?;
        
        // Generate instruction data
        let instruction_data = self.generate_instruction_data(instruction)
            .map_err(|e| ExtractorError::Simulation(format!("Failed to generate instruction data: {}", e)))?;
        
        // Create the instruction
        let ix = Instruction {
            program_id: self.program_id,
            accounts,
            data: instruction_data,
        };
        
        // Add compute budget instruction to avoid hitting limits
        let compute_budget_ix = self.create_compute_budget_instruction(1_400_000)
            .map_err(|e| ExtractorError::Simulation(format!("Failed to create compute budget instruction: {}", e)))?;
        
        // Create a transaction
        let message = Message::new(&[compute_budget_ix, ix], Some(&self.payer.pubkey()));
        let mut tx = Transaction::new_unsigned(message);
        
        // Sign the transaction
        let recent_blockhash = self.get_recent_blockhash().await
            .map_err(|e| ExtractorError::Simulation(format!("Failed to get recent blockhash: {}", e)))?;
        tx.sign(&[&self.payer], recent_blockhash);
        
        // Simulate the transaction with retry logic
        let result = self.simulate_transaction_with_retry(&tx, 3).await
            .map_err(|e| ExtractorError::Simulation(format!("Transaction simulation failed: {}", e)))?;
        
        // Extract logs
        let logs = if let Some(logs) = result.value.logs {
            logs
        } else {
            Vec::new()
        };
        
        // Extract error
        let error = if let Some(err) = result.value.err {
            Some(format!("{:?}", err))
        } else {
            None
        };
        
        // Extract compute units
        let compute_units = result.value.units_consumed.unwrap_or(0);
        
        // Analyze account changes
        let account_changes = self.analyze_account_changes(&account_data, &logs, &result)
            .map_err(|e| ExtractorError::Simulation(format!("Failed to analyze account changes: {}", e)))?;
        
        Ok(SimulationResult {
            instruction: instruction.clone(),
            logs,
            account_changes,
            error,
            compute_units,
        })
    }
    
    /// Simulate a transaction with retry logic
    async fn simulate_transaction_with_retry(&self, transaction: &Transaction, retries: usize) -> ExtractorResult<SimulateResult> {
        let mut attempts = 0;
        let mut last_error = None;
        
        while attempts < retries {
            match self.simulate_transaction(transaction).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    attempts += 1;
                    last_error = Some(ExtractorError::Simulation(format!("Simulation attempt {} failed: {}", attempts, e)));
                    
                    if attempts < retries {
                        // Exponential backoff
                        let delay = std::time::Duration::from_millis(500 * 2u64.pow(attempts as u32));
                        warn!("Simulation attempt {} failed, retrying in {:?}: {}", 
                              attempts, delay, e);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| 
            ExtractorError::Simulation("Simulation failed with unknown error".to_string())
        ))
    }
    
    /// Generate mock accounts for an instruction
    fn generate_mock_accounts(&self, instruction: &IdlInstruction) -> Result<(Vec<AccountMeta>, HashMap<String, Vec<u8>>)> {
        let mut accounts = Vec::new();
        let mut account_data = HashMap::new();
        
        // Add payer as first account
        accounts.push(AccountMeta::new(self.payer.pubkey(), true));
        account_data.insert(self.payer.pubkey().to_string(), Vec::new());
        
        // Add program ID as last account (not writable)
        accounts.push(AccountMeta::new_readonly(self.program_id, false));
        
        // Generate mock accounts based on instruction name and args
        // This is a heuristic approach - in a real implementation, we'd need more context
        
        // For initialize/create instructions, add a new account
        if instruction.name.contains("initialize") || instruction.name.contains("create") {
            let new_account = Keypair::new();
            accounts.push(AccountMeta::new(new_account.pubkey(), false));
            
            // For Anchor accounts, add a discriminator
            if self.idl.metadata.origin == "anchor" {
                let mut data = Vec::new();
                let discriminator = generate_anchor_discriminator(&instruction.name);
                data.extend_from_slice(&discriminator);
                account_data.insert(new_account.pubkey().to_string(), data);
            } else {
                account_data.insert(new_account.pubkey().to_string(), Vec::new());
            }
        }
        
        // For transfer instructions, add source and destination accounts
        if instruction.name.contains("transfer") {
            let source = Keypair::new();
            let destination = Keypair::new();
            accounts.push(AccountMeta::new(source.pubkey(), false));
            accounts.push(AccountMeta::new(destination.pubkey(), false));
            account_data.insert(source.pubkey().to_string(), Vec::new());
            account_data.insert(destination.pubkey().to_string(), Vec::new());
        }
        
        // For other instructions, add a generic account
        if accounts.len() < 3 {
            let generic_account = Keypair::new();
            accounts.push(AccountMeta::new(generic_account.pubkey(), false));
            account_data.insert(generic_account.pubkey().to_string(), Vec::new());
        }
        
        Ok((accounts, account_data))
    }
    
    /// Generate instruction data
    fn generate_instruction_data(&self, instruction: &IdlInstruction) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        
        // For Anchor programs, add discriminator
        if self.idl.metadata.origin == "anchor" {
            let discriminator = generate_anchor_discriminator(&instruction.name);
            data.extend_from_slice(&discriminator);
        } else {
            // For non-Anchor programs, add instruction code
            data.push(instruction.code);
        }
        
        // Add mock data for each argument
        for arg in &instruction.args {
            match arg.type_name.as_str() {
                "u8" => data.push(1),
                "u16" => data.extend_from_slice(&1u16.to_le_bytes()),
                "u32" => data.extend_from_slice(&1u32.to_le_bytes()),
                "u64" => data.extend_from_slice(&1u64.to_le_bytes()),
                "i8" => data.push(1),
                "i16" => data.extend_from_slice(&1i16.to_le_bytes()),
                "i32" => data.extend_from_slice(&1i32.to_le_bytes()),
                "i64" => data.extend_from_slice(&1i64.to_le_bytes()),
                "bool" => data.push(1), // true
                "Pubkey" | "pubkey" => {
                    let pubkey = Pubkey::new_unique();
                    data.extend_from_slice(pubkey.as_ref());
                },
                "string" | "String" => {
                    // Add a short string "test"
                    data.extend_from_slice(&4u32.to_le_bytes()); // length
                    data.extend_from_slice(b"test");
                },
                _ => {
                    // For unknown types, add 8 bytes of zeros
                    data.extend_from_slice(&[0; 8]);
                }
            }
        }
        
        Ok(data)
    }
    
    /// Create a compute budget instruction
    fn create_compute_budget_instruction(&self, units: u32) -> Result<Instruction> {
        // Compute budget program ID
        let program_id = Pubkey::from_str("ComputeBudget111111111111111111111111111111")?;
        
        // Instruction data: units
        let mut data = Vec::new();
        data.push(0); // SetComputeUnitLimit instruction
        data.extend_from_slice(&units.to_le_bytes());
        
        Ok(Instruction {
            program_id,
            accounts: Vec::new(),
            data,
        })
    }
    
    /// Get recent blockhash
    async fn get_recent_blockhash(&self) -> Result<[u8; 32]> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getRecentBlockhash",
            "params": []
        });
        
        let response: Value = self.client.post(&self.rpc_url)
            .json(&request)
            .send()
            .await?
            .json()
            .await?;
        
        let blockhash = response["result"]["value"]["blockhash"]
            .as_str()
            .ok_or_else(|| anyhow!("Failed to get blockhash"))?;
        
        let decoded = bs58::decode(blockhash)
            .into_vec()
            .context("Failed to decode blockhash")?;
        
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&decoded);
        
        Ok(hash)
    }
    
    /// Simulate a transaction
    async fn simulate_transaction(&self, transaction: &Transaction) -> Result<SimulateResult> {
        // Encode transaction
        let serialized = bincode::serialize(transaction)?;
        let encoded = bs58::encode(serialized).into_string();
        
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "simulateTransaction",
            "params": [
                encoded,
                {
                    "sigVerify": false,
                    "commitment": "confirmed",
                    "encoding": "base64",
                    "accounts": {
                        "encoding": "base64",
                    }
                }
            ]
        });
        
        let response: SimulateResponse = self.client.post(&self.rpc_url)
            .json(&request)
            .send()
            .await?
            .json()
            .await?;
        
        Ok(response.result)
    }
    
    /// Analyze account changes from simulation
    fn analyze_account_changes(&self, 
                              account_data: &HashMap<String, Vec<u8>>, 
                              logs: &[String],
                              result: &SimulateResult) -> Result<Vec<AccountChange>> {
        let mut changes = Vec::new();
        
        // Extract account changes from simulation result
        if let Some(accounts) = &result.value.accounts {
            for (i, account_info) in accounts.iter().enumerate() {
                if let Some(account_info) = account_info {
                    // Get account address from logs or use a placeholder
                    let address = if i < logs.len() {
                        extract_account_address_from_log(&logs[i])
                            .unwrap_or_else(|| format!("Account_{}", i))
                    } else {
                        format!("Account_{}", i)
                    };
                    
                    // Decode account data
                    let data_after = if !account_info.data.is_empty() {
                        base64::decode(&account_info.data[0])?
                    } else {
                        Vec::new()
                    };
                    
                    // Get data before simulation
                    let data_before = account_data.get(&address)
                        .cloned()
                        .unwrap_or_default();
                    
                    // Check if this is a new account
                    let is_new = !account_data.contains_key(&address);
                    
                    // Check if owned by program
                    let owned_by_program = account_info.owner == self.program_id.to_string();
                    
                    changes.push(AccountChange {
                        address,
                        data_before,
                        data_after,
                        is_new,
                        owned_by_program,
                    });
                }
            }
        }
        
        Ok(changes)
    }
    
    /// Enhance IDL based on simulation results
    pub fn enhance_idl(&self, results: &[SimulationResult]) -> Result<IDL> {
        let mut enhanced_idl = self.idl.clone();
        
        // Enhance instructions
        self.enhance_instructions(&mut enhanced_idl, results);
        
        // Enhance accounts
        for result in results {
            self.enhance_accounts(&mut enhanced_idl, result);
        }
        
        Ok(enhanced_idl)
    }
    
    /// Enhance instruction definitions based on simulation
    fn enhance_instructions(&self, idl: &mut IDL, results: &[SimulationResult]) {
        for result in results {
            // Skip failed simulations
            if result.error.is_some() {
                continue;
            }
            
            // Find the instruction in the IDL
            if let Some(instruction) = idl.instructions.iter_mut()
                .find(|i| i.name == result.instruction.name) {
                
                // Analyze logs to improve instruction definition
                for log in &result.logs {
                    // Look for parameter names and types in logs
                    if log.contains("Instruction:") && log.contains("Args:") {
                        let args_part = log.split("Args:").nth(1).unwrap_or("");
                        let args: Vec<&str> = args_part.split(',').collect();
                        
                        for (i, arg) in args.iter().enumerate() {
                            if i < instruction.args.len() {
                                // Try to extract parameter name
                                if let Some(name_value) = arg.split(':').collect::<Vec<&str>>().get(0..2) {
                                    let name = name_value[0].trim();
                                    let value = name_value[1].trim();
                                    
                                    // Update parameter name if it's generic
                                    if instruction.args[i].name.starts_with("param_") {
                                        instruction.args[i].name = name.to_string();
                                    }
                                    
                                    // Try to infer better type from value
                                    if value.starts_with("0x") {
                                        // Likely a pubkey
                                        instruction.args[i].type_name = "Pubkey".to_string();
                                    } else if value == "true" || value == "false" {
                                        instruction.args[i].type_name = "bool".to_string();
                                    } else if value.parse::<u64>().is_ok() {
                                        // Numeric value, keep existing type or default to u64
                                        if !["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"]
                                            .contains(&instruction.args[i].type_name.as_str()) {
                                            instruction.args[i].type_name = "u64".to_string();
                                        }
                                    } else {
                                        // Likely a string
                                        instruction.args[i].type_name = "string".to_string();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    /// Enhance account definitions based on simulation
    fn enhance_accounts(&self, idl: &mut IDL, result: &SimulationResult) {
        for change in &result.account_changes {
            // Skip system program accounts
            if change.address == "11111111111111111111111111111111" {
                continue;
            }
            
            // Try to identify account type from data
            if let Some(account_type) = self.identify_account_type(&change.data_after) {
                // Check if we already have this account type
                if !idl.accounts.iter().any(|a| a.name == account_type) {
                    // Create a new account definition
                    let mut account = IdlAccount::new(account_type.clone(), account_type.to_lowercase());
                    
                    // Analyze data to extract fields
                    let fields = self.analyze_account_data(&change.data_after);
                    
                    // Add fields to account
                    for (name, type_name, offset) in fields {
                        account.add_field(name, type_name, offset);
                    }
                    
                    // Add to IDL
                    idl.accounts.push(account);
                }
            }
        }
    }
    
    /// Identify account type from data
    fn identify_account_type(&self, data: &[u8]) -> Option<String> {
        // Check for Anchor discriminator
        if data.len() >= ANCHOR_DISCRIMINATOR_LENGTH {
            let mut discriminator = [0u8; ANCHOR_DISCRIMINATOR_LENGTH];
            discriminator.copy_from_slice(&data[0..ANCHOR_DISCRIMINATOR_LENGTH]);
            
            // Try to match with known account types
            for account in &self.idl.accounts {
                let account_discriminator = generate_anchor_account_discriminator(&account.name);
                if discriminator == account_discriminator {
                    return Some(account.name.clone());
                }
            }
            
            // If not found, try common account names
            let common_accounts = [
                "State", "Config", "User", "Pool", "Vault", "Token", "Mint", "Authority",
                "Escrow", "Stake", "Vote", "Proposal", "Transaction", "Metadata", "Settings",
            ];
            
            for &name in &common_accounts {
                let account_discriminator = generate_anchor_account_discriminator(name);
                if discriminator == account_discriminator {
                    return Some(name.to_string());
                }
            }
        }
        
        // Default to generic account name
        Some("Account".to_string())
    }
    
    /// Analyze account data to extract fields
    fn analyze_account_data(&self, data: &[u8]) -> Vec<(String, String, usize)> {
        let mut fields = Vec::new();
        
        // Skip discriminator for Anchor accounts
        let start_offset = if self.idl.metadata.origin == "anchor" {
            ANCHOR_DISCRIMINATOR_LENGTH
        } else {
            0
        };
        
        if data.len() <= start_offset {
            return fields;
        }
        
        let data = &data[start_offset..];
        
        // Look for pubkeys (32 byte aligned data)
        for i in (0..data.len()).step_by(32) {
            if i + 32 <= data.len() {
                // Check if this looks like a pubkey (non-zero, not all same value)
                let slice = &data[i..i+32];
                let is_nonzero = slice.iter().any(|&b| b != 0);
                let not_all_same = slice.windows(2).any(|w| w[0] != w[1]);
                
                if is_nonzero && not_all_same {
                    fields.push((
                        format!("pubkey_at_{}", i),
                        "Pubkey".to_string(),
                        i + start_offset
                    ));
                }
            }
        }
        
        // Look for other common types
        let mut offset = 0;
        while offset < data.len() {
            let remaining = data.len() - offset;
            
            if remaining >= 8 {
                fields.push((
                    format!("field_at_{}", offset),
                    "u64".to_string(),
                    offset + start_offset
                ));
                offset += 8;
            } else if remaining >= 4 {
                fields.push((
                    format!("field_at_{}", offset),
                    "u32".to_string(),
                    offset + start_offset
                ));
                offset += 4;
            } else if remaining >= 2 {
                fields.push((
                    format!("field_at_{}", offset),
                    "u16".to_string(),
                    offset + start_offset
                ));
                offset += 2;
            } else {
                fields.push((
                    format!("field_at_{}", offset),
                    "u8".to_string(),
                    offset + start_offset
                ));
                offset += 1;
            }
        }
        
        fields
    }
}

/// Extract account address from log message
fn extract_account_address_from_log(log: &str) -> Option<String> {
    if log.contains("Account:") {
        let parts: Vec<&str> = log.split("Account:").collect();
        if parts.len() > 1 {
            let address_part = parts[1].trim();
            let address = address_part.split_whitespace().next()?;
            return Some(address.to_string());
        }
    }
    None
}

/// Generate Anchor account discriminator
pub fn generate_anchor_account_discriminator(name: &str) -> [u8; 8] {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(format!("account:{}", name).as_bytes());
    let result = hasher.finalize();
    
    let mut discriminator = [0u8; 8];
    discriminator.copy_from_slice(&result[..8]);
    discriminator
}

/// Extract instruction from transaction data with improved error handling
fn extract_instruction_from_transaction(transaction_data: &[u8], program_id: &Pubkey) -> ExtractorResult<Instruction> {
    let context = ErrorContext {
        program_id: Some(program_id.to_string()),
        component: "transaction_simulator".to_string(),
        operation: "extract_instruction".to_string(),
        details: Some(format!("data_len={}", transaction_data.len())),
    };
    
    let (data, accounts) = crate::utils::transaction_parser::parse_transaction(transaction_data)
        .with_context(context.clone())?;
    
    // Create an instruction from the parsed data
    let instruction = Instruction {
        program_id: *program_id,
        accounts,
        data,
    };
    
    Ok(instruction)
}