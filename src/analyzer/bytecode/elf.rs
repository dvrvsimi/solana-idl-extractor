//! ELF file handling for Solana programs

use anyhow::{Result, anyhow, Context};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::path::Path;
use std::fs::File;
use goblin::elf;
use goblin::elf::header::{EM_BPF, EM_X86_64, EM_AARCH64};
use goblin::elf::section_header::{SHT_SYMTAB, SHT_STRTAB, SHT_REL, SHT_RELA};
use goblin::elf::dynamic::DT_NULL;
use std::convert::TryInto;

/// ELF section
#[derive(Debug, Clone)]
pub struct ElfSection {
    /// Section name
    pub name: String,
    /// Section data
    pub data: Vec<u8>,
    /// Section address
    pub address: usize,
    /// Section size
    pub size: usize,
}

/// Parse ELF sections from program data
pub fn parse_elf_sections(program_data: &[u8]) -> Result<Vec<ElfSection>> {
    let mut sections = Vec::new();
    
    // Check ELF header
    if program_data.len() < 64 {
        return Err(anyhow!("Program data too small to be a valid ELF file"));
    }
    
    // Get section header offset (e_shoff)
    let sh_offset = u64::from_le_bytes(program_data[40..48].try_into().unwrap()) as usize;
    
    // Get section header entry size (e_shentsize)
    let sh_entsize = u16::from_le_bytes(program_data[58..60].try_into().unwrap()) as usize;
    
    // Get number of section headers (e_shnum)
    let sh_num = u16::from_le_bytes(program_data[60..62].try_into().unwrap()) as usize;
    
    // Get section header string table index (e_shstrndx)
    let sh_strndx = u16::from_le_bytes(program_data[62..64].try_into().unwrap()) as usize;
    
    if sh_offset == 0 || sh_entsize == 0 || sh_num == 0 {
        return Err(anyhow!("Invalid ELF section header information"));
    }
    
    // Get section header string table
    let str_hdr_offset = sh_offset + sh_strndx * sh_entsize;
    if str_hdr_offset + 24 >= program_data.len() {
        return Err(anyhow!("Invalid section header string table offset"));
    }
    
    let str_offset = u64::from_le_bytes(program_data[str_hdr_offset + 24..str_hdr_offset + 32].try_into().unwrap()) as usize;
    let str_size = u64::from_le_bytes(program_data[str_hdr_offset + 32..str_hdr_offset + 40].try_into().unwrap()) as usize;
    
    if str_offset + str_size > program_data.len() {
        return Err(anyhow!("Invalid section header string table data"));
    }
    
    let str_table = &program_data[str_offset..str_offset + str_size];
    
    // Parse section headers
    for i in 0..sh_num {
        let hdr_offset = sh_offset + i * sh_entsize;
        if hdr_offset + sh_entsize > program_data.len() {
            continue;
        }
        
        // Get section name offset
        let name_offset = u32::from_le_bytes(program_data[hdr_offset..hdr_offset + 4].try_into().unwrap()) as usize;
        
        // Get section offset
        let offset = u64::from_le_bytes(program_data[hdr_offset + 24..hdr_offset + 32].try_into().unwrap()) as usize;
        
        // Get section size
        let size = u64::from_le_bytes(program_data[hdr_offset + 32..hdr_offset + 40].try_into().unwrap()) as usize;
        
        // Get section address
        let address = u64::from_le_bytes(program_data[hdr_offset + 16..hdr_offset + 24].try_into().unwrap()) as usize;
        
        if offset + size > program_data.len() {
            continue;
        }
        
        // Extract section name
        let mut name_end = name_offset;
        while name_end < str_table.len() && str_table[name_end] != 0 {
            name_end += 1;
        }
        
        let name = if name_offset < str_table.len() {
            String::from_utf8_lossy(&str_table[name_offset..name_end]).to_string()
        } else {
            format!("section_{}", i)
        };
        
        // Extract section data
        let data = program_data[offset..offset + size].to_vec();
        
        sections.push(ElfSection {
            name,
            data,
            address,
            size,
        });
    }
    
    if sections.is_empty() {
        return Err(anyhow!("No valid sections found"));
    }
    
    Ok(sections)
}

/// Represents a relocation entry in an ELF file
#[derive(Debug, Clone)]
pub struct RelocationEntry {
    pub offset: u64,      // Location to apply the relocation
    pub symbol_index: u32, // Symbol table index
    pub r_type: u32,      // Relocation type
    pub addend: i64,      // Optional addend (for RELA type)
}

/// Represents a symbol from the ELF symbol table
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub binding: SymbolBinding,
    pub symbol_type: SymbolType,
    pub section_index: u16,
}

/// Symbol binding (local, global, weak)
#[derive(Debug, Clone, PartialEq)]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
    Unknown(u8),
}

/// Symbol type (object, function, section, etc.)
#[derive(Debug, Clone, PartialEq)]
pub enum SymbolType {
    NoType,
    Object,
    Function,
    Section,
    File,
    Common,
    TLS,
    Unknown(u8),
}

/// ELF analyzer
pub struct ElfAnalyzer<'a> {
    elf_file: elf::Elf<'a>,
    data: &'a [u8],
}

impl<'a> ElfAnalyzer<'a> {
    /// Create a new ELF analyzer from bytes
    pub fn from_bytes(data: &'a [u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(anyhow!("File too small"));
        }
        
        let elf_file = elf::Elf::parse(data)
            .map_err(|e| anyhow!("Failed to parse ELF file: {}", e))?;
        
        // Validate architecture
        let arch = match elf_file.header.e_machine {
            EM_BPF => "BPF",
            EM_X86_64 => "x86_64",
            EM_AARCH64 => "AArch64",
            other => return Err(anyhow!("Unsupported architecture: {}", other)),
        };
        
        debug!("Detected ELF architecture: {}", arch);
        
        Ok(Self {
            elf_file,
            data,
        })
    }
    
    /// Get all functions from the symbol table
    pub fn get_functions(&self) -> Result<Vec<Symbol>> {
        let symbols = self.parse_symbols()?;
        Ok(symbols.into_iter()
            .filter(|sym| sym.symbol_type == SymbolType::Function)
            .collect())
    }
    
    /// Parse the symbol table and extract function names and addresses
    pub fn parse_symbols(&self) -> Result<Vec<Symbol>> {
        let mut symbols = Vec::new();
        
        // Use goblin's built-in symbol table parsing
        for sym in self.elf_file.syms.iter() {
            let name = self.elf_file.strtab.get_at(sym.st_name)
                .unwrap_or_default()
                .to_string();
            
            // Extract binding and type from st_info
            let binding = match (sym.st_info >> 4) & 0xf {
                0 => SymbolBinding::Local,
                1 => SymbolBinding::Global,
                2 => SymbolBinding::Weak,
                other => SymbolBinding::Unknown(other),
            };
            
            let symbol_type = match sym.st_info & 0xf {
                0 => SymbolType::NoType,
                1 => SymbolType::Object,
                2 => SymbolType::Function,
                3 => SymbolType::Section,
                4 => SymbolType::File,
                5 => SymbolType::Common,
                6 => SymbolType::TLS,
                other => SymbolType::Unknown(other),
            };
            
            symbols.push(Symbol {
                name,
                address: sym.st_value,
                size: sym.st_size,
                binding,
                symbol_type,
                section_index: sym.st_shndx as u16,
            });
        }
        
        Ok(symbols)
    }
}

/// Find pattern in binary data
pub fn find_pattern(data: &[u8], pattern: &[u8]) -> bool {
    data.windows(pattern.len()).any(|window| window == pattern)
}