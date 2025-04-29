//! ELF file parsing for Solana programs

use anyhow::{Result, anyhow, Context};
use goblin::elf::{Elf, header::{EM_BPF, ET_DYN, ET_EXEC}, section_header::*};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use log::{debug, info, warn};

/// ELF section information
#[derive(Debug, Clone)]
pub struct ElfSection {
    /// Section name
    pub name: String,
    /// Section data
    pub data: Vec<u8>,
    /// Section address
    pub address: u64,
    /// Section size
    pub size: u64,
    /// Section type
    pub section_type: u32,
    /// Section flags
    pub flags: u64,
}

/// ELF symbol information
#[derive(Debug, Clone)]
pub struct ElfSymbol {
    /// Symbol name
    pub name: String,
    /// Symbol address
    pub address: u64,
    /// Symbol size
    pub size: u64,
    /// Symbol type
    pub sym_type: u8,
    /// Symbol binding
    pub binding: u8,
    /// Symbol visibility
    pub visibility: u8,
    /// Symbol section index
    pub section_index: u16,
}

/// ELF analyzer for Solana programs
pub struct ElfAnalyzer {
    /// Parsed ELF file
    elf: Box<Elf<'static>>,
    /// Raw binary data
    data: Vec<u8>,
}

impl ElfAnalyzer {
    /// Create a new ELF analyzer from a file path
    pub fn from_file(path: &Path) -> Result<Self> {
        let mut file = File::open(path)
            .context("Failed to open ELF file")?;
        
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .context("Failed to read ELF file")?;
        
        Self::from_bytes(buffer)
    }
    
    /// Create a new ELF analyzer from bytes
    // Update the from_bytes method to use unsafe transmute for the lifetime
pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
    let elf_ref = Elf::parse(&data)
        .context("Failed to parse ELF file")?;
    
    // Use unsafe to convert the lifetime
    let elf = unsafe {
        std::mem::transmute::<Elf, Elf<'static>>(elf_ref)
    };
    
    // Validate that this is a BPF ELF file
    if elf.header.e_machine != EM_BPF {
        warn!("ELF file is not a BPF program (machine type: {})", elf.header.e_machine);
    }
    
    if elf.header.e_type != ET_EXEC && elf.header.e_type != ET_DYN {
        warn!("ELF file is not an executable or shared object (type: {})", elf.header.e_type);
    }
    
    Ok(Self { elf: Box::new(elf), data })
}
    
    /// Get all sections in the ELF file
    pub fn get_sections(&self) -> Result<Vec<ElfSection>> {
        let mut sections = Vec::new();
        
        for section_header in &self.elf.section_headers {
            let name = match self.elf.shdr_strtab.get_at(section_header.sh_name) {
                Some(name) => name.to_string(),
                None => format!("unknown_{}", section_header.sh_name),
            };
            
            let offset = section_header.sh_offset as usize;
            let size = section_header.sh_size as usize;
            
            let data = if offset > 0 && size > 0 && offset + size <= self.data.len() {
                self.data[offset..offset + size].to_vec()
            } else {
                Vec::new()
            };
            
            sections.push(ElfSection {
                name,
                data,
                address: section_header.sh_addr,
                size: section_header.sh_size,
                section_type: section_header.sh_type,
                flags: section_header.sh_flags,
            });
        }
        
        Ok(sections)
    }
    
    /// Get a specific section by name
    pub fn get_section(&self, name: &str) -> Result<Option<ElfSection>> {
        for section_header in &self.elf.section_headers {
            if let Some(section_name) = self.elf.shdr_strtab.get_at(section_header.sh_name) {
                if section_name == name {
                    let offset = section_header.sh_offset as usize;
                    let size = section_header.sh_size as usize;
                    
                    let data = if offset > 0 && size > 0 && offset + size <= self.data.len() {
                        self.data[offset..offset + size].to_vec()
                    } else {
                        Vec::new()
                    };
                    
                    return Ok(Some(ElfSection {
                        name: name.to_string(),
                        data,
                        address: section_header.sh_addr,
                        size: section_header.sh_size,
                        section_type: section_header.sh_type,
                        flags: section_header.sh_flags,
                    }));
                }
            }
        }
        
        Ok(None)
    }
    
    /// Get all symbols in the ELF file
    pub fn get_symbols(&self) -> Result<Vec<ElfSymbol>> {
        let mut symbols = Vec::new();
        
        for sym in &self.elf.syms {
            let name = match self.elf.strtab.get_at(sym.st_name) {
                Some(name) => name.to_string(),
                None => format!("unknown_{}", sym.st_name),
            };
            
            symbols.push(ElfSymbol {
                name,
                address: sym.st_value,
                size: sym.st_size,
                sym_type: sym.st_type(),
                binding: sym.st_bind(),
                visibility: sym.st_visibility(),
                section_index: sym.st_shndx as u16,
            });
        }
        
        Ok(symbols)
    }
    
    /// Get the text section (code)
    pub fn get_text_section(&self) -> Result<Option<ElfSection>> {
        
        // Try standard text section name
        if let Ok(Some(section)) = self.get_section(".text") {
            log::info!("Found standard .text section, size: {} bytes", section.data.len());
            return Ok(Some(section));
        }
        
        // Try alternative text section names
        for name in &[".text.main", ".text.solana", ".text.program", ".text.spl"] {
            if let Ok(Some(section)) = self.get_section(name) {
                log::info!("Found alternative text section: {}, size: {} bytes", name, section.data.len());
                return Ok(Some(section));
            }
        }
        
        log::info!("No standard text section found, looking for any executable section");
        
        // If no specific text section found, look for any section that might contain code
        for section_header in &self.elf.section_headers {
            // Check if section has executable flag
            if section_header.sh_flags & 0x4 != 0 {
                if let Some(section_name) = self.elf.shdr_strtab.get_at(section_header.sh_name) {
                    log::info!("Found executable section: {}", section_name);
                    
                    let offset = section_header.sh_offset as usize;
                    let size = section_header.sh_size as usize;
                    
                    let data = if offset > 0 && size > 0 && offset + size <= self.data.len() {
                        self.data[offset..offset + size].to_vec()
                    } else {
                        log::warn!("Section data is invalid or empty");
                        Vec::new()
                    };
                    
                    log::info!("Using executable section: {}, size: {} bytes", section_name, data.len());
                    
                    return Ok(Some(ElfSection {
                        name: section_name.to_string(),
                        data,
                        address: section_header.sh_addr,
                        size: section_header.sh_size,
                        section_type: section_header.sh_type,
                        flags: section_header.sh_flags,
                    }));
                }
            }
        }
        
        log::warn!("No text or executable section found in ELF file");
        Ok(None)
    }
    
    /// Get the rodata section (read-only data)
    pub fn get_rodata_section(&self) -> Result<Option<ElfSection>> {
        self.get_section(".rodata")
    }
    
    /// Get the data section
    pub fn get_data_section(&self) -> Result<Option<ElfSection>> {
        self.get_section(".data")
    }
    
    /// Get the bss section (uninitialized data)
    pub fn get_bss_section(&self) -> Result<Option<ElfSection>> {
        self.get_section(".bss")
    }
    
    /// Extract all string literals from the ELF file
    pub fn extract_strings(&self) -> Result<Vec<String>> {
        let mut strings = Vec::new();
        
        // Get the rodata section which typically contains string literals
        if let Ok(Some(rodata)) = self.get_rodata_section() {
            let mut i = 0;
            while i < rodata.data.len() {
                // Look for null-terminated strings
                let start = i;
                while i < rodata.data.len() && rodata.data[i] != 0 {
                    i += 1;
                }
                
                if i > start {
                    // Found a potential string
                    if let Ok(s) = std::str::from_utf8(&rodata.data[start..i]) {
                        if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                            strings.push(s.to_string());
                        }
                    }
                }
                
                i += 1;
            }
        }
        
        Ok(strings)
    }
    
    /// Check if this is likely a Solana program
    pub fn is_solana_program(&self) -> bool {
        // Check for BPF architecture
        if self.elf.header.e_machine != EM_BPF {
            return false;
        }
        
        // Check for Solana-specific symbols or strings
        if let Ok(symbols) = self.get_symbols() {
            for symbol in &symbols {
                if symbol.name.contains("solana") || 
                   symbol.name.contains("entrypoint") {
                    return true;
                }
            }
        }
        
        // Check for Solana-specific strings
        if let Ok(strings) = self.extract_strings() {
            for string in &strings {
                if string.contains("solana") || 
                   string.contains("Solana") || 
                   string.contains("Program") {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Get all sections in the ELF file
    pub fn get_all_sections(&self) -> Result<Vec<ElfSection>> {
        let mut sections = Vec::new();
        
        for section_header in &self.elf.section_headers {
            if let Some(section_name) = self.elf.shdr_strtab.get_at(section_header.sh_name) {
                let offset = section_header.sh_offset as usize;
                let size = section_header.sh_size as usize;
                
                let data = if offset > 0 && size > 0 && offset + size <= self.data.len() {
                    self.data[offset..offset + size].to_vec()
                } else {
                    Vec::new()
                };
                
                sections.push(ElfSection {
                    name: section_name.to_string(),
                    data,
                    address: section_header.sh_addr,
                    size: section_header.sh_size,
                    section_type: section_header.sh_type,
                    flags: section_header.sh_flags,
                });
            }
        }
        
        Ok(sections)
    }
}

/// Find a pattern in binary data
pub fn find_pattern(data: &[u8], pattern: &[u8]) -> bool {
    data.windows(pattern.len()).any(|window| window == pattern)
}

/// Parse an ELF file and extract sections
pub fn parse_elf(data: &[u8]) -> Result<HashMap<String, Vec<u8>>> {
    let analyzer = ElfAnalyzer::from_bytes(data.to_vec())?;
    let sections = analyzer.get_sections()?;
    
    let mut result = HashMap::new();
    for section in sections {
        result.insert(section.name, section.data);
    }
    
    Ok(result)
}