use crate::models::instruction::Argument;
use goblin::elf::Elf;


/// Extract arguments from a program by analyzing its bytecode patterns
pub fn extract_args(program_data: &[u8], entrypoint: usize) -> Vec<Argument> {
    // Parse the ELF file using goblin
    let elf = match Elf::parse(program_data) {
        Ok(elf) => elf,
        Err(e) => {
            log::warn!("Failed to parse ELF file: {}", e);
            return Vec::new();
        }
    };
    
    // Find the text section
    let text_section = match elf.section_headers.iter()
        .find(|header| {
            elf.shdr_strtab.get_at(header.sh_name)
                .map(|name| name == ".text")
                .unwrap_or(false)
        }) {
        Some(section) => section,
        None => {
            log::warn!("Failed to find .text section");
            return Vec::new();
        }
    };
    
    // Extract the text section data
    let text_data = &program_data[text_section.sh_offset as usize..
                                 (text_section.sh_offset + text_section.sh_size) as usize];
    
    // Analyze instruction patterns to identify arguments
    let args = analyze_instruction_patterns(text_data, entrypoint);
    
    // If we couldn't find arguments through pattern analysis, try a heuristic approach
    if args.is_empty() {
        return infer_args_heuristically(text_data, entrypoint);
    }
    
    args
}

/// Analyze instruction patterns to identify arguments
fn analyze_instruction_patterns(text_data: &[u8], entrypoint: usize) -> Vec<Argument> {
    let mut args = Vec::new();
    let mut offset = 0;
    
    // Find the entrypoint in the text section
    while offset + 8 <= text_data.len() {
        let addr = offset;
        
        // If we've reached the entrypoint, start analyzing
        if addr == entrypoint {
            // Look for instruction patterns that load from instruction data
            // This is typically done at the beginning of a function
            let mut _arg_offset = 0;
            
            // Scan the next 50 instructions (arbitrary limit)
            for i in 0..50 {
                if offset + (i+1)*8 > text_data.len() {
                    break;
                }
                
                let opcode = text_data[offset + i*8] & 0x7f;
                let dst_reg = text_data[offset + i*8 + 1] & 0x0f;
                let src_reg = (text_data[offset + i*8 + 1] >> 4) & 0x0f;
                
                let imm = i32::from_le_bytes([
                    text_data[offset + i*8 + 4],
                    text_data[offset + i*8 + 5],
                    text_data[offset + i*8 + 6],
                    text_data[offset + i*8 + 7],
                ]);
                
                // Look for ldxb/ldxh/ldxw/ldxdw instructions that load from r1
                // r1 typically contains the instruction data pointer
                if (opcode == 0x71 || opcode == 0x69 || opcode == 0x61 || opcode == 0x79) && src_reg == 1 {
                    let size = match opcode {
                        0x71 => 1, // ldxb
                        0x69 => 2, // ldxh
                        0x61 => 4, // ldxw
                        0x79 => 8, // ldxdw
                        _ => 0,
                    };
                    
                    if size > 0 {
                        // Use the immediate value as the offset into the instruction data
                        // This helps identify the actual position of the argument
                        let field_offset = imm as usize;
                        
                        // Use the destination register to track where the data goes
                        // This can help identify how the argument is used
                        let field_type = match size {
                            1 => "u8".to_string(),
                            2 => "u16".to_string(),
                            4 => "u32".to_string(),
                            8 => "u64".to_string(),
                            _ => "bytes".to_string(),
                        };
                        
                        // Create a more descriptive name based on the offset and register
                        let name = format!("arg_{}_r{}", field_offset, dst_reg);
                        
                        args.push(Argument {
                            name,
                            ty: field_type,
                            docs: Some(format!("Loaded from offset {} into register r{}", field_offset, dst_reg)),
                        });
                        
                        _arg_offset += size;
                    }
                }
            }
            
            break;
        }
        
        offset += 8;
    }
    
    // Deduplicate arguments by combining those with the same offset
    let mut unique_args = Vec::new();
    let mut seen_offsets = std::collections::HashSet::new();
    
    for arg in args {
        // Extract the offset from the name (arg_X_rY)
        if let Some(offset_str) = arg.name.split('_').nth(1) {
            if let Ok(offset) = offset_str.parse::<usize>() {
                if !seen_offsets.contains(&offset) {
                    seen_offsets.insert(offset);
                    unique_args.push(arg);
                }
            } else {
                unique_args.push(arg);
            }
        } else {
            unique_args.push(arg);
        }
    }
    
    unique_args
}

/// Infer arguments heuristically when pattern analysis fails
fn infer_args_heuristically(_text_data: &[u8], _entrypoint: usize) -> Vec<Argument> {
    // Default to some common argument patterns for Solana programs
    vec![
        Argument {
            name: "instruction_data".to_string(),
            ty: "Vec<u8>".to_string(),
            docs: Some("The instruction data".to_string()),
        },
        Argument {
            name: "accounts".to_string(),
            ty: "Vec<AccountInfo>".to_string(),
            docs: Some("The accounts required by this instruction".to_string()),
        },
    ]
} 