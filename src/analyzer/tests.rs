//! Tests for the analyzer module

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::models::{Instruction, Account};
    
    #[test]
    fn test_bytecode_analysis_basic() {
        // Create a simple mock program bytecode
        // This would be a simplified representation of a Solana program
        let program_data = include_bytes!("../../tests/fixtures/simple_program.so");
        
        // Analyze the bytecode
        let analysis = bytecode::analyze(program_data).unwrap();
        
        // Verify the analysis results
        assert!(!analysis.instructions.is_empty(), "Should extract at least one instruction");
        
        // Check the first instruction
        let first_instruction = &analysis.instructions[0];
        assert_eq!(first_instruction.name, "initialize", "First instruction should be 'initialize'");
        assert_eq!(first_instruction.index, 0, "First instruction should have index 0");
    }
    
    #[test]
    fn test_find_pattern() {
        let data = b"Hello, this is a test pattern";
        assert!(bytecode::find_pattern(data, b"test"));
        assert!(!bytecode::find_pattern(data, b"nonexistent"));
    }
    
    #[test]
    fn test_is_anchor_program() {
        let anchor_program = b"anchor_program_some_data";
        assert!(bytecode::is_anchor_program(anchor_program));
        
        let non_anchor_program = b"regular_solana_program";
        assert!(!bytecode::is_anchor_program(non_anchor_program));
    }
    
    #[test]
    fn test_analyze_invalid_data() {
        let invalid_data = b"not an ELF file";
        let result = bytecode::analyze(invalid_data);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_analyze_elf_header() {
        // Create a mock ELF header
        let mut mock_elf = vec![0u8; 16];
        mock_elf[0] = 0x7F;
        mock_elf[1] = b'E';
        mock_elf[2] = b'L';
        mock_elf[3] = b'F';
        
        // Add "account" string to trigger account detection
        mock_elf.extend_from_slice(b"account");
        
        let result = bytecode::analyze(&mock_elf);
        assert!(result.is_ok());
        
        let analysis = result.unwrap();
        assert_eq!(analysis.accounts.len(), 1);
        assert_eq!(analysis.accounts[0].name, "GenericAccount");
    }
    
    #[test]
    fn test_pattern_analysis_empty() {
        let program_id = Pubkey::new_unique();
        let transactions = Vec::new();
        
        let result = patterns::analyze(&program_id, &transactions);
        assert!(result.is_ok());
        
        let analysis = result.unwrap();
        assert!(analysis.instruction_patterns.is_empty());
        assert!(analysis.account_patterns.is_empty());
    }
    
    #[test]
    fn test_analyze_instruction_patterns() {
        // Create mock instruction data
        let instruction_data = vec![
            vec![0, 1, 2, 3],
            vec![0, 4, 5, 6],
            vec![1, 7, 8, 9],
        ];
        
        let patterns = patterns::analyze_instruction_patterns(&instruction_data);
        
        assert_eq!(patterns.len(), 2);
        
        // Check that we have patterns for discriminators 0 and 1
        let has_discriminator_0 = patterns.iter().any(|p| p.index == 0 && p.frequency == 2);
        let has_discriminator_1 = patterns.iter().any(|p| p.index == 1 && p.frequency == 1);
        
        assert!(has_discriminator_0);
        assert!(has_discriminator_1);
    }
    
    #[test]
    fn test_parse_elf_sections() {
        // Create a minimal valid ELF header
        let mut elf_data = vec![0u8; 1024];
        
        // ELF magic number
        elf_data[0] = 0x7F;
        elf_data[1] = b'E';
        elf_data[2] = b'L';
        elf_data[3] = b'F';
        
        // 64-bit ELF
        elf_data[4] = 2;
        
        // Little endian
        elf_data[5] = 1;
        
        // ELF version
        elf_data[6] = 1;
        
        // Set section header offset (e_shoff) to 64
        elf_data[40] = 64;
        
        // Set section header entry size (e_shentsize) to 64
        elf_data[58] = 64;
        
        // Set number of section headers (e_shnum) to 3
        elf_data[60] = 3;
        
        // Set section header string table index (e_shstrndx) to 1
        elf_data[62] = 1;
        
        // Create a string table section
        // Section 1: String table
        let str_table_offset = 200;
        let str_table = b"\0.text\0.data\0.rodata\0";
        
        // Section header for string table
        let str_hdr_offset = 64 + 64; // Second section header
        elf_data[str_hdr_offset] = 1; // sh_name = 1
        elf_data[str_hdr_offset + 24] = str_table_offset as u8; // sh_offset
        elf_data[str_hdr_offset + 32] = str_table.len() as u8; // sh_size
        
        // Copy string table to data
        for (i, &b) in str_table.iter().enumerate() {
            elf_data[str_table_offset + i] = b;
        }
        
        // Create .text section
        // Section 2: .text
        let text_offset = 300;
        let text_data = b"Some code";
        
        // Section header for .text
        let text_hdr_offset = 64 + 64 * 2; // Third section header
        elf_data[text_hdr_offset] = 1; // sh_name = 1 (.text)
        elf_data[text_hdr_offset + 24] = text_offset as u8; // sh_offset
        elf_data[text_hdr_offset + 32] = text_data.len() as u8; // sh_size
        
        // Copy .text to data
        for (i, &b) in text_data.iter().enumerate() {
            elf_data[text_offset + i] = b;
        }
        
        // Parse sections
        let sections = bytecode::parse_elf_sections(&elf_data).unwrap();
        
        // Verify sections
        assert!(!sections.is_empty(), "Should extract at least one section");
        
        // Check if .text section was extracted
        let has_text = sections.iter().any(|(name, _)| name == ".text");
        assert!(has_text, "Should extract .text section");
    }
    
    #[test]
    fn test_find_byte_comparisons() {
        // Create mock code with comparison instructions
        let mut code = vec![0u8; 100];
        
        // CMP AL, 0
        code[10] = 0x3C;
        code[11] = 0x00;
        
        // CMP AL, 1
        code[20] = 0x3C;
        code[21] = 0x01;
        
        // CMP byte ptr [rax], 2
        code[30] = 0x80;
        code[31] = 0x38;
        code[32] = 0x02;
        
        // Find comparisons
        let comparisons = bytecode::find_byte_comparisons(&code);
        
        // Verify comparisons
        assert_eq!(comparisons.len(), 3, "Should find 3 comparisons");
        
        // Check comparison values
        let values: Vec<u8> = comparisons.iter().map(|(_, v)| *v).collect();
        assert!(values.contains(&0), "Should find comparison with 0");
        assert!(values.contains(&1), "Should find comparison with 1");
        assert!(values.contains(&2), "Should find comparison with 2");
    }
    
    #[test]
    fn test_infer_parameters() {
        // Create mock code with memory access patterns
        let mut code = vec![0u8; 200];
        
        // 8-byte access (u64)
        code[10] = 0x48;
        code[11] = 0x8B;
        
        // 4-byte access (u32)
        code[20] = 0x8B;
        
        // 32-byte access (Pubkey)
        code[30] = 0xC7;
        code[33] = 0x20;
        
        // Infer parameters
        let params = bytecode::infer_parameters(&code, 5);
        
        // Verify parameters
        assert!(!params.is_empty(), "Should infer at least one parameter");
        
        // Check parameter types
        let has_pubkey = params.iter().any(|p| p == "pubkey");
        let has_u64 = params.iter().any(|p| p == "u64");
        
        assert!(has_pubkey || has_u64, "Should infer pubkey or u64 parameter");
    }
    
    #[test]
    fn test_infer_parameter_types() {
        // Test with empty data
        let empty_data = &[];
        assert!(infer_parameter_types(empty_data).is_empty());
        
        // Test with u8
        let u8_data = &[42];
        let u8_types = infer_parameter_types(u8_data);
        assert_eq!(u8_types, vec!["u8"]);
        
        // Test with u32
        let u32_data = &[1, 2, 3, 4];
        let u32_types = infer_parameter_types(u32_data);
        assert_eq!(u32_types, vec!["u32"]);
        
        // Test with u64
        let u64_data = &[1, 2, 3, 4, 0, 0, 0, 0];
        let u64_types = infer_parameter_types(u64_data);
        assert_eq!(u64_types, vec!["u64"]);
        
        // Test with pubkey
        let mut pubkey_data = vec![0; 32];
        pubkey_data[0] = 1;
        pubkey_data[31] = 1;
        let pubkey_types = infer_parameter_types(&pubkey_data);
        assert_eq!(pubkey_types, vec!["pubkey"]);
        
        // Test with mixed types
        let mixed_data = &[
            // u8
            42,
            // u32
            1, 2, 3, 4,
            // pubkey
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
        ];
        let mixed_types = infer_parameter_types(mixed_data);
        assert_eq!(mixed_types.len(), 3);
        assert_eq!(mixed_types[0], "u8");
        assert_eq!(mixed_types[1], "u32");
        assert_eq!(mixed_types[2], "pubkey");
    }
    
    #[test]
    fn test_extract_discriminator() {
        // Create a mock UiInstruction
        let mut instruction = solana_transaction_status::UiInstruction {
            program_id: Some("11111111111111111111111111111111".to_string()),
            accounts: Some(vec!["0".to_string(), "1".to_string()]),
            data: Some("AQIDBA==".to_string()), // Base64 for [1,2,3,4]
        };
        
        // Test with base64 data
        let discriminator = extract_discriminator(&instruction);
        assert_eq!(discriminator, 1);
        
        // Test with base58 data
        instruction.data = Some("2Pv5".to_string()); // Base58 for [1,2,3,4]
        let discriminator = extract_discriminator(&instruction);
        assert_eq!(discriminator, 1);
        
        // Test with empty data
        instruction.data = Some("".to_string());
        let discriminator = extract_discriminator(&instruction);
        assert_eq!(discriminator, 0);
        
        // Test with no data
        instruction.data = None;
        let discriminator = extract_discriminator(&instruction);
        assert_eq!(discriminator, 0);
    }
} 