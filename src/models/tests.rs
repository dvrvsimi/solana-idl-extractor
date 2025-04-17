#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::patterns::{PatternAnalysis, InstructionPattern, AccountPattern};
    
    #[test]
    fn test_idl_new() {
        let program_id = "11111111111111111111111111111111".to_string();
        let idl = IDL::new(program_id.clone());
        
        assert_eq!(idl.name, "program_11111111");
        assert_eq!(idl.version, "0.1.0");
        assert_eq!(idl.program_id, program_id);
        assert!(idl.instructions.is_empty());
        assert!(idl.accounts.is_empty());
        assert!(idl.errors.is_empty());
        assert!(idl.metadata.is_none());
    }
    
    #[test]
    fn test_idl_add_error() {
        let program_id = "11111111111111111111111111111111".to_string();
        let mut idl = IDL::new(program_id);
        
        idl.add_error(1, "TestError".to_string(), "Test error message".to_string());
        
        assert_eq!(idl.errors.len(), 1);
        assert_eq!(idl.errors[0].code, 1);
        assert_eq!(idl.errors[0].name, "TestError");
        assert_eq!(idl.errors[0].msg, "Test error message");
    }
    
    #[test]
    fn test_idl_set_metadata() {
        let program_id = "11111111111111111111111111111111".to_string();
        let mut idl = IDL::new(program_id.clone());
        
        idl.set_metadata("native".to_string(), Some("1.0.0".to_string()));
        
        assert!(idl.metadata.is_some());
        let metadata = idl.metadata.unwrap();
        assert_eq!(metadata.address, program_id);
        assert_eq!(metadata.origin, "native");
        assert_eq!(metadata.framework_version, Some("1.0.0".to_string()));
    }
} 