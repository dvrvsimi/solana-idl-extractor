//! Error handling for the Solana IDL extractor.
//!
//! This module provides a comprehensive error system for the IDL extractor,
//! including specific error types, context information, and utilities for
//! adding context to errors.
//!
//! The error system is designed to provide detailed information about where
//! and why errors occurred, making it easier to diagnose and fix issues.
//! It also includes fallback mechanisms to gracefully handle error conditions.

use thiserror::Error;
use std::fmt;

/// Main error type for the IDL extractor.
///
/// This enum represents all possible errors that can occur during IDL extraction.
/// Each variant corresponds to a specific category of errors, with a descriptive
/// message providing details about the specific error.
#[derive(Error, Debug)]
pub enum ExtractorError {
    /// Errors related to bytecode analysis, such as invalid instructions or CFG construction.
    #[error("Bytecode analysis error: {0}")]
    BytecodeAnalysis(String),
    
    /// Errors related to transaction parsing, such as invalid transaction formats.
    #[error("Transaction parsing error: {0}")]
    TransactionParsing(String),
    
    /// Errors related to pattern analysis, such as invalid instruction patterns.
    #[error("Pattern analysis error: {0}")]
    PatternAnalysis(String),
    
    /// Errors related to simulation, such as RPC failures or invalid accounts.
    #[error("Simulation error: {0}")]
    Simulation(String),
    
    /// Errors related to RPC communication, such as connection failures.
    #[error("RPC error: {0}")]
    Rpc(String),
    
    /// Errors related to IDL generation, such as invalid IDL formats.
    #[error("IDL generation error: {0}")]
    IdlGeneration(String),
    
    /// Errors related to file I/O, such as file not found or permission denied.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Errors from external libraries, such as serialization failures.
    #[error("External error: {0}")]
    External(String),
    
    /// Fallback for other errors that don't fit into the above categories.
    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Result type alias for the IDL extractor.
///
/// This type alias simplifies the use of `Result` with `ExtractorError`.
pub type ExtractorResult<T> = Result<T, ExtractorError>;

/// Context information for errors.
///
/// This struct provides detailed context about where an error occurred,
/// including the program ID, component, operation, and additional details.
/// This information is useful for diagnosing and fixing errors.
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// Program ID being analyzed, if applicable.
    pub program_id: Option<String>,
    
    /// Component where the error occurred (e.g., "bytecode_parser").
    pub component: String,
    
    /// Operation being performed when the error occurred (e.g., "parse_instructions").
    pub operation: String,
    
    /// Additional context details, such as input sizes or parameters.
    pub details: Option<String>,
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "In {} while {}", self.component, self.operation)?;
        if let Some(program_id) = &self.program_id {
            write!(f, " for program {}", program_id)?;
        }
        if let Some(details) = &self.details {
            write!(f, " ({})", details)?;
        }
        Ok(())
    }
}

/// Extension trait for adding context to errors.
///
/// This trait provides methods for adding context to errors, making it
/// easier to understand where and why errors occurred.
pub trait ErrorExt<T> {
    /// Add context to an error.
    ///
    /// This method adds detailed context information to an error, including
    /// the program ID, component, operation, and additional details.
    ///
    /// # Arguments
    ///
    /// * `context` - The context information to add to the error.
    ///
    /// # Returns
    ///
    /// A result with the original value or an error with added context.
    fn with_context(self, context: ErrorContext) -> ExtractorResult<T>;
    
    /// Add simple context to an error.
    ///
    /// This method adds basic context information to an error, including
    /// the component and operation.
    ///
    /// # Arguments
    ///
    /// * `component` - The component where the error occurred.
    /// * `operation` - The operation being performed when the error occurred.
    ///
    /// # Returns
    ///
    /// A result with the original value or an error with added context.
    fn with_simple_context(self, component: &str, operation: &str) -> ExtractorResult<T>;
}

impl<T, E: std::error::Error + 'static> ErrorExt<T> for Result<T, E> {
    fn with_context(self, context: ErrorContext) -> ExtractorResult<T> {
        self.map_err(|e| {
            let error_msg = format!("{}: {}", context, e);
            match e.downcast::<ExtractorError>() {
                Ok(extractor_err) => extractor_err,
                Err(_) => match e.to_string().to_lowercase() {
                    s if s.contains("rpc") || s.contains("connection") => 
                        ExtractorError::Rpc(error_msg),
                    s if s.contains("bytecode") || s.contains("instruction") => 
                        ExtractorError::BytecodeAnalysis(error_msg),
                    s if s.contains("transaction") || s.contains("parse") => 
                        ExtractorError::TransactionParsing(error_msg),
                    s if s.contains("pattern") || s.contains("analyze") => 
                        ExtractorError::PatternAnalysis(error_msg),
                    s if s.contains("simulation") || s.contains("simulate") => 
                        ExtractorError::Simulation(error_msg),
                    s if s.contains("idl") || s.contains("generate") => 
                        ExtractorError::IdlGeneration(error_msg),
                    s if s.contains("io") || s.contains("file") => 
                        ExtractorError::Io(std::io::Error::new(std::io::ErrorKind::Other, error_msg)),
                    _ => ExtractorError::Unknown(error_msg),
                }
            }
        })
    }
    
    fn with_simple_context(self, component: &str, operation: &str) -> ExtractorResult<T> {
        self.with_context(ErrorContext {
            program_id: None,
            component: component.to_string(),
            operation: operation.to_string(),
            details: None,
        })
    }
}