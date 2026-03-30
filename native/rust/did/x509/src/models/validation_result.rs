// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Result of validating a certificate chain against a DID:x509 identifier
#[derive(Debug, Clone, PartialEq)]
pub struct DidX509ValidationResult {
    /// Whether the validation succeeded
    pub is_valid: bool,
    
    /// List of validation errors (empty if valid)
    pub errors: Vec<String>,
    
    /// Index of the CA certificate that matched the fingerprint, if found
    pub matched_ca_index: Option<usize>,
}

impl DidX509ValidationResult {
    /// Create a successful validation result
    pub fn valid(matched_ca_index: usize) -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            matched_ca_index: Some(matched_ca_index),
        }
    }

    /// Create a failed validation result with an error message
    pub fn invalid(error: String) -> Self {
        Self {
            is_valid: false,
            errors: vec![error],
            matched_ca_index: None,
        }
    }

    /// Create a failed validation result with multiple error messages
    pub fn invalid_multiple(errors: Vec<String>) -> Self {
        Self {
            is_valid: false,
            errors,
            matched_ca_index: None,
        }
    }

    /// Add an error to the result
    pub fn add_error(&mut self, error: String) {
        self.is_valid = false;
        self.errors.push(error);
    }
}
