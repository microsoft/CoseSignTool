// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationFailure {
    pub message: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub validator_name: String,
    pub failures: Vec<ValidationFailure>,
    pub metadata: HashMap<String, String>,
}

impl ValidationResult {
    pub fn success(validator_name: impl Into<String>, metadata: HashMap<String, String>) -> Self {
        Self {
            is_valid: true,
            validator_name: validator_name.into(),
            failures: Vec::new(),
            metadata,
        }
    }

    pub fn failure(validator_name: impl Into<String>, failures: Vec<ValidationFailure>) -> Self {
        Self {
            is_valid: false,
            validator_name: validator_name.into(),
            failures,
            metadata: HashMap::new(),
        }
    }

    pub fn failure_message(
        validator_name: impl Into<String>,
        message: impl Into<String>,
        error_code: Option<String>,
    ) -> Self {
        Self::failure(
            validator_name,
            vec![ValidationFailure {
                message: message.into(),
                error_code,
            }],
        )
    }
}
