// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Validation result types.
//!
//! The Rust port uses a structured result type rather than raising exceptions.
//! This keeps callers in control of error handling and provides enough detail
//! for diagnostics (message + optional error code).

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationFailure {
    /// Human-readable explanation of the failure.
    pub message: String,
    /// Optional machine-readable error code.
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResult {
    /// Overall validity.
    pub is_valid: bool,
    /// Name of the validator producing this result (used by higher-level aggregators).
    pub validator_name: String,
    /// A list of failures explaining why validation failed.
    pub failures: Vec<ValidationFailure>,
    /// Extra metadata for callers (e.g., diagnostic information).
    pub metadata: HashMap<String, String>,
}

impl ValidationResult {
    /// Construct a success result.
    pub fn success(validator_name: impl Into<String>, metadata: HashMap<String, String>) -> Self {
        Self {
            is_valid: true,
            validator_name: validator_name.into(),
            failures: Vec::new(),
            metadata,
        }
    }

    /// Construct a failure result with one or more failures.
    pub fn failure(validator_name: impl Into<String>, failures: Vec<ValidationFailure>) -> Self {
        Self {
            is_valid: false,
            validator_name: validator_name.into(),
            failures,
            metadata: HashMap::new(),
        }
    }

    /// Construct a failure result from a single message + optional error code.
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
