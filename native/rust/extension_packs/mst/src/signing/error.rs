// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for MST client operations.

use std::fmt;

/// Errors that can occur during MST client operations.
#[derive(Debug)]
pub enum MstClientError {
    /// HTTP request failed.
    HttpError(String),
    /// CBOR parsing failed.
    CborParseError(String),
    /// Operation timed out after polling.
    OperationTimeout {
        /// The operation ID that timed out.
        operation_id: String,
        /// Number of retries attempted.
        retries: u32,
    },
    /// Operation failed with an error status.
    OperationFailed {
        /// The operation ID that failed.
        operation_id: String,
        /// The status returned by the service.
        status: String,
    },
    /// Required field missing from response.
    MissingField {
        /// Name of the missing field.
        field: String,
    },
}

impl fmt::Display for MstClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MstClientError::HttpError(msg) => write!(f, "HTTP error: {}", msg),
            MstClientError::CborParseError(msg) => write!(f, "CBOR parse error: {}", msg),
            MstClientError::OperationTimeout {
                operation_id,
                retries,
            } => {
                write!(
                    f,
                    "Operation {} timed out after {} retries",
                    operation_id, retries
                )
            }
            MstClientError::OperationFailed {
                operation_id,
                status,
            } => {
                write!(
                    f,
                    "Operation {} failed with status: {}",
                    operation_id, status
                )
            }
            MstClientError::MissingField { field } => {
                write!(f, "Missing required field: {}", field)
            }
        }
    }
}

impl std::error::Error for MstClientError {}
