// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt;

#[derive(Debug)]
pub enum AtsClientError {
    HttpError(String),
    AuthenticationFailed(String),
    ServiceError { code: String, message: String, target: Option<String> },
    OperationFailed { operation_id: String, status: String },
    OperationTimeout { operation_id: String },
    DeserializationError(String),
    InvalidConfiguration(String),
    CertificateChainNotAvailable(String),
    SignFailed(String),
}

impl fmt::Display for AtsClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpError(msg) => write!(f, "HTTP error: {}", msg),
            Self::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            Self::ServiceError { code, message, target } => {
                write!(f, "Service error [{}]: {}", code, message)?;
                if let Some(t) = target { write!(f, " (target: {})", t)?; }
                Ok(())
            }
            Self::OperationFailed { operation_id, status } => write!(f, "Operation {} failed with status: {}", operation_id, status),
            Self::OperationTimeout { operation_id } => write!(f, "Operation {} timed out", operation_id),
            Self::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
            Self::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
            Self::CertificateChainNotAvailable(msg) => write!(f, "Certificate chain not available: {}", msg),
            Self::SignFailed(msg) => write!(f, "Sign failed: {}", msg),
        }
    }
}

impl std::error::Error for AtsClientError {}