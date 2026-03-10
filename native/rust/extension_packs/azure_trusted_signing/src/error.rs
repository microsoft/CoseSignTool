// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for Azure Trusted Signing operations.

use std::fmt;

/// Errors from Azure Trusted Signing operations.
#[derive(Debug)]
pub enum AtsError {
    /// Failed to fetch signing certificate from ATS.
    CertificateFetchFailed(String),
    /// Signing operation failed.
    SigningFailed(String),
    /// Invalid configuration.
    InvalidConfiguration(String),
    /// DID:x509 construction failed.
    DidX509Error(String),
}

impl fmt::Display for AtsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertificateFetchFailed(msg) => write!(f, "ATS certificate fetch failed: {}", msg),
            Self::SigningFailed(msg) => write!(f, "ATS signing failed: {}", msg),
            Self::InvalidConfiguration(msg) => write!(f, "ATS invalid configuration: {}", msg),
            Self::DidX509Error(msg) => write!(f, "ATS DID:x509 error: {}", msg),
        }
    }
}

impl std::error::Error for AtsError {}