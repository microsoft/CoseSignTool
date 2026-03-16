// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for Azure Artifact Signing operations.

use std::fmt;

/// Errors from Azure Artifact Signing operations.
#[derive(Debug)]
pub enum AasError {
    /// Failed to fetch signing certificate from AAS.
    CertificateFetchFailed(String),
    /// Signing operation failed.
    SigningFailed(String),
    /// Invalid configuration.
    InvalidConfiguration(String),
    /// DID:x509 construction failed.
    DidX509Error(String),
}

impl fmt::Display for AasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertificateFetchFailed(msg) => write!(f, "AAS certificate fetch failed: {}", msg),
            Self::SigningFailed(msg) => write!(f, "AAS signing failed: {}", msg),
            Self::InvalidConfiguration(msg) => write!(f, "AAS invalid configuration: {}", msg),
            Self::DidX509Error(msg) => write!(f, "AAS DID:x509 error: {}", msg),
        }
    }
}

impl std::error::Error for AasError {}
