// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signing errors.

/// Error type for signing operations.
#[derive(Debug)]
pub enum SigningError {
    /// Error related to key operations.
    KeyError(String),

    /// Header contribution failed.
    HeaderContributionFailed(String),

    /// Signing operation failed.
    SigningFailed(String),

    /// Signature verification failed.
    VerificationFailed(String),

    /// Invalid configuration.
    InvalidConfiguration(String),
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyError(msg) => write!(f, "Key error: {}", msg),
            Self::HeaderContributionFailed(msg) => write!(f, "Header contribution failed: {}", msg),
            Self::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            Self::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            Self::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
        }
    }
}

impl std::error::Error for SigningError {}
