// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for certificate operations.

use crypto_primitives::CryptoError;

/// Error type for local certificate operations.
#[derive(Debug)]
pub enum CertLocalError {
    /// Key generation failed.
    KeyGenerationFailed(String),
    /// Certificate creation failed.
    CertificateCreationFailed(String),
    /// Invalid options provided.
    InvalidOptions(String),
    /// Unsupported algorithm.
    UnsupportedAlgorithm(String),
    /// I/O error.
    IoError(String),
    /// Load failed.
    LoadFailed(String),
}

impl std::fmt::Display for CertLocalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGenerationFailed(msg) => write!(f, "key generation failed: {}", msg),
            Self::CertificateCreationFailed(msg) => {
                write!(f, "certificate creation failed: {}", msg)
            }
            Self::InvalidOptions(msg) => write!(f, "invalid options: {}", msg),
            Self::UnsupportedAlgorithm(msg) => write!(f, "unsupported algorithm: {}", msg),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::LoadFailed(msg) => write!(f, "load failed: {}", msg),
        }
    }
}

impl std::error::Error for CertLocalError {}

impl From<CryptoError> for CertLocalError {
    fn from(err: CryptoError) -> Self {
        Self::KeyGenerationFailed(err.to_string())
    }
}
