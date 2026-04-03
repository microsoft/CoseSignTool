// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Key Vault error types.

/// Error type for Azure Key Vault operations.
#[derive(Debug)]
pub enum AkvError {
    /// Cryptographic operation failed.
    CryptoOperationFailed(String),

    /// Key not found or inaccessible.
    KeyNotFound(String),

    /// Invalid key type or algorithm.
    InvalidKeyType(String),

    /// Authentication failed.
    AuthenticationFailed(String),

    /// Network or connectivity error.
    NetworkError(String),

    /// Invalid configuration.
    InvalidConfiguration(String),

    /// Certificate source error.
    CertificateSourceError(String),

    /// General error.
    General(String),
}

impl std::fmt::Display for AkvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AkvError::CryptoOperationFailed(msg) => write!(f, "Crypto operation failed: {}", msg),
            AkvError::KeyNotFound(msg) => write!(f, "Key not found: {}", msg),
            AkvError::InvalidKeyType(msg) => write!(f, "Invalid key type or algorithm: {}", msg),
            AkvError::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            AkvError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            AkvError::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
            AkvError::CertificateSourceError(msg) => write!(f, "Certificate source error: {}", msg),
            AkvError::General(msg) => write!(f, "AKV error: {}", msg),
        }
    }
}

impl std::error::Error for AkvError {}
