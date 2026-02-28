// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate error types.

/// Errors related to certificate operations.
#[derive(Debug)]
pub enum CertificateError {
    /// Certificate not found.
    NotFound,
    /// Invalid certificate.
    InvalidCertificate(String),
    /// Chain building failed.
    ChainBuildFailed(String),
    /// Private key not available.
    NoPrivateKey,
    /// Signing error.
    SigningError(String),
}

impl std::fmt::Display for CertificateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Certificate not found"),
            Self::InvalidCertificate(s) => write!(f, "Invalid certificate: {}", s),
            Self::ChainBuildFailed(s) => write!(f, "Chain building failed: {}", s),
            Self::NoPrivateKey => write!(f, "Private key not available"),
            Self::SigningError(s) => write!(f, "Signing error: {}", s),
        }
    }
}

impl std::error::Error for CertificateError {}


