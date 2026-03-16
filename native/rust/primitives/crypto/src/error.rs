// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic operation errors.

/// Errors from cryptographic backend operations.
///
/// This is the error type returned by `CryptoSigner`, `CryptoVerifier`,
/// and `CryptoProvider`. It does NOT include COSE-specific errors
/// (those are in `cose_sign1_primitives::CoseKeyError`).
#[derive(Debug)]
pub enum CryptoError {
    /// Signing operation failed.
    SigningFailed(String),
    /// Signature verification failed.
    VerificationFailed(String),
    /// The key material is invalid or corrupted.
    InvalidKey(String),
    /// The requested algorithm is not supported by this backend.
    UnsupportedAlgorithm(i64),
    /// The requested operation is not supported.
    UnsupportedOperation(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SigningFailed(s) => write!(f, "signing failed: {}", s),
            Self::VerificationFailed(s) => write!(f, "verification failed: {}", s),
            Self::InvalidKey(s) => write!(f, "invalid key: {}", s),
            Self::UnsupportedAlgorithm(a) => write!(f, "unsupported algorithm: {}", a),
            Self::UnsupportedOperation(s) => write!(f, "unsupported operation: {}", s),
        }
    }
}

impl std::error::Error for CryptoError {}
