// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for CoseSign1 operations.
//!
//! Implements `std::error::Error` manually to avoid external dependencies.

use std::fmt;

use crypto_primitives::CryptoError;

use cose_primitives::CoseError;

/// Errors that can occur during key operations.
#[derive(Debug)]
pub enum CoseKeyError {
    /// Cryptographic operation failed.
    Crypto(CryptoError),
    /// Building Sig_structure failed.
    SigStructureFailed(String),
    /// An I/O error occurred.
    IoError(String),
    /// CBOR encoding error.
    CborError(String),
}

impl fmt::Display for CoseKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "{}", e),
            Self::SigStructureFailed(s) => write!(f, "sig_structure failed: {}", s),
            Self::IoError(s) => write!(f, "I/O error: {}", s),
            Self::CborError(s) => write!(f, "CBOR error: {}", s),
        }
    }
}

impl std::error::Error for CoseKeyError {}

impl From<CryptoError> for CoseKeyError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// Errors that can occur during payload operations.
#[derive(Debug, Clone)]
pub enum PayloadError {
    /// Failed to open the payload source.
    OpenFailed(String),
    /// Failed to read the payload.
    ReadFailed(String),
    /// Payload length mismatch (streaming).
    LengthMismatch {
        /// Expected length.
        expected: u64,
        /// Actual bytes read.
        actual: u64,
    },
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenFailed(msg) => write!(f, "failed to open payload: {}", msg),
            Self::ReadFailed(msg) => write!(f, "failed to read payload: {}", msg),
            Self::LengthMismatch { expected, actual } => {
                write!(
                    f,
                    "payload length mismatch: expected {} bytes, got {}",
                    expected, actual
                )
            }
        }
    }
}

impl std::error::Error for PayloadError {}

/// Errors that can occur during CoseSign1 operations.
#[derive(Debug)]
pub enum CoseSign1Error {
    /// CBOR encoding/decoding error.
    CborError(String),
    /// Key operation error.
    KeyError(CoseKeyError),
    /// Payload operation error.
    PayloadError(PayloadError),
    /// The message structure is invalid.
    InvalidMessage(String),
    /// The payload is detached but none was provided for verification.
    PayloadMissing,
    /// Signature verification failed.
    SignatureMismatch,
    /// Payload exceeds maximum size for embedding.
    PayloadTooLargeForEmbedding(u64, u64),
    /// An I/O error occurred.
    IoError(String),
}

impl fmt::Display for CoseSign1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CborError(msg) => write!(f, "CBOR error: {}", msg),
            Self::KeyError(e) => write!(f, "key error: {}", e),
            Self::PayloadError(e) => write!(f, "payload error: {}", e),
            Self::InvalidMessage(msg) => write!(f, "invalid message: {}", msg),
            Self::PayloadMissing => write!(f, "payload is detached but none provided"),
            Self::SignatureMismatch => write!(f, "signature verification failed"),
            Self::PayloadTooLargeForEmbedding(size, max) => {
                write!(
                    f,
                    "payload too large for embedding: {} bytes (max {})",
                    size, max
                )
            }
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
        }
    }
}

impl std::error::Error for CoseSign1Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KeyError(e) => Some(e),
            Self::PayloadError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CoseKeyError> for CoseSign1Error {
    fn from(e: CoseKeyError) -> Self {
        Self::KeyError(e)
    }
}

impl From<PayloadError> for CoseSign1Error {
    fn from(e: PayloadError) -> Self {
        Self::PayloadError(e)
    }
}

impl From<CoseError> for CoseSign1Error {
    fn from(e: CoseError) -> Self {
        match e {
            CoseError::CborError(s) => Self::CborError(s),
            CoseError::InvalidMessage(s) => Self::InvalidMessage(s),
            CoseError::IoError(s) => Self::IoError(s),
        }
    }
}
