// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Factory errors.

/// Error type for factory operations.
#[derive(Debug)]
pub enum FactoryError {
    /// Signing operation failed.
    SigningFailed(String),

    /// Post-sign verification failed.
    VerificationFailed(String),

    /// Invalid input provided to factory.
    InvalidInput(String),

    /// CBOR encoding/decoding error.
    CborError(String),

    /// Transparency provider failed.
    TransparencyFailed(String),

    /// Payload exceeds maximum size for embedding.
    PayloadTooLargeForEmbedding(u64, u64),
}

impl std::fmt::Display for FactoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            Self::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            Self::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Self::CborError(msg) => write!(f, "CBOR error: {}", msg),
            Self::TransparencyFailed(msg) => write!(f, "Transparency failed: {}", msg),
            Self::PayloadTooLargeForEmbedding(size, max) => {
                write!(
                    f,
                    "Payload too large for embedding: {} bytes (max {})",
                    size, max
                )
            }
        }
    }
}

impl std::error::Error for FactoryError {}

impl From<cose_sign1_signing::SigningError> for FactoryError {
    fn from(err: cose_sign1_signing::SigningError) -> Self {
        match err {
            cose_sign1_signing::SigningError::VerificationFailed(msg) => {
                FactoryError::VerificationFailed(msg)
            }
            _ => FactoryError::SigningFailed(err.to_string()),
        }
    }
}

impl From<cose_sign1_primitives::CoseSign1Error> for FactoryError {
    fn from(err: cose_sign1_primitives::CoseSign1Error) -> Self {
        FactoryError::SigningFailed(err.to_string())
    }
}
