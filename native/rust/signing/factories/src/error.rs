// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Factory errors.

use std::borrow::Cow;

/// Error type for factory operations.
#[derive(Debug)]
pub enum FactoryError {
    /// Signing operation failed.
    SigningFailed { detail: Cow<'static, str> },

    /// Post-sign verification failed.
    VerificationFailed { detail: Cow<'static, str> },

    /// Invalid input provided to factory.
    InvalidInput { detail: Cow<'static, str> },

    /// CBOR encoding/decoding error.
    CborError { detail: Cow<'static, str> },

    /// Transparency provider failed.
    TransparencyFailed { detail: Cow<'static, str> },

    /// Payload exceeds maximum size for embedding.
    PayloadTooLargeForEmbedding { actual: u64, max: u64 },
}

impl std::fmt::Display for FactoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SigningFailed { detail } => write!(f, "Signing failed: {}", detail),
            Self::VerificationFailed { detail } => {
                write!(f, "Verification failed: {}", detail)
            }
            Self::InvalidInput { detail } => write!(f, "Invalid input: {}", detail),
            Self::CborError { detail } => write!(f, "CBOR error: {}", detail),
            Self::TransparencyFailed { detail } => {
                write!(f, "Transparency failed: {}", detail)
            }
            Self::PayloadTooLargeForEmbedding { actual, max } => {
                write!(
                    f,
                    "Payload too large for embedding: {} bytes (max {})",
                    actual, max
                )
            }
        }
    }
}

impl std::error::Error for FactoryError {}

impl From<cose_sign1_signing::SigningError> for FactoryError {
    fn from(err: cose_sign1_signing::SigningError) -> Self {
        match err {
            cose_sign1_signing::SigningError::VerificationFailed { detail } => {
                FactoryError::VerificationFailed { detail }
            }
            _ => FactoryError::SigningFailed {
                detail: err.to_string().into(),
            },
        }
    }
}

impl From<cose_sign1_primitives::CoseSign1Error> for FactoryError {
    fn from(err: cose_sign1_primitives::CoseSign1Error) -> Self {
        FactoryError::SigningFailed {
            detail: err.to_string().into(),
        }
    }
}
