// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Errors that can occur when working with COSE headers and CWT claims.
#[derive(Debug)]
pub enum HeaderError {
    CborEncodingError(String),

    CborDecodingError(String),

    InvalidClaimType {
        label: i64,
        expected: String,
        actual: String,
    },

    MissingRequiredClaim(String),

    InvalidTimestamp(String),

    ComplexClaimValue(String),
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CborEncodingError(msg) => write!(f, "CBOR encoding error: {}", msg),
            Self::CborDecodingError(msg) => write!(f, "CBOR decoding error: {}", msg),
            Self::InvalidClaimType { label, expected, actual } => write!(
                f,
                "Invalid CWT claim type for label {}: expected {}, got {}",
                label, expected, actual
            ),
            Self::MissingRequiredClaim(msg) => write!(f, "Missing required claim: {}", msg),
            Self::InvalidTimestamp(msg) => write!(f, "Invalid timestamp value: {}", msg),
            Self::ComplexClaimValue(msg) => write!(f, "Custom claim value too complex: {}", msg),
        }
    }
}

impl std::error::Error for HeaderError {}
