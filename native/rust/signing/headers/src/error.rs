// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::borrow::Cow;

/// Errors that can occur when working with COSE headers and CWT claims.
#[derive(Debug)]
pub enum HeaderError {
    CborEncodingError(Cow<'static, str>),

    CborDecodingError(Cow<'static, str>),

    InvalidClaimType {
        label: i64,
        expected: Cow<'static, str>,
        actual: Cow<'static, str>,
    },

    MissingRequiredClaim(Cow<'static, str>),

    InvalidTimestamp(Cow<'static, str>),

    ComplexClaimValue(Cow<'static, str>),
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CborEncodingError(msg) => write!(f, "CBOR encoding error: {}", msg),
            Self::CborDecodingError(msg) => write!(f, "CBOR decoding error: {}", msg),
            Self::InvalidClaimType {
                label,
                expected,
                actual,
            } => write!(
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
