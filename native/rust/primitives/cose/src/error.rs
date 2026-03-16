// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for generic COSE operations.
//!
//! These errors cover CBOR encoding/decoding and structural validation
//! that apply to any COSE message type (Sign1, Encrypt, MAC, etc.).
//!
//! For Sign1-specific errors, see `cose_sign1_primitives::error`.

use std::fmt;

/// Errors that can occur during generic COSE operations.
///
/// This covers CBOR-level and structural errors that are not specific
/// to any particular COSE message type.
#[derive(Debug)]
pub enum CoseError {
    /// CBOR encoding/decoding error.
    CborError(String),
    /// The message or header structure is invalid.
    InvalidMessage(String),
}

impl fmt::Display for CoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CborError(msg) => write!(f, "CBOR error: {}", msg),
            Self::InvalidMessage(msg) => write!(f, "invalid message: {}", msg),
        }
    }
}

impl std::error::Error for CoseError {}
