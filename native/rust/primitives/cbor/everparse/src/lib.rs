// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! # CBOR Primitives EverParse Implementation
//!
//! This crate provides a concrete implementation of the `cbor_primitives` traits
//! using EverParse's verified `cborrs` library as the underlying CBOR library.
//!
//! This implementation is suitable for security-critical applications where formal
//! verification is required. The underlying `cborrs` library has been formally
//! verified using EverParse.
//!
//! ## Limitations
//!
//! - **No floating-point support**: The EverParse encoder (`EverParseEncoder`) does
//!   not support encoding floating-point values, as the verified `cborrs` parser
//!   does not handle floats. Use `EverparseCborEncoder` if you need floating-point
//!   encoding (though it won't be verified by EverParse).
//!
//! ## Usage
//!
//! ```rust,ignore
//! use cbor_primitives::CborProvider;
//! use cbor_primitives_everparse::EverParseCborProvider;
//!
//! let provider = EverParseCborProvider::default();
//! let mut encoder = provider.encoder();
//! // Use the encoder...
//! ```

mod decoder;
mod encoder;

pub use decoder::EverparseCborDecoder;
pub use encoder::{EverParseEncoder, EverparseCborEncoder};

use cbor_primitives::{CborProvider, CborType};

/// Error type for EverParse CBOR operations.
#[derive(Debug, Clone)]
pub enum EverparseError {
    /// Unexpected CBOR type encountered.
    UnexpectedType {
        /// The expected CBOR type.
        expected: CborType,
        /// The actual CBOR type found.
        found: CborType,
    },
    /// Unexpected end of input.
    UnexpectedEof,
    /// Invalid UTF-8 in text string.
    InvalidUtf8,
    /// Integer overflow during encoding or decoding.
    Overflow,
    /// Invalid CBOR data.
    InvalidData(String),
    /// Encoding error.
    Encoding(String),
    /// Decoding error.
    Decoding(String),
    /// Verification failed.
    VerificationFailed(String),
    /// Feature not supported.
    NotSupported(String),
}

impl std::fmt::Display for EverparseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EverparseError::UnexpectedType { expected, found } => {
                write!(f, "unexpected CBOR type: expected {:?}, found {:?}", expected, found)
            }
            EverparseError::UnexpectedEof => write!(f, "unexpected end of CBOR data"),
            EverparseError::InvalidUtf8 => write!(f, "invalid UTF-8 in CBOR text string"),
            EverparseError::Overflow => write!(f, "integer overflow in CBOR encoding/decoding"),
            EverparseError::InvalidData(msg) => write!(f, "invalid CBOR data: {}", msg),
            EverparseError::Encoding(msg) => write!(f, "encoding error: {}", msg),
            EverparseError::Decoding(msg) => write!(f, "decoding error: {}", msg),
            EverparseError::VerificationFailed(msg) => write!(f, "verification failed: {}", msg),
            EverparseError::NotSupported(msg) => write!(f, "not supported: {}", msg),
        }
    }
}

impl std::error::Error for EverparseError {}

/// Type alias for the EverParse CBOR decoder.
pub type EverParseDecoder<'a> = EverparseCborDecoder<'a>;

/// Type alias for the EverParse error type.
pub type EverParseError = EverparseError;

/// EverParse CBOR provider implementing the [`CborProvider`] trait.
///
/// This provider creates encoders and decoders backed by EverParse's verified
/// `cborrs` library. The encoder produces deterministic CBOR encoding, and the
/// decoder uses EverParse's formally verified parser.
///
/// Note that the encoder does not support floating-point values, as the verified
/// `cborrs` parser does not handle floats.
#[derive(Clone, Default)]
pub struct EverParseCborProvider;

impl CborProvider for EverParseCborProvider {
    type Encoder = EverParseEncoder;
    type Decoder<'a> = EverParseDecoder<'a>;
    type Error = EverParseError;

    fn encoder(&self) -> Self::Encoder {
        EverParseEncoder::new()
    }

    fn encoder_with_capacity(&self, capacity: usize) -> Self::Encoder {
        EverParseEncoder::with_capacity(capacity)
    }

    fn decoder<'a>(&self, data: &'a [u8]) -> Self::Decoder<'a> {
        EverParseDecoder::new(data)
    }
}
