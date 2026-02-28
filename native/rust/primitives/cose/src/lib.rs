// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! # COSE Primitives
//!
//! RFC 9052 COSE types and constants shared across all COSE message types.
//!
//! This crate provides the generic COSE building blocks — header types,
//! IANA algorithm constants, the CBOR provider singleton, and base error
//! types — that are not specific to any particular COSE structure
//! (Sign1, Encrypt0, MAC0, etc.).
//!
//! ## What belongs here vs. `cose_sign1_primitives`
//!
//! | This crate (`cose_primitives`) | `cose_sign1_primitives` |
//! |--------------------------------|-------------------------|
//! | `CoseHeaderMap`, `ProtectedHeader` | `CoseSign1Message`, `CoseSign1Builder` |
//! | `CoseHeaderLabel`, `CoseHeaderValue` | `Sig_structure1` construction |
//! | IANA algorithm constants (`ES256`, etc.) | `COSE_SIGN1_TAG` (tag 18) |
//! | `CoseError` (CBOR/structural) | `CoseSign1Error`, `CoseKeyError` |
//! | CBOR provider singleton | Payload streaming types |
//!
//! ## Architecture
//!
//! This crate is generic over the `CborProvider` trait from `cbor_primitives`
//! and re-exports algorithm constants from `crypto_primitives`. The concrete
//! CBOR provider is selected at compile time via the `cbor-everparse` feature.

pub mod algorithms;
pub mod error;
pub mod headers;
pub mod provider;

// Re-exports for convenience
pub use algorithms::{EDDSA, ES256, ES384, ES512, PS256, PS384, PS512, RS256, RS384, RS512};
#[cfg(feature = "pqc")]
pub use algorithms::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
pub use error::CoseError;
pub use headers::{ContentType, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ProtectedHeader};
