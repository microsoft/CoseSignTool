// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509-backed COSE_Sign1 verification helpers.
//!
//! This crate adds support for verifying COSE_Sign1 where the signing certificate
//! is provided via the `x5c` COSE header (label 33).
//!
//! Current parity status:
//! - Extracts the leaf certificate and uses its public key for signature verification.
//! - Full chain building and trust evaluation are not implemented yet; callers can
//!   only opt into a limited allow-untrusted diagnostic mode.

pub mod x5c_verifier;

// Re-export the public API from the internal module.
pub use x5c_verifier::{verify_cose_sign1_with_x5c, verify_parsed_cose_sign1_with_x5c, X509ChainVerifyOptions, X509RevocationMode, X509TrustMode};
