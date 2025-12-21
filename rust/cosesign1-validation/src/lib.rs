// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE_Sign1 signature verification.
//!
//! This crate is responsible for cryptographic verification once a COSE_Sign1
//! is parsed and the Sig_structure bytes are computed.
//!
//! Supported algorithms (as of this port):
//! - ES256 / ES384 / ES512 (ECDSA)
//! - RS256 (RSA PKCS#1 v1.5)
//! - PS256 (RSA-PSS)
//! - ML-DSA-44 / 65 / 87 (provisional COSE alg ids used by this repo)
//!
//! The primary entry point is `verify_cose_sign1`.

pub mod cose_sign1_verifier;
pub mod validation_result;

// Re-export the public API from the internal modules.
pub use cose_sign1_verifier::{verify_cose_sign1, verify_parsed_cose_sign1, CoseAlgorithm, VerifyOptions};
pub use validation_result::{ValidationFailure, ValidationResult};
