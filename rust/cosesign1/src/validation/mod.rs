// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE_Sign1 signature verification.

pub mod cose_sign1_verifier;

pub use cose_sign1_verifier::{
    verify_cose_sign1, verify_parsed_cose_sign1, verify_sig_structure, CoseAlgorithm, VerifyOptions,
};
pub use cosesign1_abstractions::{ValidationFailure, ValidationResult};
