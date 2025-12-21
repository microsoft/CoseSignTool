// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod cose_sign1_verifier;
pub mod validation_result;

pub use cose_sign1_verifier::{verify_cose_sign1, verify_parsed_cose_sign1, CoseAlgorithm, VerifyOptions};
pub use validation_result::{ValidationFailure, ValidationResult};
