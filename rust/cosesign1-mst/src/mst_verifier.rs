// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_validation::ValidationResult;

#[derive(Debug, Clone, Default)]
pub struct VerificationOptions {
    pub allow_network_key_fetch: bool,
    pub jwks_path: String,
}

pub fn verify_transparent_statement(
    validator_name: &str,
    _transparent_statement_cose_sign1: &[u8],
    _options: &VerificationOptions,
) -> ValidationResult {
    ValidationResult::failure_message(
        validator_name,
        "MST verification not implemented in Rust yet",
        Some("NOT_IMPLEMENTED".to_string()),
    )
}

pub fn verify_transparent_statement_receipt(
    validator_name: &str,
    _receipt_cose_sign1: &[u8],
    _input_signed_claims: &[u8],
) -> ValidationResult {
    ValidationResult::failure_message(
        validator_name,
        "MST receipt verification not implemented in Rust yet",
        Some("NOT_IMPLEMENTED".to_string()),
    )
}
