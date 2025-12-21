// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MST verification stubs.
//!
//! The native project contains MST verification functionality. The Rust port
//! maintains API shape parity but does not yet implement MST verification.
//!
//! These functions intentionally return a structured `ValidationResult` rather
//! than panicking so callers can handle "not implemented" gracefully.

use cosesign1_validation::ValidationResult;

#[derive(Debug, Clone, Default)]
pub struct VerificationOptions {
    /// Whether network access is permitted to fetch keys (JWKS) dynamically.
    pub allow_network_key_fetch: bool,
    /// Optional path to a JWKS file, for offline verification.
    pub jwks_path: String,
}

/// Verify a transparent statement COSE_Sign1.
///
/// Currently unimplemented in the Rust port.
pub fn verify_transparent_statement(
    validator_name: &str,
    _transparent_statement_cose_sign1: &[u8],
    _options: &VerificationOptions,
) -> ValidationResult {
    // Stub implementation: return a consistent, machine-readable error code.
    ValidationResult::failure_message(
        validator_name,
        "MST verification not implemented in Rust yet",
        Some("NOT_IMPLEMENTED".to_string()),
    )
}

/// Verify a transparent statement receipt.
///
/// Currently unimplemented in the Rust port.
pub fn verify_transparent_statement_receipt(
    validator_name: &str,
    _receipt_cose_sign1: &[u8],
    _input_signed_claims: &[u8],
) -> ValidationResult {
    // Stub implementation: return a consistent, machine-readable error code.
    ValidationResult::failure_message(
        validator_name,
        "MST receipt verification not implemented in Rust yet",
        Some("NOT_IMPLEMENTED".to_string()),
    )
}
