// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509-backed COSE_Sign1 helpers.
//!
//! This crate provides:
//! - A signing-key provider for extracting the COSE signing key from `x5c` (label 33).
//! - A message validator for validating the `x5c` chain against a trust model.

pub mod x5c_verifier;

mod x5c_public_key_provider;
mod x5c_chain_message_validator;
mod x5c_header;

/// Provider name for COSE `x5c`-based signing key resolution.
pub const X5C_PROVIDER_NAME: &str = "x5c";

/// Stable strong ID for the `x5c` signing-key provider.
pub const X5C_PROVIDER_ID: cosesign1_abstractions::SigningKeyProviderId =
	cosesign1_abstractions::SigningKeyProviderId(uuid::uuid!("b5e23a46-0f88-4b29-9b05-8a2f2c3c4b8a"));

/// Provider name for X.509 chain validation message validator.
pub const X5C_CHAIN_VALIDATOR_NAME: &str = "x5c_chain";

/// Stable strong ID for the X.509 chain validation message validator.
pub const X5C_CHAIN_VALIDATOR_ID: cosesign1_abstractions::MessageValidatorId =
	cosesign1_abstractions::MessageValidatorId(uuid::uuid!("08a7a8fb-0d1e-458b-8a23-2bf0e8f10d2b"));

/// Helper for configuring X.509 chain validation as a message validator.
pub fn x5c_chain_validation_options(
	chain: X509ChainVerifyOptions,
) -> (cosesign1_abstractions::MessageValidatorId, cosesign1_abstractions::OpaqueOptions) {
	(X5C_CHAIN_VALIDATOR_ID, cosesign1_abstractions::OpaqueOptions::new(chain))
}

// Re-export the public API from the internal module.
pub use x5c_verifier::{
	validate_x5c_chain, X509ChainVerifyOptions, X509RevocationMode, X509TrustMode,
};
