// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared interfaces and datatypes for the COSE_Sign1 Rust crates.
//!
//! This crate exists to prevent circular dependencies across:
//! - high-level facade (`cosesign1`)
//! - plugins (`cosesign1-x509`, `cosesign1-mst`, and other future providers/validators)
//!
//! It is intentionally kept small and stable. It includes link-time plugin registries
//! for signing key providers and message validators.

pub mod header_map;
pub mod parsed_cose_sign1;
pub mod validation_result;
pub mod options;
pub mod key_provider;
pub mod message_validator;

pub use header_map::{CoseHeaderMap, HeaderKey, HeaderValue};
pub use parsed_cose_sign1::{ParsedCoseSign1, SigStructureView, COSE_SIGN1_TAG, SIG_STRUCTURE_CONTEXT_SIGNATURE1};
pub use validation_result::{ValidationFailure, ValidationResult};

pub use options::OpaqueOptions;

pub use key_provider::{
    provider_name, resolve_signing_key, providers_ordered, PublicKeyProviderError, ResolvePublicKeyError,
    ResolvedSigningKey, SigningKeyProvider, SigningKeyProviderId, SigningKeyProviderRegistration,
};

pub use message_validator::{
    run_validator_by_id, validator_name, validators_ordered, MessageValidationContext, MessageValidator,
    MessageValidatorError, MessageValidatorId, MessageValidatorRegistration, RunValidatorError,
};
