// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! X.509 certificate support pack for COSE_Sign1 signing and validation.
//!
//! This crate provides both signing and validation capabilities for
//! X.509 certificate-based COSE signatures.
//!
//! ## Modules
//!
//! - [`signing`] — Certificate signing service, header contributors, key providers, SCITT
//! - [`validation`] — Signing key resolver, trust facts, fluent extensions, trust pack
//! - Root modules — Shared types (chain builder, thumbprint, extensions, error)

// Shared types (used by both signing and validation)
pub mod chain_builder;
pub mod chain_sort_order;
pub mod cose_key_factory;
pub mod error;
pub mod extensions;
pub mod thumbprint;

// Signing support
pub mod signing;

// Validation support
pub mod validation;

// Re-export shared types at crate root for convenience
pub use chain_builder::*;
pub use chain_sort_order::*;
pub use cose_key_factory::*;
pub use error::*;
pub use extensions::*;
pub use thumbprint::*;

// =====================================================================
// Trust-fact registry — Phase 3 (np-fact-registry, R1).
//
// Enumerates the concrete trust facts this pack contributes. Expansion
// produces `pub fn __cose_sign1_trust_facts() -> Vec<TrustFactDescriptor>`
// which the workspace-level `HandRolledFactRegistry::from_packs(&[...])`
// collects by name. IDs MUST stay byte-identical to Phase 1's
// `StaticFactRegistry` baseline; the `tests/registered_facts.rs` smoke
// check enforces it.
// =====================================================================

cose_sign1_validation_primitives::register_facts! {
    validation::facts::CertificateSigningKeyTrustFact,
    validation::facts::X509ChainElementIdentityFact,
    validation::facts::X509ChainTrustedFact,
    validation::facts::X509SigningCertificateBasicConstraintsFact,
    validation::facts::X509SigningCertificateEkuFact,
    validation::facts::X509SigningCertificateIdentityAllowedFact,
    validation::facts::X509SigningCertificateIdentityFact,
    validation::facts::X509SigningCertificateKeyUsageFact,
    validation::facts::X509X5ChainCertificateIdentityFact,
}
