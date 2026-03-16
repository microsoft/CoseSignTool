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

