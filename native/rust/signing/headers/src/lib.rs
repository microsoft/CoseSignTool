// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! # COSE Sign1 Headers
//!
//! Provides CWT (CBOR Web Token) Claims support and header contributors
//! for COSE_Sign1 messages.
//!
//! This crate ports V2's `CoseSign1.Headers` package to Rust, providing
//! SCITT-compliant header management.

pub mod error;
pub mod cwt_claims;
pub mod cwt_claims_labels;
pub mod cwt_claims_contributor;

pub use error::HeaderError;
pub use cwt_claims::{CwtClaims, CwtClaimValue};
pub use cwt_claims_labels::CWTClaimsHeaderLabels;
pub use cwt_claims_contributor::CwtClaimsHeaderContributor;
