// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Azure Trusted Signing extension pack for COSE_Sign1 signing and validation.
//!
//! This crate provides integration with Microsoft Azure Trusted Signing (ATS),
//! a cloud-based HSM-backed signing service with FIPS 140-2 Level 3 compliance.
//!
//! ## Modules
//!
//! - [`signing`] — ATS signing service, certificate source, DID:x509 helpers
//! - [`validation`] — ATS trust pack and fact types
//! - [`options`] — Configuration options
//! - [`error`] — Error types

pub mod error;
pub mod options;
pub mod signing;
pub mod validation;