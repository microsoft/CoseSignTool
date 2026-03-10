// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Rust port of Azure.CodeSigning.Sdk — REST client for Azure Trusted Signing.
//!
//! Reverse-engineered from Azure.CodeSigning.Sdk NuGet v0.1.164.
//!
//! ## REST API
//!
//! - Base: `{endpoint}/codesigningaccounts/{account}/certificateprofiles/{profile}`
//! - Auth: Bearer token, scope `{endpoint}/.default`
//! - Sign: POST `.../sign` → 202 LRO → poll → SignStatus
//! - Cert chain: GET `.../sign/certchain` → PKCS#7 bytes
//! - Root cert: GET `.../sign/rootcert` → DER bytes  
//! - EKU: GET `.../sign/eku` → JSON string array

pub mod error;
pub mod models;
pub mod client;

pub use client::{CertificateProfileClient, CertificateProfileClientCreateOptions, SignOptions};
pub use error::AtsClientError;
pub use models::*;