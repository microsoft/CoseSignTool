// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Key Vault COSE signing and validation support pack.
//!
//! This crate provides Azure Key Vault integration for both signing and
//! validating COSE_Sign1 messages.
//!
//! ## Modules
//!
//! - [`common`] — Shared types (KeyVaultCryptoClient trait, algorithm mapper, errors)
//! - [`signing`] — AKV signing key, signing service, header contributors, certificate source
//! - [`validation`] — Trust facts, fluent extensions, trust pack for AKV kid validation

pub mod common;
pub mod signing;
pub mod validation;


