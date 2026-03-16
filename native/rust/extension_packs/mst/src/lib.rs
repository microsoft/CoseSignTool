// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]


//! Microsoft Supply Chain Transparency (MST) support pack for COSE_Sign1.
//!
//! This crate provides validation support for transparent signing receipts
//! emitted by Microsoft's transparent signing infrastructure, and a
//! transparency provider that wraps the `code_transparency_client` crate.
//!
//! ## Modules
//!
//! - [`validation`] — Trust facts, fluent extensions, trust pack, receipt verification
//! - [`signing`] — Transparency provider integrating with the Azure SDK client

// Re-export the Azure SDK client crate
pub use code_transparency_client;

// Signing support (transparency provider wrapping the client)
pub mod signing;

// Validation support
pub mod validation;
