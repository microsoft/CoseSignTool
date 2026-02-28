// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Microsoft Supply Chain Transparency (MST) support pack for COSE_Sign1.
//!
//! This crate provides validation support for transparent signing receipts
//! emitted by Microsoft's transparent signing infrastructure.
//!
//! ## Modules
//!
//! - [`validation`] — Trust facts, fluent extensions, trust pack, receipt verification
//! - [`signing`] — REST client for MST transparency service

// HTTP client
pub mod http_client;

// Signing support
pub mod signing;

// Validation support
pub mod validation;
