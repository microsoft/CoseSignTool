// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Core signing abstractions for COSE_Sign1 messages.
//!
//! This crate provides traits and types for building signing services and managing
//! signing operations with COSE_Sign1 messages. It maps V2 C# signing abstractions
//! to Rust.

pub mod context;
pub mod error;
pub mod extensions;
pub mod metadata;
pub mod options;
pub mod signer;
pub mod traits;
pub mod transparency;

pub use context::*;
pub use error::*;
pub use extensions::*;
pub use metadata::*;
pub use options::*;
pub use signer::*;
pub use traits::*;
pub use transparency::{
    add_proof_with_receipt_merge, extract_receipts, merge_receipts, TransparencyError,
    TransparencyProvider, TransparencyValidationResult, RECEIPTS_HEADER_LABEL,
};
