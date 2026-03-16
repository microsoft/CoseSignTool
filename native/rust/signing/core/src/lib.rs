// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Core signing abstractions for COSE_Sign1 messages.
//!
//! This crate provides traits and types for building signing services and managing
//! signing operations with COSE_Sign1 messages. It maps V2 C# signing abstractions
//! to Rust.

pub mod traits;
pub mod context;
pub mod options;
pub mod metadata;
pub mod signer;
pub mod error;
pub mod extensions;
pub mod transparency;

pub use traits::*;
pub use context::*;
pub use options::*;
pub use metadata::*;
pub use signer::*;
pub use error::*;
pub use extensions::*;
pub use transparency::{
    TransparencyProvider, TransparencyValidationResult, TransparencyError,
    RECEIPTS_HEADER_LABEL, extract_receipts, merge_receipts, add_proof_with_receipt_merge,
};
