// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Microsoft Transparent Statement (MST) parity crate (work-in-progress).
//!
//! This crate exists to mirror the native MST verification APIs:
//! - `VerifyTransparentStatement`
//! - `VerifyTransparentStatementOnline`
//! - `VerifyTransparentStatementReceipt`
//!
//! The Rust port currently exposes the same surface area but returns
//! `NOT_IMPLEMENTED` until the full verifier is implemented.

pub mod mst_verifier;

// Re-export the public API from the internal module.
pub use mst_verifier::{verify_transparent_statement, verify_transparent_statement_receipt, VerificationOptions};
