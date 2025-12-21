// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// MST parity crate (work-in-progress).
//
// Native APIs to mirror:
// - VerifyTransparentStatement
// - VerifyTransparentStatementOnline
// - VerifyTransparentStatementReceipt

pub mod mst_verifier;

pub use mst_verifier::{verify_transparent_statement, verify_transparent_statement_receipt, VerificationOptions};
