// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Transparent signing (MST) trust pack for COSE_Sign1 validation.
//!
//! This crate adds validation support for transparent signing receipts/claims
//! emitted by Microsoft’s transparent signing infrastructure.
//!
//! The pack wiring lives in [`pack`]; receipt-specific verification helpers and
//! types are in [`receipt_verify`].

pub mod facts;
pub mod fluent_ext;
pub mod pack;
pub mod receipt_verify;
