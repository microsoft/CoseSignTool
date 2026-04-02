// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! COSE_Sign1 validation entrypoint.
//!
//! This crate provides the primary validation API for COSE_Sign1 messages.
//! New integrations should start with the fluent surface in [`fluent`], which
//! wires together:
//! - COSE parsing
//! - Signature verification via trust packs
//! - Trust evaluation via the `cose_sign1_validation_primitives` engine
//!
//! For advanced/legacy scenarios, lower-level APIs exist under [`internal`], but
//! the fluent surface is the intended stable integration point.
//!
//! # Validation Pipeline
//!
//! ```text
//! COSE bytes ──► parse ──► Validator::validate()
//!                               │
//!                     ┌─────────┼──────────┐
//!                     ▼         ▼          ▼
//!               Resolution   Trust    Signature
//!               (key lookup) (plan)   (verify)
//!                     │         │          │
//!                     └─────────┼──────────┘
//!                               ▼
//!                     Post-Signature Policies
//!                               │
//!                               ▼
//!                    CoseSign1ValidationResult
//! ```
//!
//! # Zero-Copy Validation
//!
//! For optimal performance, prefer [`Validator::validate_arc`] or
//! [`Validator::validate_bytes`] which avoid cloning the parsed message.
//! The standard [`Validator::validate`] accepts `&CoseSign1Message` for
//! convenience but performs one `Arc::new(message.clone())`.

pub use cbor_primitives::{CborProvider, RawCbor};

/// Fluent-first API entrypoint.
///
/// New integrations should prefer importing from `cose_sign1_validation::fluent`.
pub mod fluent;

/// Legacy/advanced surface (intentionally hidden from docs).
#[doc(hidden)]
pub mod internal;

mod message_fact_producer;
mod message_facts;
mod trust_packs;
mod trust_plan_builder;
mod validator;

mod indirect_signature;
