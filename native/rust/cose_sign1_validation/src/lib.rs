// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE_Sign1 validation entrypoint.
//!
//! This crate provides the primary validation API for COSE_Sign1 messages.
//! New integrations should start with the fluent surface in [`fluent`], which
//! wires together:
//! - COSE parsing
//! - Signature verification via trust packs
//! - Trust evaluation via the `cose_sign1_validation_trust` engine
//!
//! For advanced/legacy scenarios, lower-level APIs exist under [`internal`], but
//! the fluent surface is the intended stable integration point.

/// Fluent-first API entrypoint.
///
/// New integrations should prefer importing from `cose_sign1_validation::fluent`.
pub mod fluent;

/// Legacy/advanced surface (intentionally hidden from docs).
#[doc(hidden)]
pub mod internal;

mod cose;

mod message_fact_producer;
mod message_facts;
mod trust_packs;
mod trust_plan_builder;
mod validator;
