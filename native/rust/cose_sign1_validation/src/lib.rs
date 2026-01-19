// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
mod trust_plan_builder;
mod trust_packs;
mod validator;
