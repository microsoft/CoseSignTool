// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![deny(missing_docs)]

//! `cose_sign1_trustfrontends_json` — Phase 2 (np-frontend-json) of the native Rust
//! trust-policy port.
//!
//! Canonical reference frontend (`cose-tp-json/v1`). Parses, JSON-Schema-validates, and
//! translates user-authored `.coseTrustPolicy.json` documents into a
//! `cose_sign1_trust_policy_spec::TrustPolicySpec`. Mirrors the .NET
//! `CoseSign1.Validation.TrustFrontends.Json` deliverable.
//!
//! # Pipeline
//!
//! 1. **JSON parse** via `serde_json::from_str` (TPX001 on parse failure with line/col).
//! 2. **Schema-validate** against the embedded `cose-tp/v1` schema (Draft 2020-12) —
//!    every leaf failure surfaces as `TPX100` with a JSON-pointer instance location.
//! 3. **Walk** the validated tree into a `TrustPolicySpec`, evaluating the closed scope
//!    grammar (`message` / `primary_signing_key` / `any_counter_signature`) and the
//!    closed expression grammar (`fact` / `all_of` / `any_of` / `not` / `implies` /
//!    `allow_all` / `deny_all`).
//! 4. **Capability gating** (D4): when `ctx.available_facts` is supplied and
//!    `ctx.allow_unknown_facts == false`, every `RequireFact.fact_id` is checked against
//!    the host's advertised id set; misses surface as `TPX200`. When per-fact predicate
//!    schemas are supplied, the predicate is validated against them; misses surface as
//!    `TPX201`.
//! 5. **Bind** is a separate post-translate call ([`cose_sign1_trust_policy_spec::bind`])
//!    so the same translation can be reused for multiple parameter sets.
//!
//! # Sandboxing (§6.5.4 #6, #7)
//!
//! - Pure data walks. No `eval`, no plugin loading, no I/O during translation.
//! - Bounded recursion: max depth 64 (configurable via [`CoseTpJsonOptions::max_depth`]).
//!   Documents that nest beyond the cap surface `TPX300` and translation halts.
//! - Reads only the user document — never re-issues network I/O.
//!
//! # Cross-port note (D7)
//!
//! The embedded schema bytes are **byte-identical** (after platform line-ending
//! normalization to LF) to the .NET schema at `V2/schemas/cose-tp/v1.json`. The
//! `cross_port_schema` integration test asserts this; drifting either side is a CI gate
//! failure.

// pub mod cache;  // landed in next commit
pub mod codes;
pub mod frontend;
pub mod options;
pub mod schema;
mod walk;

// pub use cache::{TranslatorCache, TranslatorCacheError};
pub use frontend::{CoseTpJsonFrontend, FRONTEND_ID};
pub use options::CoseTpJsonOptions;
pub use schema::{embedded_schema_bytes, EMBEDDED_SCHEMA_RESOURCE_NAME};

// Re-export the abstraction layer for ergonomics: callers depend on this crate alone for
// the JSON frontend story and pick up the trait + supporting types transitively.
pub use cose_sign1_trust_policy_spec::{
    CoseTrustPolicyFrontend, FactCapabilities, TrustPolicySeverity,
    TrustPolicyTranslationContext, TrustPolicyTranslationDiagnostic,
    TrustPolicyTranslationResult,
};
