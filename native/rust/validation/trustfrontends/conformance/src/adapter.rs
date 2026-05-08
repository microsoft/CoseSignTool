// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`ConformanceAdapter`] — the per-frontend bridge that lets the harness
//! load fixtures, build a fresh frontend instance, and parse a fixture into
//! the frontend's document type.
//!
//! Each shipping frontend implements this trait once in its own test crate
//! (or in this crate, when the conformance crate also owns the frontend's
//! reference adapter — see [`crate::JsonConformanceAdapter`]).

use cose_sign1_trust_policy_spec::CoseTrustPolicyFrontend;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Per-frontend bridge consumed by the conformance harness.
///
/// `TDoc` is the parsed-document type the frontend's
/// [`CoseTrustPolicyFrontend`] consumes — `serde_json::Value` for JSON,
/// future Rego frontends supply their own representation.
///
/// Adapters are stateless / cheap to construct: the harness creates a fresh
/// [`CoseTrustPolicyFrontend`] for every property test so leftover translator
/// caches cannot mask non-determinism.
pub trait ConformanceAdapter<TDoc> {
    /// Build a fresh frontend instance.
    ///
    /// MUST NOT reuse process-wide caches across calls — the determinism
    /// property checks for caching that "smooths over" non-deterministic
    /// translation, so each call returns a new instance with no shared
    /// mutable state.
    fn create_frontend(&self) -> Box<dyn CoseTrustPolicyFrontend<TDoc>>;

    /// Parse the file at `fixture_path` into the frontend's document type.
    ///
    /// Implementations panic on I/O errors — fixtures are committed to the
    /// crate, so a missing fixture is a programming error, not a runtime
    /// failure mode.
    fn load_document(&self, fixture_path: &Path) -> TDoc;

    /// File extension shared by every fixture this frontend understands
    /// (e.g. `coseTrustPolicy.json` for JSON, `coseTrustPolicy.rego` for
    /// future Rego). The leading dot is omitted — the harness composes
    /// `<stem>.<extension>`.
    fn fixture_extension(&self) -> &'static str;

    /// Absolute path of the conformance fixtures root for this frontend.
    ///
    /// All adapters share the same root directory (`fixtures/` under the
    /// conformance crate); the per-property sub-directories (`per_fact/`,
    /// `cross/`, …) are looked up by [`crate::fixtures`] helpers.
    fn fixture_root(&self) -> PathBuf;

    /// The set of fact ids this frontend's host advertises in its
    /// [`cose_sign1_trust_policy_spec::FactCapabilities`].
    ///
    /// The §6.5.10 #2 (attribute fidelity) property iterates this set and
    /// asserts every id has a per-fact fixture. The harness intentionally
    /// pulls the list through the adapter (rather than reading the registry
    /// directly) so frontends with a smaller surface — for example a
    /// custom-built host that registers only a subset of the canonical fact
    /// list — can still run a tight conformance pass.
    fn registered_fact_ids(&self) -> BTreeSet<String>;
}
