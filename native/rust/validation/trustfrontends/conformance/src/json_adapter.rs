// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`JsonConformanceAdapter`] — adapter that wires the canonical
//! `cose-tp-json/v1` frontend into the conformance harness.
//!
//! Because the conformance crate already depends on
//! `cose_sign1_trustfrontends_json` (it's the first conforming frontend),
//! the adapter ships in this crate so any consumer can run the full 8-property
//! suite against the JSON frontend with one line:
//!
//! ```ignore
//! cose_sign1_trustfrontends_conformance::run_conformance_all(
//!     &cose_sign1_trustfrontends_conformance::JsonConformanceAdapter::default(),
//! );
//! ```
//!
//! Future frontends (Phase 5a Rego) ship a sibling adapter inside their own
//! crate that points at the same `fixture_root()` (the conformance crate's
//! `fixtures/` directory) but advertises a different
//! [`crate::ConformanceAdapter::fixture_extension`].

use crate::adapter::ConformanceAdapter;
use cose_sign1_trust_policy_spec::CoseTrustPolicyFrontend;
use cose_sign1_trustfrontends_json::CoseTpJsonFrontend;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Conformance adapter for the canonical `cose-tp-json/v1` frontend.
///
/// Constructed with [`JsonConformanceAdapter::default`] in the common case;
/// [`JsonConformanceAdapter::with_fact_ids`] lets a host run the suite against
/// a smaller fact set when its registry advertises only a subset.
#[derive(Debug, Clone)]
pub struct JsonConformanceAdapter {
    fact_ids: BTreeSet<String>,
}

impl JsonConformanceAdapter {
    /// Construct an adapter with the caller-supplied fact-id set.
    pub fn with_fact_ids(fact_ids: BTreeSet<String>) -> Self {
        Self { fact_ids }
    }

    /// The canonical 16-fact baseline mirrored from the static registry.
    ///
    /// This is the same list `StaticFactRegistry::default_mappings()` carries
    /// in Phase 1 (deprecated but retained as the conformance baseline). The
    /// list is hand-curated here so the conformance crate is independent of
    /// every pack crate — adding a pack crate dependency just to enumerate
    /// fact ids would invert the dependency direction (packs depend on the
    /// conformance crate's contract, not the other way around).
    pub fn canonical_fact_ids() -> BTreeSet<String> {
        CANONICAL_FACT_IDS.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Crate-relative path to the conformance fixture root.
    ///
    /// Resolved from `CARGO_MANIFEST_DIR` so the path works regardless of the
    /// caller's current working directory.
    pub fn default_fixture_root() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir).join("fixtures")
    }
}

impl Default for JsonConformanceAdapter {
    fn default() -> Self {
        Self::with_fact_ids(Self::canonical_fact_ids())
    }
}

impl ConformanceAdapter<Value> for JsonConformanceAdapter {
    fn create_frontend(&self) -> Box<dyn CoseTrustPolicyFrontend<Value>> {
        Box::new(CoseTpJsonFrontend::new())
    }

    fn load_document(&self, fixture_path: &Path) -> Value {
        let bytes = std::fs::read(fixture_path).unwrap_or_else(|err| {
            panic!(
                "JsonConformanceAdapter: cannot read fixture {}: {err}",
                fixture_path.display(),
            )
        });
        serde_json::from_slice(&bytes).unwrap_or_else(|err| {
            panic!(
                "JsonConformanceAdapter: fixture {} is not valid JSON: {err}",
                fixture_path.display(),
            )
        })
    }

    fn fixture_extension(&self) -> &'static str {
        "coseTrustPolicy.json"
    }

    fn fixture_root(&self) -> PathBuf {
        Self::default_fixture_root()
    }

    fn registered_fact_ids(&self) -> BTreeSet<String> {
        self.fact_ids.clone()
    }
}

/// 16-fact canonical baseline — matches `StaticFactRegistry::default_mappings()`.
const CANONICAL_FACT_IDS: &[&str] = &[
    // Certificates pack.
    "x509-chain-trusted/v1",
    "x509-cert-identity/v1",
    "x509-cert-eku/v1",
    "x509-cert-key-usage/v1",
    "x509-cert-basic-constraints/v1",
    "x509-cert-identity-allowed/v1",
    "x509-x5chain-cert-identity/v1",
    "x509-chain-element-identity/v1",
    "certificate-signing-key-trust/v1",
    // MST pack.
    "mst-receipt-present/v1",
    "mst-receipt-trusted/v1",
    "mst-receipt-issuer-host/v1",
    // Message-level facts (validation/core).
    "content-type/v1",
    "detached-payload-present/v1",
    "counter-signature-subject/v1",
    "unknown-counter-signature-bytes/v1",
];
