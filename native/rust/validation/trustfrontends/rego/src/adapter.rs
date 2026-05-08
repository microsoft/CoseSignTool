// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`RegoConformanceAdapter`] — adapter that wires the constrained
//! `cose-tp-rego/v1` frontend into the Phase 4 conformance harness.
//!
//! The adapter ships in this crate so any consumer can run the full
//! 8-property conformance suite against the Rego frontend:
//!
//! ```ignore
//! cose_sign1_trustfrontends_conformance::run_conformance_all(
//!     &cose_sign1_trustfrontends_rego::RegoConformanceAdapter::default(),
//! );
//! ```
//!
//! Cross-frontend equivalence (§6.5.10 #8) — the property that Rego and
//! JSON frontends produce byte-identical canonical IR for the same logical
//! policy — is exercised by pairing this adapter with
//! [`cose_sign1_trustfrontends_conformance::JsonConformanceAdapter`] in
//! [`cose_sign1_trustfrontends_conformance::run_conformance_8_cross_equivalence`]:
//!
//! ```ignore
//! run_conformance_8_cross_equivalence(
//!     &cose_sign1_trustfrontends_conformance::JsonConformanceAdapter::default(),
//!     &cose_sign1_trustfrontends_rego::RegoConformanceAdapter::default(),
//! );
//! ```
//!
//! The adapter shares the JSON adapter's `fixture_root` (the conformance
//! crate's `fixtures/` directory) but advertises `coseTrustPolicy.rego` as
//! its [`ConformanceAdapter::fixture_extension`], so a Rego sibling file
//! per JSON fixture is the contract for ship-eligibility.

use crate::CoseTpRegoFrontend;
use crate::RegoDocument;
use cose_sign1_trust_policy_spec::{CoseTrustPolicyFrontend, TrustPolicyTranslationDiagnostic};
use cose_sign1_trustfrontends_conformance::{ConformanceAdapter, JsonConformanceAdapter};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Conformance adapter for the constrained `cose-tp-rego/v1` frontend.
#[derive(Debug, Clone)]
pub struct RegoConformanceAdapter {
    fact_ids: BTreeSet<String>,
    fixture_root: PathBuf,
}

impl RegoConformanceAdapter {
    /// Construct an adapter with the caller-supplied fact-id set and the
    /// canonical `fixtures/` root.
    pub fn with_fact_ids(fact_ids: BTreeSet<String>) -> Self {
        Self {
            fact_ids,
            fixture_root: JsonConformanceAdapter::default_fixture_root(),
        }
    }

    /// Construct an adapter with explicit fact-id set + fixture root —
    /// used by integration tests that ship their own fixture trees.
    pub fn with_fixture_root(fact_ids: BTreeSet<String>, fixture_root: PathBuf) -> Self {
        Self { fact_ids, fixture_root }
    }
}

impl Default for RegoConformanceAdapter {
    fn default() -> Self {
        Self::with_fact_ids(JsonConformanceAdapter::canonical_fact_ids())
    }
}

impl ConformanceAdapter<RegoDocument> for RegoConformanceAdapter {
    fn create_frontend(&self) -> Box<dyn CoseTrustPolicyFrontend<RegoDocument>> {
        Box::new(CoseTpRegoFrontend::new())
    }

    fn load_document(&self, fixture_path: &Path) -> RegoDocument {
        let bytes = std::fs::read(fixture_path).unwrap_or_else(|err| {
            panic!(
                "RegoConformanceAdapter: cannot read fixture {}: {err}",
                fixture_path.display(),
            )
        });
        let text = String::from_utf8(bytes).unwrap_or_else(|err| {
            panic!(
                "RegoConformanceAdapter: fixture {} is not UTF-8: {err}",
                fixture_path.display(),
            )
        });
        let mut diagnostics: Vec<TrustPolicyTranslationDiagnostic> = Vec::new();
        let path_str = fixture_path.to_string_lossy().into_owned();
        let document = RegoDocument::parse(&text, Some(&path_str), &mut diagnostics);
        document.unwrap_or_else(|| {
            panic!(
                "RegoConformanceAdapter: fixture {} failed to parse as cose-tp-rego/v1: diagnostics={:?}",
                fixture_path.display(),
                diagnostics,
            )
        })
    }

    fn fixture_extension(&self) -> &'static str {
        "coseTrustPolicy.rego"
    }

    fn fixture_root(&self) -> PathBuf {
        self.fixture_root.clone()
    }

    fn registered_fact_ids(&self) -> BTreeSet<String> {
        self.fact_ids.clone()
    }
}
