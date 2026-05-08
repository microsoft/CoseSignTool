// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`RegoDocument`] — opaque parsed form of a `.coseTrustPolicy.rego`
//! source document.
//!
//! Consumers call [`RegoDocument::parse`] (or
//! [`crate::CoseTpRegoFrontend::translate_text`] for the combined flow) to
//! produce one. The internal AST + lowered JSON tree are private; the
//! struct presents only enough surface for cross-crate ergonomics.

use crate::ast::RegoValueNode;
use cose_sign1_trust_policy_spec::TrustPolicyTranslationDiagnostic;
use serde_json::Value;

/// Parsed form of a `.coseTrustPolicy.rego` document.
///
/// The parsing strategy is encapsulated. Per the .NET Phase 5a precedent,
/// the canonical implementation is a hand-rolled recursive-descent parser
/// over a constrained Rego subset (Option B); regorus partial evaluation
/// (Option A from the original Rust port plan R2) was evaluated and
/// rejected — see crate-level docs in [`crate`] for the full rationale.
pub struct RegoDocument {
    pub(crate) ast: RegoValueNode,
    pub(crate) lowered: Value,
    pub(crate) document_source: Option<String>,
}

impl RegoDocument {
    /// Parse a Rego source string into a [`RegoDocument`].
    ///
    /// Returns `None` and pushes one or more `Error`-severity diagnostics
    /// onto `diagnostics` when the document violates the cose-tp-rego/v1
    /// constrained-subset grammar or trips a defense-in-depth guard.
    /// Returns `Some(doc)` with no `Error`-severity diagnostics on success.
    pub fn parse(
        text: &str,
        document_source: Option<&str>,
        diagnostics: &mut Vec<TrustPolicyTranslationDiagnostic>,
    ) -> Option<Self> {
        crate::frontend::parse_into(text, document_source, diagnostics)
            .map(|(ast, lowered)| Self {
                ast,
                lowered,
                document_source: document_source.map(|s| s.to_owned()),
            })
    }

    /// Path / URI that identifies this document for diagnostics.
    pub fn document_source(&self) -> Option<&str> {
        self.document_source.as_deref()
    }

    /// Lowered `cose-tp-json/v1` JSON tree.
    ///
    /// Operator-facing accessor for debugging Rego→JSON translation
    /// mismatches: pretty-printing this value reproduces what the JSON
    /// frontend's schema validator + walker observes. Useful when a
    /// diagnostic surfaces a `TPX100` schema violation and the operator
    /// needs to see exactly what shape the parser produced.
    pub fn lowered(&self) -> &serde_json::Value {
        &self.lowered
    }
}

impl std::fmt::Debug for RegoDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegoDocument")
            .field("document_source", &self.document_source)
            .field("ast", &self.ast)
            .finish()
    }
}
