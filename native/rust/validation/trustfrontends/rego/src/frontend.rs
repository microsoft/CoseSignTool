// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`CoseTpRegoFrontend`] — the constrained-Rego-subset frontend
//! (`cose-tp-rego/v1`).
//!
//! Pipeline:
//!
//! 1. Defense-in-depth: bound input size to `MAX_INPUT_BYTES` so a hostile
//!    multi-megabyte document does not pressure memory during tokenisation.
//!    Trips emit `TPX306`.
//! 2. Tokenise via [`crate::tokenizer::Tokenizer`]. Lexical errors surface
//!    as `TPX001` with line / column anchors.
//! 3. Parse via [`crate::parser::Parser`]. Forbidden constructs surface
//!    as the per-cause sub-codes (`TPX301`, `TPX302`, `TPX303`, `TPX304`,
//!    `TPX305`); structural errors as `TPX001`/`TPX002`/`TPX003`/`TPX004`/
//!    `TPX005`.
//! 4. Lower to a [`serde_json::Value`] matching the `cose-tp-json/v1`
//!    schema via [`crate::lower::lower`]. The JSON frontend's schema
//!    validator + walker is then driven over the lowered tree, so
//!    byte-equality with the JSON frontend's canonical IR is a property of
//!    construction.
//!
//! Per §6.5.4 every implementation MUST satisfy:
//! determinism (parser is deterministic; JSON walker is deterministic),
//! totality (every input produces a result with diagnostics or a spec —
//! no panics escape), attribute fidelity (the JSON walker enforces the
//! registry; this frontend defers entirely), reject-what-you-can't-translate
//! (constrained subset; closed grammar), capability-aware (the
//! [`TrustPolicyTranslationContext::available_facts`] flows straight
//! through), no code execution (no Rego evaluation; no `opa eval`,
//! regorus, or shell-out), and bounded runtime (parser is `O(n)`; the
//! JSON walker is `O(spec-size)`).

use crate::codes::{TPX_001_MALFORMED_REGO, TPX_306_INPUT_TOO_LARGE};
use crate::document::RegoDocument;
use crate::strings::{FRONTEND_ID, MAX_INPUT_BYTES, MEDIA_TYPE_REGO};
use cose_sign1_trust_policy_spec::{
    CoseTrustPolicyFrontend, SourceLocation, TrustPolicySeverity,
    TrustPolicyTranslationContext, TrustPolicyTranslationDiagnostic,
    TrustPolicyTranslationResult,
};
use cose_sign1_trustfrontends_json::CoseTpJsonFrontend;

const SUPPORTED_MEDIA_TYPES: &[&str] = &[MEDIA_TYPE_REGO];

/// Constrained-Rego-subset frontend implementing the `cose-tp-rego/v1`
/// translation contract.
///
/// Cheap to clone — the underlying [`CoseTpJsonFrontend`] is a
/// thin-wrapper over an immutable options bundle and the lazily-compiled
/// embedded schema (shared across all instances).
#[derive(Clone, Debug, Default)]
pub struct CoseTpRegoFrontend {
    json_frontend: CoseTpJsonFrontend,
}

impl CoseTpRegoFrontend {
    /// Construct a frontend with default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a frontend that re-uses the supplied JSON frontend
    /// instance for the schema-validation + walker stage. Permits hosts to
    /// share a single configured JSON frontend (with custom translator
    /// caches, depth caps, etc.) across both translation paths.
    pub fn with_json_frontend(json_frontend: CoseTpJsonFrontend) -> Self {
        Self { json_frontend }
    }

    /// Translate raw Rego text. Combines parse + lower + schema-validate +
    /// walk in one call.
    pub fn translate_text(
        &self,
        text: &str,
        ctx: &TrustPolicyTranslationContext,
        document_source: Option<&str>,
    ) -> TrustPolicyTranslationResult {
        let mut diagnostics: Vec<TrustPolicyTranslationDiagnostic> = Vec::new();
        let document = match RegoDocument::parse(text, document_source, &mut diagnostics) {
            Some(d) => d,
            None => return TrustPolicyTranslationResult::failure(diagnostics),
        };
        self.translate_internal(document, ctx, document_source, diagnostics)
    }

    fn translate_internal(
        &self,
        document: RegoDocument,
        ctx: &TrustPolicyTranslationContext,
        document_source: Option<&str>,
        seed_diagnostics: Vec<TrustPolicyTranslationDiagnostic>,
    ) -> TrustPolicyTranslationResult {
        // The lowered tree is structurally identical to the JSON frontend's
        // expected shape. We hand it to the JSON frontend as a typed
        // `serde_json::Value` so the schema validator + walker run
        // directly on the tree we materialised — no `to_string` +
        // re-parse round-trip, and the `document_source` anchor still
        // flows through the JSON walker for diagnostics.
        let RegoDocument { lowered, document_source: doc_src, .. } = document;
        let source = document_source.or(doc_src.as_deref());
        let inner = self.json_frontend.translate_value_with_source(
            lowered,
            ctx,
            source,
        );

        if seed_diagnostics.is_empty() {
            return inner;
        }

        merge_seed_with_inner(seed_diagnostics, inner)
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn merge_seed_with_inner(
    seed_diagnostics: Vec<TrustPolicyTranslationDiagnostic>,
    inner: TrustPolicyTranslationResult,
) -> TrustPolicyTranslationResult {
    // Defensive: parse-success normally produces no diagnostics, so this
    // branch is only reached if a parser warning slipped past `parse_into`
    // without flipping `has_error`. The merge keeps totality even if such
    // a future path is added.
    let TrustPolicyTranslationResult { spec, diagnostics, .. } = inner;
    let mut merged: Vec<TrustPolicyTranslationDiagnostic> =
        Vec::with_capacity(seed_diagnostics.len() + diagnostics.len());
    merged.extend(seed_diagnostics);
    merged.extend(diagnostics);
    match spec {
        Some(s) => TrustPolicyTranslationResult::success(s, merged),
        None => TrustPolicyTranslationResult::failure(merged),
    }
}

impl CoseTrustPolicyFrontend<RegoDocument> for CoseTpRegoFrontend {
    fn frontend_id(&self) -> &'static str {
        FRONTEND_ID
    }

    fn supported_media_types(&self) -> &'static [&'static str] {
        SUPPORTED_MEDIA_TYPES
    }

    fn translate(
        &self,
        document: RegoDocument,
        ctx: &TrustPolicyTranslationContext,
    ) -> TrustPolicyTranslationResult {
        self.translate_internal(document, ctx, None, Vec::new())
    }
}

/// Crate-internal entry point shared by [`CoseTpRegoFrontend::translate_text`]
/// and [`RegoDocument::parse`]: tokenise + parse + lower into the JSON
/// representation, surfacing the input-size guard before tokenisation
/// allocates a token stream.
pub(crate) fn parse_into(
    text: &str,
    document_source: Option<&str>,
    diagnostics: &mut Vec<TrustPolicyTranslationDiagnostic>,
) -> Option<(crate::ast::RegoValueNode, serde_json::Value)> {
    if text.len() > MAX_INPUT_BYTES {
        diagnostics.push(
            TrustPolicyTranslationDiagnostic::new(
                TrustPolicySeverity::Error,
                TPX_306_INPUT_TOO_LARGE,
                format!("Document size {} bytes exceeds the cose-tp-rego/v1 maximum of {} bytes; reject as a defense-in-depth measure against memory-exhaustion DoS. Real-world cose-tp/v1 policies are <1 KB.", text.len(), MAX_INPUT_BYTES),
                Some(SourceLocation::at(1, 1)),
                None,
            ),
        );
        let _ = document_source; // available for future doc-source pinning
        return None;
    }

    let tokenizer = crate::tokenizer::Tokenizer::new(text);
    let (tokens, lex_errors) = tokenizer.tokenize();
    for le in lex_errors {
        let prefixed = match document_source {
            Some(src) if !src.is_empty() => format!("{}:{}:{}: {}", src, le.line, le.column, le.message),
            _ => le.message,
        };
        diagnostics.push(TrustPolicyTranslationDiagnostic::new(
            TrustPolicySeverity::Error,
            TPX_001_MALFORMED_REGO,
            prefixed,
            Some(SourceLocation::at(le.line, le.column)),
            None,
        ));
    }

    if has_error(diagnostics) {
        return None;
    }

    let mut parser = crate::parser::Parser::new(tokens, document_source);
    let ast = parser.parse();
    diagnostics.extend(parser.take_diagnostics());

    let ast = ast?;
    if has_error(diagnostics) {
        return None;
    }

    let lowered = crate::lower::lower(&ast);
    Some((ast, lowered))
}

fn has_error(diagnostics: &[TrustPolicyTranslationDiagnostic]) -> bool {
    diagnostics
        .iter()
        .any(|d| d.severity == TrustPolicySeverity::Error)
}
