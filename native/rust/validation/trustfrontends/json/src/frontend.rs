// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`CoseTpJsonFrontend`] — the canonical reference frontend (`cose-tp-json/v1`).
//!
//! Pipeline (see crate-level docs for the full contract):
//!
//! 1. `serde_json::from_str` (TPX001 with line/col).
//! 2. `jsonschema` Draft 2020-12 validation against the embedded schema (TPX100/101).
//! 3. Walk via [`crate::walk::DocumentTranslator`] (TPX200/201/300/301).

use crate::codes::{
    TPX_001_PARSE_ERROR, TPX_100_SCHEMA_VIOLATION, TPX_101_FRONTEND_MISMATCH,
};
use crate::options::{CoseTpJsonOptions, MEDIA_TYPE_JSON, MEDIA_TYPE_JSONC};
use crate::schema::embedded_schema_bytes;
use crate::walk::DocumentTranslator;
use cose_sign1_trust_policy_spec::{
    CoseTrustPolicyFrontend, SourceLocation, TrustPolicySeverity,
    TrustPolicyTranslationContext, TrustPolicyTranslationDiagnostic,
    TrustPolicyTranslationResult,
};
use jsonschema::{draft202012, Validator};
use serde_json::Value;
use std::sync::OnceLock;

/// Stable frontend identifier — re-exported as [`crate::FRONTEND_ID`].
pub const FRONTEND_ID: &str = "cose-tp-json/v1";

const SUPPORTED_MEDIA_TYPES: &[&str] = &[MEDIA_TYPE_JSON, MEDIA_TYPE_JSONC];

/// Reference frontend implementation of the `cose-tp-json/v1` translation contract.
///
/// `CoseTpJsonFrontend` is cheap to clone — it carries only an [`CoseTpJsonOptions`]
/// value plus the lazily-compiled embedded schema (shared across all instances). Hosts
/// typically construct it once at startup.
#[derive(Clone, Debug)]
pub struct CoseTpJsonFrontend {
    options: CoseTpJsonOptions,
}

impl CoseTpJsonFrontend {
    /// Construct a frontend with default [`CoseTpJsonOptions`].
    pub fn new() -> Self {
        Self::with_options(CoseTpJsonOptions::default())
    }

    /// Construct a frontend with caller-supplied options.
    pub fn with_options(options: CoseTpJsonOptions) -> Self {
        Self { options }
    }

    /// The active configuration.
    pub fn options(&self) -> &CoseTpJsonOptions {
        &self.options
    }

    /// Translate raw document text. Combines parse + schema-validate + walk in one call.
    ///
    /// `document_source` is opaque metadata embedded in diagnostic source locations
    /// (e.g. `file:///etc/myapp/trust.coseTrustPolicy.json`). Reserved for future
    /// use — the current implementation surfaces JSON-pointer paths in the diagnostic
    /// `message` field and a synthetic `SourceLocation::at(0, 0)` for non-parse errors,
    /// matching the .NET reference.
    pub fn translate_text(
        &self,
        text: &str,
        ctx: &TrustPolicyTranslationContext,
        document_source: Option<&str>,
    ) -> TrustPolicyTranslationResult {
        let mut diagnostics: Vec<TrustPolicyTranslationDiagnostic> = Vec::new();

        let document = match parse_document(text) {
            Ok(value) => value,
            Err(diag) => {
                diagnostics.push(diag);
                return TrustPolicyTranslationResult::failure(diagnostics);
            }
        };

        self.translate_value(document, ctx, document_source, diagnostics)
    }

    fn translate_value(
        &self,
        document: Value,
        ctx: &TrustPolicyTranslationContext,
        document_source: Option<&str>,
        mut diagnostics: Vec<TrustPolicyTranslationDiagnostic>,
    ) -> TrustPolicyTranslationResult {
        if !validate_against_schema(&document, &mut diagnostics) {
            return TrustPolicyTranslationResult::failure(diagnostics);
        }

        let root_object = match document {
            Value::Object(map) => map,
            other => return non_object_root_failure(other, diagnostics),
        };

        let mut walker = DocumentTranslator {
            ctx,
            options: &self.options,
            document_source,
            diagnostics: &mut diagnostics,
        };
        let spec = walker.walk_root(root_object, FRONTEND_ID);

        if has_error(&diagnostics) {
            TrustPolicyTranslationResult::failure(diagnostics)
        } else {
            TrustPolicyTranslationResult::success(spec, diagnostics)
        }
    }
}

impl Default for CoseTpJsonFrontend {
    fn default() -> Self {
        Self::new()
    }
}

impl CoseTrustPolicyFrontend<Value> for CoseTpJsonFrontend {
    fn frontend_id(&self) -> &'static str {
        FRONTEND_ID
    }

    fn supported_media_types(&self) -> &'static [&'static str] {
        SUPPORTED_MEDIA_TYPES
    }

    fn translate(
        &self,
        document: Value,
        ctx: &TrustPolicyTranslationContext,
    ) -> TrustPolicyTranslationResult {
        self.translate_value(document, ctx, None, Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Stage 1 — JSON parse.
// ---------------------------------------------------------------------------

fn parse_document(text: &str) -> Result<Value, TrustPolicyTranslationDiagnostic> {
    serde_json::from_str::<Value>(text).map_err(|err| {
        TrustPolicyTranslationDiagnostic::new(
            TrustPolicySeverity::Error,
            TPX_001_PARSE_ERROR,
            format!("Malformed JSON document: {err}"),
            Some(SourceLocation::at(err.line() as u32, err.column() as u32)),
            None,
        )
    })
}

// ---------------------------------------------------------------------------
// Stage 2 — JSON-Schema validation.
// ---------------------------------------------------------------------------

fn compiled_schema() -> &'static Validator {
    static CELL: OnceLock<Validator> = OnceLock::new();
    CELL.get_or_init(|| {
        let schema_value: Value = serde_json::from_slice(embedded_schema_bytes())
            .expect("embedded cose-tp/v1 schema must be valid JSON");
        draft202012::new(&schema_value)
            .expect("embedded cose-tp/v1 schema must compile under Draft 2020-12")
    })
}

fn validate_against_schema(
    document: &Value,
    diagnostics: &mut Vec<TrustPolicyTranslationDiagnostic>,
) -> bool {
    let schema = compiled_schema();
    if schema.is_valid(document) {
        return true;
    }

    let mut emitted = 0usize;
    for error in schema.iter_errors(document) {
        let pointer = error.instance_path.to_string();
        let pointer_text = if pointer.is_empty() {
            "$".to_owned()
        } else {
            pointer
        };
        let code = if pointer_text.ends_with("/frontend") {
            TPX_101_FRONTEND_MISMATCH
        } else {
            TPX_100_SCHEMA_VIOLATION
        };
        diagnostics.push(TrustPolicyTranslationDiagnostic::new(
            TrustPolicySeverity::Error,
            code,
            format!(
                "Schema validation failed at '{pointer_text}': {error}",
            ),
            Some(SourceLocation::at(0, 0)),
            None,
        ));
        emitted += 1;
    }
    if emitted == 0 {
        // Defensive — `is_valid` returned false but `iter_errors` produced no leaves.
        emit_umbrella_schema_error(diagnostics);
    }
    false
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn emit_umbrella_schema_error(diagnostics: &mut Vec<TrustPolicyTranslationDiagnostic>) {
    diagnostics.push(TrustPolicyTranslationDiagnostic::new(
        TrustPolicySeverity::Error,
        TPX_100_SCHEMA_VIOLATION,
        "Schema validation failed (no leaf details available).".to_owned(),
        Some(SourceLocation::at(0, 0)),
        None,
    ));
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn non_object_root_failure(
    received: Value,
    mut diagnostics: Vec<TrustPolicyTranslationDiagnostic>,
) -> TrustPolicyTranslationResult {
    diagnostics.push(emit_non_object_root(&received));
    TrustPolicyTranslationResult::failure(diagnostics)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn emit_non_object_root(received: &Value) -> TrustPolicyTranslationDiagnostic {
    TrustPolicyTranslationDiagnostic::new(
        TrustPolicySeverity::Error,
        TPX_001_PARSE_ERROR,
        format!(
            "Document parsed to {kind}; the root must be an object.",
            kind = short_kind(received),
        ),
        Some(SourceLocation::at(0, 0)),
        None,
    )
}

fn has_error(diagnostics: &[TrustPolicyTranslationDiagnostic]) -> bool {
    diagnostics
        .iter()
        .any(|d| d.severity == TrustPolicySeverity::Error)
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn short_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a bool",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}
