// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Frontend translation abstraction (Phase 2, §6.5.3).
//!
//! Every CoseSign1 trust-policy frontend (Phase 2 JSON, Phase 5a Rego) implements
//! [`CoseTrustPolicyFrontend`]: parse a document of frontend-specific shape, validate
//! it against the frontend's published grammar, walk it into a [`crate::TrustPolicySpec`],
//! and surface diagnostics with stable codes + source locations.
//!
//! # Placement rationale
//!
//! Co-located with the IR rather than in the validation runtime because every frontend
//! MUST return a [`crate::TrustPolicySpec`]. Lifting the abstraction into
//! `cose_sign1_validation_primitives` would create a cycle (primitives is referenced by
//! this crate, not the other way around). Future frontends (`cose-tp-rego/v1`, `cel/v1`)
//! reference this crate for the IR types and pick up the abstraction at zero cost. Mirrors
//! the .NET architectural decision captured in the Phase 2 dispatch report.

use crate::source_location::SourceLocation;
use crate::spec::TrustPolicySpec;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Diagnostic severity. Closed enum carried by every
/// [`TrustPolicyTranslationDiagnostic`].
///
/// `#[non_exhaustive]` so future severities (e.g. `Hint`, `Note`) can land in a minor
/// release without breaking source-level matches downstream.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TrustPolicySeverity {
    /// Translation cannot proceed; a result that carries any `Error` MUST have
    /// `spec = None` per the totality contract (§6.5.4 #2).
    Error,
    /// Translation succeeded but the frontend wants the host to know about a soft issue
    /// (e.g. deprecated key, extraneous field tolerated for forward-compat).
    Warning,
    /// Informational note. Always non-blocking.
    Info,
}

/// One observation emitted by a frontend's
/// [`CoseTrustPolicyFrontend::translate`] pass.
///
/// `code` is drawn from the stable `TPXxxx` namespace (see
/// [`crate::diagnostic_codes`]) so callers can switch on the failure category without
/// parsing the human-readable message.
///
/// `#[non_exhaustive]` permits adding fields (e.g. structured `data` payloads) in a minor
/// release without breaking literal-form construction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrustPolicyTranslationDiagnostic {
    /// Severity tier.
    pub severity: TrustPolicySeverity,
    /// Stable diagnostic code from the `TPXxxx` namespace.
    pub code: String,
    /// Human-readable message identifying the offending construct.
    pub message: String,
    /// Optional source pointer to the construct in the user document.
    pub location: Option<SourceLocation>,
    /// Optional remediation hint.
    pub suggestion: Option<String>,
}

impl TrustPolicyTranslationDiagnostic {
    /// Construct a diagnostic with explicit values for every field. Use this from
    /// crates outside `cose_sign1_trust_policy_spec` (the struct is `#[non_exhaustive]`
    /// to remain forward-compat, so cross-crate literal construction is forbidden by
    /// the compiler).
    pub fn new(
        severity: TrustPolicySeverity,
        code: impl Into<String>,
        message: impl Into<String>,
        location: Option<SourceLocation>,
        suggestion: Option<String>,
    ) -> Self {
        Self {
            severity,
            code: code.into(),
            message: message.into(),
            location,
            suggestion,
        }
    }

    /// Construct an `Error`-severity diagnostic with the given code and message.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(
            TrustPolicySeverity::Error,
            code,
            message,
            None,
            None,
        )
    }

    /// Construct a `Warning`-severity diagnostic with the given code and message.
    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(
            TrustPolicySeverity::Warning,
            code,
            message,
            None,
            None,
        )
    }

    /// Construct an `Info`-severity diagnostic with the given code and message.
    pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(
            TrustPolicySeverity::Info,
            code,
            message,
            None,
            None,
        )
    }

    /// Builder helper: attach a [`SourceLocation`] to this diagnostic.
    pub fn with_location(mut self, location: SourceLocation) -> Self {
        self.location = Some(location);
        self
    }

    /// Builder helper: attach a remediation suggestion to this diagnostic.
    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }
}

/// Capability surface advertised by the host (§6.5.4 #5, D4).
///
/// When a translator receives a non-null [`FactCapabilities`] in its
/// [`TrustPolicyTranslationContext`], it MUST validate every fact reference against
/// `available_fact_ids` (unless [`TrustPolicyTranslationContext::allow_unknown_facts`]
/// is `true`). Unknown ids surface as the `TPX200` diagnostic.
///
/// Optional per-fact predicate schemas in `predicate_schemas` let the translator catch
/// type-shape errors before the policy reaches the trust evaluator. Failures surface as
/// `TPX201`.
///
/// `#[non_exhaustive]` so forward-compat additions (e.g. predicate-schema versioning) are
/// not a breaking change.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct FactCapabilities {
    /// Set of fact ids the host advertises (e.g. `x509-chain-trusted/v1`).
    pub available_fact_ids: BTreeSet<String>,
    /// Optional per-fact predicate schemas, keyed by fact id.
    ///
    /// Each value is a JSON Schema document carried as a `serde_json::Value` so the
    /// frontend abstraction stays validator-agnostic.
    pub predicate_schemas: BTreeMap<String, Value>,
}

impl FactCapabilities {
    /// Construct a capability surface advertising the given ids and no predicate schemas.
    pub fn ids_only(ids: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            available_fact_ids: ids.into_iter().map(Into::into).collect(),
            predicate_schemas: BTreeMap::new(),
        }
    }
}

impl Default for FactCapabilities {
    fn default() -> Self {
        Self {
            available_fact_ids: BTreeSet::new(),
            predicate_schemas: BTreeMap::new(),
        }
    }
}

/// Inputs supplied to [`CoseTrustPolicyFrontend::translate`] alongside the parsed
/// document.
///
/// `parameters` carries host-supplied values for `$param` references; per design decision
/// D5 the frontend does not bind eagerly — binding is a separate post-translate pass via
/// [`crate::bind`] so the same translation can be reused for multiple parameter sets.
///
/// `available_facts` (when non-null) plus `allow_unknown_facts` (default `false`) gate
/// fact references per §6.5.4 #5.
///
/// `#[non_exhaustive]` so future opt-in fields (e.g. predicate evaluation hooks) ship in a
/// minor release without breaking source compatibility.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TrustPolicyTranslationContext {
    /// Host-supplied parameter values applied by the post-translate
    /// [`crate::bind`] pass.
    pub parameters: BTreeMap<String, Value>,
    /// Optional fact capability surface used to gate fact references.
    pub available_facts: Option<FactCapabilities>,
    /// When `true` and `available_facts` is supplied, references to unrecognised ids do
    /// NOT produce errors.
    pub allow_unknown_facts: bool,
}

impl TrustPolicyTranslationContext {
    /// An empty context: no parameters, no capability gating.
    pub fn empty() -> Self {
        Self {
            parameters: BTreeMap::new(),
            available_facts: None,
            allow_unknown_facts: false,
        }
    }
}

impl Default for TrustPolicyTranslationContext {
    fn default() -> Self {
        Self::empty()
    }
}

/// Output of [`CoseTrustPolicyFrontend::translate`].
///
/// Either carries a well-formed [`TrustPolicySpec`] with no `Error`-severity diagnostics,
/// or carries a `None` `spec` with at least one `Error` diagnostic — the totality
/// contract per §6.5.4 #2.
///
/// `#[non_exhaustive]` so future fields (e.g. translator metadata, timing) can be added
/// without breaking literal construction.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TrustPolicyTranslationResult {
    /// The produced spec, or `None` when translation failed.
    pub spec: Option<TrustPolicySpec>,
    /// Diagnostics emitted by the translator. May be empty on success.
    pub diagnostics: Vec<TrustPolicyTranslationDiagnostic>,
}

impl TrustPolicyTranslationResult {
    /// `true` when `spec` is `Some` and no diagnostic has severity
    /// [`TrustPolicySeverity::Error`].
    pub fn is_success(&self) -> bool {
        self.spec.is_some() && !self.has_error()
    }

    /// `true` when at least one diagnostic has severity [`TrustPolicySeverity::Error`].
    pub fn has_error(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == TrustPolicySeverity::Error)
    }

    /// Construct a successful result.
    pub fn success(
        spec: TrustPolicySpec,
        diagnostics: Vec<TrustPolicyTranslationDiagnostic>,
    ) -> Self {
        Self {
            spec: Some(spec),
            diagnostics,
        }
    }

    /// Construct a failed result.
    pub fn failure(diagnostics: Vec<TrustPolicyTranslationDiagnostic>) -> Self {
        Self {
            spec: None,
            diagnostics,
        }
    }
}

/// The translation contract every CoseSign1 trust-policy frontend must satisfy
/// (§6.5.3).
///
/// Generic over the parsed-document type (`serde_json::Value` for the JSON frontend,
/// future frontends supply their own document representation).
///
/// Per §6.5.4 every implementation MUST satisfy: determinism, totality, attribute
/// fidelity, reject-what-you-cant-translate, capability-aware translation, no code
/// execution, bounded runtime, schema-checked output.
pub trait CoseTrustPolicyFrontend<TDocument> {
    /// Stable identifier for this frontend (e.g. `cose-tp-json/v1`).
    fn frontend_id(&self) -> &'static str;

    /// IANA media types this frontend recognises.
    fn supported_media_types(&self) -> &'static [&'static str];

    /// Translate `document` to a [`TrustPolicyTranslationResult`].
    fn translate(
        &self,
        document: TDocument,
        ctx: &TrustPolicyTranslationContext,
    ) -> TrustPolicyTranslationResult;
}
