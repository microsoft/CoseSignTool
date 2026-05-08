// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![deny(missing_docs)]

//! `cose_sign1_trustfrontends_rego` — Phase 5a (np-frontend-rego) of the
//! native Rust trust-policy port.
//!
//! Constrained-Rego-subset frontend (`cose-tp-rego/v1`). Parses an
//! OPA-compatible Rego document, rejects forbidden builtins / unconstrained
//! iteration / `data.*` references, lowers the parsed AST to the canonical
//! `cose-tp-json/v1` JSON shape, and forwards to
//! [`cose_sign1_trustfrontends_json::CoseTpJsonFrontend::translate_text`]
//! for schema validation + document walking. Mirrors the .NET
//! `CoseSign1.Validation.TrustFrontends.Rego` deliverable shipped in V2.
//!
//! # Why a constrained subset (and not full Rego)
//!
//! The original Rust port plan (decision R2) recommended `regorus` —
//! Microsoft's pure-Rust Rego interpreter — as the parser substrate. Phase
//! 5a re-evaluated that choice against the actual surface §6.5.6 demands.
//! The shape of "trust policy as data" is a tightly-bounded subset: object
//! literals, `input.<name>` parameter substitution, scalar literals,
//! arrays. Constraining a full-power Rego interpreter to that subset is a
//! larger engineering surface than writing a hand-rolled recursive-descent
//! parser:
//!
//! | Option | Cost | Verdict |
//! | --- | --- | --- |
//! | **A.** `regorus` partial-eval | Drag in regorus + transitive deps; configure HTTP / regex / file I/O / custom-builtin disable hooks; post-validate the residual against the same reject-list anyway | rejected |
//! | **B.** Hand-rolled parser over the §6.5.6 subset | ~1 KLoC, zero external deps, identical reject-list to .NET Phase 5a | **chosen** |
//!
//! The .NET Phase 5a port reached the same conclusion under analogous
//! constraints (no first-class .NET OPA partial-eval library) and shipped
//! a constrained-subset interpreter; the Rust port lifts the same
//! decision.
//!
//! # Pipeline
//!
//! 1. **Defense-in-depth** — bound input to 1 MiB so a hostile multi-MB
//!    document does not pressure memory during tokenisation. Trips emit
//!    `TPX306`.
//! 2. **Tokenise** the Rego source; lexical errors emit `TPX001` with
//!    line / column anchors.
//! 3. **Parse** via recursive descent on the closed subset; forbidden
//!    constructs surface per-cause sub-codes
//!    (`TPX301`/`TPX302`/`TPX303`/`TPX304`/`TPX305`); structural errors
//!    surface `TPX001`/`TPX002`/`TPX003`/`TPX004`/`TPX005`.
//! 4. **Lower** the AST to the canonical `cose-tp-json/v1` JSON shape.
//! 5. **Drive the JSON frontend** over the lowered tree — schema
//!    validation + walk + `ParameterRef` lifting all happen there. Cross-
//!    frontend equivalence is therefore a *property of construction*, not
//!    duplicated logic.
//!
//! # Sandboxing (§6.5.4 #6, #7)
//!
//! - The parser walks tokens; the lowerer pattern-matches AST nodes; the
//!   JSON frontend (audited under Phase 2 / Phase 4) validates + walks.
//!   No `eval`, no plugin loading, no I/O during translation.
//! - Bounded recursion: max depth 64, enforced by the parser's nesting
//!   counter — documents that exceed the cap surface `TPX305`.
//! - Bounded input: max 1 MiB, enforced before tokenisation — documents
//!   that exceed the cap surface `TPX306`.
//!
//! # Cross-port note (R2 amendment)
//!
//! This Rust frontend is logically equivalent to the .NET frontend at
//! `V2/CoseSign1.Validation.TrustFrontends.Rego/`. Both share the same
//! frontend id (`cose-tp-rego/v1`), media type
//! (`application/x-cose-trust-policy+rego`), accept-list grammar, and
//! reject-list (TPX301-306). The cross-frontend canonical-IR
//! byte-equality property is exercised by the conformance harness's
//! [`cose_sign1_trustfrontends_conformance::run_conformance_8_cross_equivalence`]
//! when paired with [`cose_sign1_trustfrontends_conformance::JsonConformanceAdapter`].

pub mod codes;
pub mod strings;

mod adapter;
mod ast;
mod document;
mod frontend;
mod lower;
mod parser;
mod tokenizer;

pub use adapter::RegoConformanceAdapter;
pub use document::RegoDocument;
pub use frontend::CoseTpRegoFrontend;
pub use strings::{FILE_EXTENSION, FRONTEND_ID, MAX_INPUT_BYTES, MAX_NESTING_DEPTH, MEDIA_TYPE_REGO, SNIFF_PREFIX};

// Re-export the abstraction layer for ergonomics: callers depend on this
// crate alone for the Rego frontend story and pick up the trait + supporting
// types transitively.
pub use cose_sign1_trust_policy_spec::{
    CoseTrustPolicyFrontend, FactCapabilities, TrustPolicySeverity,
    TrustPolicyTranslationContext, TrustPolicyTranslationDiagnostic,
    TrustPolicyTranslationResult,
};

/// Best-effort media-type sniff for a `.coseTrustPolicy.rego` document.
///
/// Returns [`MEDIA_TYPE_REGO`] when the source meets any of the dispatch
/// criteria the CLI uses (file extension, MIME type, or leading
/// `package cose_trust_policy` declaration). Returns `None` otherwise so
/// callers can fall through to other frontends. Pure function — no I/O.
pub fn sniff_media_type(filename_or_path: Option<&str>, source_text: Option<&str>) -> Option<&'static str> {
    if let Some(p) = filename_or_path {
        if p.ends_with(FILE_EXTENSION) {
            return Some(MEDIA_TYPE_REGO);
        }
    }
    if let Some(text) = source_text {
        // Skip leading whitespace + comments so a header banner doesn't
        // hide the package declaration. The check is intentionally narrow
        // — full lex would be too expensive at sniff time.
        let mut rest = text;
        loop {
            rest = rest.trim_start();
            if let Some(stripped) = rest.strip_prefix('#') {
                match stripped.find('\n') {
                    Some(end) => rest = &stripped[end + 1..],
                    None => return None,
                }
                continue;
            }
            break;
        }
        if rest.starts_with(SNIFF_PREFIX) {
            return Some(MEDIA_TYPE_REGO);
        }
    }
    None
}
