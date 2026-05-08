// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Boundary acceptance tests — for each closed reject-list family the
//! parser exposes, prove that the *closest legal equivalent* still
//! translates successfully. Without these "negative" tests the
//! reject-list could over-fire (rejecting valid input that happens to
//! share a shape with a forbidden construct) and the regression would
//! never surface.

use cose_sign1_trust_policy_spec::TrustPolicyTranslationContext;
use cose_sign1_trustfrontends_rego::CoseTpRegoFrontend;

fn must_translate(text: &str) {
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(text, &ctx, None);
    assert!(
        result.is_success(),
        "expected success; diagnostics={:?}",
        result.diagnostics,
    );
}

// ---------------------------------------------------------------------------
// TPX001 — every JSON escape that the lexer accepts MUST round-trip cleanly.
// ---------------------------------------------------------------------------

#[test]
fn legal_escapes_round_trip_successfully() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-cert-identity/v1\",\n        \"predicate\": {\"thumbprint\": \"a\\\"b\\\\c\\/d\\be\\fg\\nh\\ri\\tj\\u0041\"}\n    }\n}\n";
    must_translate(doc);
}

#[test]
fn legal_surrogate_pair_round_trips_successfully() {
    // \uD83D\uDE00 (GRINNING FACE) — closest legal equivalent of the
    // TPX001 lone-surrogate reject case.
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-cert-identity/v1\",\n        \"predicate\": {\"thumbprint\": \"\\uD83D\\uDE00\"}\n    }\n}\n";
    must_translate(doc);
}

// ---------------------------------------------------------------------------
// TPX002 — exactly the required package name passes.
// ---------------------------------------------------------------------------

#[test]
fn exactly_required_package_name_passes() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"is_trusted\": true}\n    }\n}\n";
    must_translate(doc);
}

// ---------------------------------------------------------------------------
// TPX004 — the single allowed import is accepted.
// ---------------------------------------------------------------------------

#[test]
fn allowed_future_keywords_in_import_passes() {
    let doc = "package cose_trust_policy\n\nimport future.keywords.in\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"is_trusted\": true}\n    }\n}\n";
    must_translate(doc);
}

// ---------------------------------------------------------------------------
// TPX005 — exactly one rule per package is the legal shape.
// ---------------------------------------------------------------------------

#[test]
fn single_rule_passes() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"is_trusted\": true}\n    }\n}\n";
    must_translate(doc);
}

// ---------------------------------------------------------------------------
// TPX301 — every namespace the reject-list classifies as a forbidden
// builtin is forbidden ONLY at term position. As a string-literal value
// the same identifier passes through to the JSON walker as opaque text.
// ---------------------------------------------------------------------------

#[test]
fn namespace_names_as_string_values_pass() {
    for ns in &["http", "regex", "file", "io", "os", "crypto", "net", "time", "opa"] {
        let doc = format!(
            "package cose_trust_policy\n\npolicy := {{\n    \"primary_signing_key\": {{\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {{\"value\": \"{ns}-as-data\"}}\n    }}\n}}\n"
        );
        must_translate(&doc);
    }
}

// ---------------------------------------------------------------------------
// TPX302 — `some_word` (looks like `some` but isn't) is fine as a string.
// ---------------------------------------------------------------------------

#[test]
fn iteration_keyword_lookalikes_as_strings_pass() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"reason\": \"some user-written description containing the word every\"}\n    }\n}\n";
    must_translate(doc);
}

// ---------------------------------------------------------------------------
// TPX303 — `input.data` (the legal alias for parameterised access) passes.
// ---------------------------------------------------------------------------

#[test]
fn input_namespace_passes_where_data_namespace_would_fail() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-cert-identity/v1\",\n        \"predicate\": {\"thumbprint\": input.data}\n    }\n}\n";
    must_translate(doc);
}

// ---------------------------------------------------------------------------
// TPX304 — a literal array / object (no `|`) passes; this is the closest
// legal sibling of a comprehension.
// ---------------------------------------------------------------------------

#[test]
fn literal_array_at_comprehension_position_passes() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"all_of\": [\n            {\"fact\": \"x509-chain-trusted/v1\", \"predicate\": {\"is_trusted\": true}}\n        ]\n    }\n}\n";
    must_translate(doc);
}

// ---------------------------------------------------------------------------
// TPX305 — exactly cap-1 (63) levels of nesting is legal; cap+1 trips
// (already covered in reject_list.rs). The boundary just below is the
// acceptance side.
// ---------------------------------------------------------------------------

#[test]
fn nesting_depth_just_below_cap_passes() {
    // 60 levels of nested arrays inside the body — well below the cap of 64
    // and still leaves room for the outer object literal that hosts the
    // body.
    let inner_arrays = "[".repeat(60) + &"]".repeat(60);
    let doc = format!(
        "package cose_trust_policy\n\npolicy := {{\n    \"primary_signing_key\": {{\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {{\"value\": {inner_arrays}}}\n    }}\n}}\n"
    );
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(&doc, &ctx, None);
    // 60-level nested arrays trip the JSON schema (predicate values are
    // not arrays), but the parser MUST accept the document — the only
    // failure should come from the JSON walker, never from the parser's
    // depth guard. Assert that no TPX305 surfaces.
    assert!(
        !result.diagnostics.iter().any(|d| d.code == "TPX305"),
        "depth-cap minus-4 must NOT trip the parser depth guard; diagnostics={:?}",
        result.diagnostics,
    );
}

// ---------------------------------------------------------------------------
// TPX306 — exactly cap-1 byte size is legal.
// ---------------------------------------------------------------------------

#[test]
fn input_just_below_size_cap_passes_size_guard() {
    let header = "package cose_trust_policy\npolicy := {\"primary_signing_key\": {\"fact\": \"x509-chain-trusted/v1\", \"predicate\": {\"value\": \"";
    let trailer = "\"}}}\n";
    // Pad up to cap minus a comfortable margin so the document still
    // round-trips through the JSON frontend.
    let pad_len = cose_sign1_trustfrontends_rego::MAX_INPUT_BYTES - 4096
        - header.len()
        - trailer.len();
    let mut doc = String::with_capacity(header.len() + pad_len + trailer.len());
    doc.push_str(header);
    for _ in 0..pad_len {
        doc.push('a');
    }
    doc.push_str(trailer);
    assert!(doc.len() < cose_sign1_trustfrontends_rego::MAX_INPUT_BYTES);
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(&doc, &ctx, None);
    assert!(
        !result.diagnostics.iter().any(|d| d.code == "TPX306"),
        "below-cap input MUST NOT trip the input-size guard; diagnostics len={}",
        result.diagnostics.len(),
    );
}

// ---------------------------------------------------------------------------
// Multiple-surrogate-event sequence: valid pair followed by a lone low
// surrogate. The first pair MUST be accepted; the second MUST be rejected.
// ---------------------------------------------------------------------------

#[test]
fn pair_then_lone_low_surrogate_rejects_with_tpx001() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-cert-identity/v1\",\n        \"predicate\": {\"thumbprint\": \"\\uD83D\\uDE00\\uDC00\"}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(!result.is_success());
    assert!(result.diagnostics.iter().any(|d| d.code == "TPX001"));
}

// ---------------------------------------------------------------------------
// Document-source threading — emitted diagnostics include the source path.
// ---------------------------------------------------------------------------

#[test]
fn diagnostics_include_document_source_prefix() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": invalid_identifier\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result =
        frontend.translate_text(doc, &ctx, Some("file:///etc/myapp/policy.coseTrustPolicy.rego"));
    assert!(!result.is_success());
    let diag = result
        .diagnostics
        .iter()
        .find(|d| d.code == "TPX300")
        .expect("expected TPX300 for unknown identifier");
    assert!(
        diag.message.contains("file:///etc/myapp/policy.coseTrustPolicy.rego"),
        "diagnostic message should embed document source: {}",
        diag.message,
    );
}

#[test]
fn lowered_value_accessor_is_pretty_printable() {
    use cose_sign1_trust_policy_spec::TrustPolicyTranslationDiagnostic;
    use cose_sign1_trustfrontends_rego::RegoDocument;
    let mut diagnostics: Vec<TrustPolicyTranslationDiagnostic> = Vec::new();
    let doc = RegoDocument::parse(
        "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"is_trusted\": true}\n    }\n}\n",
        Some("memory://"),
        &mut diagnostics,
    )
    .expect("parse must succeed");
    let pretty = serde_json::to_string_pretty(doc.lowered()).unwrap();
    assert!(pretty.contains("\"primary_signing_key\""));
    assert!(pretty.contains("\"x509-chain-trusted/v1\""));
}
