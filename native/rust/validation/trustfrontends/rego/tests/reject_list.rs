// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Reject-list tests — every closed-grammar rejection must surface the
//! expected `TPXxxx` sub-code so blue-team telemetry attributes rejection
//! rates accurately. Mirrors the .NET Phase 5a HardeningTests +
//! CoverageBranchTests reject-list cells.

use cose_sign1_trust_policy_spec::{
    TrustPolicySeverity, TrustPolicyTranslationContext,
};
use cose_sign1_trustfrontends_rego::CoseTpRegoFrontend;

fn translate(text: &str) -> Vec<(String, String)> {
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(text, &ctx, None);
    assert!(
        result.spec.is_none(),
        "expected rejection, got Some(spec); diagnostics={:?}",
        result.diagnostics,
    );
    assert!(
        result.diagnostics.iter().any(|d| d.severity == TrustPolicySeverity::Error),
        "diagnostics carried no Error severity: {:?}",
        result.diagnostics,
    );
    result
        .diagnostics
        .into_iter()
        .map(|d| (d.code, d.message))
        .collect()
}

fn assert_code(diagnostics: &[(String, String)], expected_code: &str) {
    assert!(
        diagnostics.iter().any(|(c, _)| c == expected_code),
        "expected {expected_code} in diagnostics; got {diagnostics:?}",
    );
}

// ---------------------------------------------------------------------------
// TPX001 — lexical / syntactic faults
// ---------------------------------------------------------------------------

#[test]
fn tpx001_unterminated_string_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX001");
}

#[test]
fn tpx001_invalid_escape_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"\\q\"\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX001");
}

#[test]
fn tpx001_lone_high_surrogate_is_rejected() {
    // \uD800 with no following \uDC00 pair.
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"\\uD800abc\"\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX001");
}

#[test]
fn tpx001_lone_low_surrogate_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"\\uDC00\"\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX001");
}

#[test]
fn tpx001_unescaped_control_char_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"abc\u{0001}def\"\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX001");
}

#[test]
fn tpx001_malformed_number_exponent_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"value\": 1e\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX001");
}

#[test]
fn tpx001_duplicate_object_key_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"fact\": \"made-up-fact/v1\"\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX001");
}

// ---------------------------------------------------------------------------
// TPX002 — missing / wrong package
// ---------------------------------------------------------------------------

#[test]
fn tpx002_missing_package_is_rejected() {
    let diags = translate("policy := {}\n");
    assert_code(&diags, "TPX002");
}

#[test]
fn tpx002_wrong_package_name_is_rejected() {
    let diags = translate("package my_app.policies\n\npolicy := {}\n");
    assert_code(&diags, "TPX002");
}

// ---------------------------------------------------------------------------
// TPX003 — missing policy rule
// ---------------------------------------------------------------------------

#[test]
fn tpx003_missing_policy_rule_is_rejected() {
    let diags = translate("package cose_trust_policy\n");
    assert_code(&diags, "TPX003");
}

#[test]
fn tpx003_wrong_rule_name_is_rejected() {
    let diags = translate("package cose_trust_policy\n\nallow := true\n");
    assert_code(&diags, "TPX003");
}

// ---------------------------------------------------------------------------
// TPX004 — forbidden import
// ---------------------------------------------------------------------------

#[test]
fn tpx004_forbidden_import_data_is_rejected() {
    let diags = translate(
        "package cose_trust_policy\n\nimport data.network.allowed\n\npolicy := {}\n",
    );
    assert_code(&diags, "TPX004");
}

#[test]
fn tpx004_forbidden_import_future_keywords_every_is_rejected() {
    let diags = translate(
        "package cose_trust_policy\n\nimport future.keywords.every\n\npolicy := {}\n",
    );
    assert_code(&diags, "TPX004");
}

// ---------------------------------------------------------------------------
// TPX005 — multiple rules
// ---------------------------------------------------------------------------

#[test]
fn tpx005_multiple_rules_per_package_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {}\n\nextra := {}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX005");
}

// ---------------------------------------------------------------------------
// TPX301 — forbidden builtins
// ---------------------------------------------------------------------------

#[test]
fn tpx301_http_send_is_rejected() {
    // Modelled on the .NET Phase 5a `untranslatable/http-send.rego` fixture:
    // forbidden builtins surface inside the policy body (as predicate values
    // or scope arms).
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\n            \"operator\": \"Equals\",\n            \"path\": \"$.is_trusted\",\n            \"value\": http.send({\"url\": \"https://example/\"})\n        }\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX301");
}

#[test]
fn tpx301_regex_match_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"message\": {\n        \"fact\": \"content-type/v1\",\n        \"predicate\": {\"matches\": regex.match(\".*\", \"x\")}\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX301");
}

#[test]
fn tpx301_crypto_namespace_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": crypto.x509.parse_certificates(\"abc\")}\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX301");
}

#[test]
fn tpx301_each_namespace_classified_as_builtin() {
    for ns in &["http", "regex", "file", "io", "os", "crypto", "net", "time", "opa"] {
        let doc = format!(
            "package cose_trust_policy\n\npolicy := {{\n    \"primary_signing_key\": {{\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {{\"value\": {ns}.foo(1)}}\n    }}\n}}\n"
        );
        let diags = translate(&doc);
        assert_code(&diags, "TPX301");
    }
}

// ---------------------------------------------------------------------------
// TPX302 — unconstrained iteration
// ---------------------------------------------------------------------------

#[test]
fn tpx302_some_keyword_at_rule_position_is_rejected() {
    // Modelled on .NET `untranslatable/unconstrained-iteration.rego`:
    // `some x in coll` lands at the rule-name slot after imports are
    // exhausted, so the parser's forbidden-rule-name guard fires first.
    let doc = "package cose_trust_policy\n\nsome x in [1, 2, 3]\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX302");
}

#[test]
fn tpx302_some_keyword_inside_predicate_value_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": some x in [1, 2, 3]}\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX302");
}

#[test]
fn tpx302_each_iteration_keyword_classified_at_rule_slot() {
    // At the rule-name slot, the parser's forbidden-rule-name guard
    // surfaces TPX302 for every iteration / quantification keyword.
    for kw in &["some", "every", "with", "default", "not", "eval"] {
        let doc = format!("package cose_trust_policy\n\n{kw} foo\n");
        let diags = translate(&doc);
        assert_code(&diags, "TPX302");
    }
}

// ---------------------------------------------------------------------------
// TPX303 — reserved data reference
// ---------------------------------------------------------------------------

#[test]
fn tpx303_data_reference_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": data.allowed_thumbprints}\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX303");
}

#[test]
fn tpx303_data_qualifier_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": data.networks.public}\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX303");
}

// ---------------------------------------------------------------------------
// TPX304 — comprehension rejected
// ---------------------------------------------------------------------------

#[test]
fn tpx304_array_comprehension_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"all_of\": [x | x > 0]\n    }\n}\n";
    let diags = translate(doc);
    // Comprehension shape MUST surface TPX304 verbatim — accepting the
    // generic TPX300 fallback would hide a regression that downgrades a
    // closed-grammar comprehension to the catch-all bucket.
    assert_code(&diags, "TPX304");
}

#[test]
fn tpx304_pipe_in_object_position_is_rejected() {
    // `{ x | y }` — the `|` is an unsupported symbol; the parser detects
    // the comprehension shape via PeekAfterIdentifierIsPipe and surfaces
    // TPX304.
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {x | y}\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX304");
}

#[test]
fn tpx304_pipe_after_array_element_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"all_of\": [1 | 2]\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX304");
}

// ---------------------------------------------------------------------------
// TPX305 — max nesting depth
// ---------------------------------------------------------------------------

#[test]
fn tpx305_deep_nesting_is_rejected() {
    // Build a 70-level-deep object via repeated wrapping. The body must be
    // an object literal per the cose-tp/v1 schema, so the test wraps the
    // depth-bomb in an outer key.
    let mut doc = String::from("package cose_trust_policy\n\npolicy := {\"primary_signing_key\": ");
    let opens = "[".repeat(70);
    let closes = "]".repeat(70);
    doc.push_str(&opens);
    doc.push_str(&closes);
    doc.push_str("}\n");
    let diags = translate(&doc);
    assert_code(&diags, "TPX305");
}

#[test]
fn tpx305_deep_object_nesting_is_rejected() {
    let mut doc = String::from("package cose_trust_policy\n\npolicy := {\"primary_signing_key\": ");
    let nested = "{\"k\": ".repeat(70);
    let close = "}".repeat(70);
    doc.push_str(&nested);
    doc.push_str("1");
    doc.push_str(&close);
    doc.push_str("}\n");
    let diags = translate(&doc);
    assert_code(&diags, "TPX305");
}

// ---------------------------------------------------------------------------
// TPX306 — input too large
// ---------------------------------------------------------------------------

#[test]
fn tpx306_oversized_input_is_rejected() {
    let header = "package cose_trust_policy\npolicy := \"";
    let trailer = "\"\n";
    let pad_len = cose_sign1_trustfrontends_rego::MAX_INPUT_BYTES + 1
        - header.len()
        - trailer.len();
    let mut doc = String::with_capacity(header.len() + pad_len + trailer.len());
    doc.push_str(header);
    for _ in 0..pad_len {
        doc.push('a');
    }
    doc.push_str(trailer);
    assert!(doc.len() > cose_sign1_trustfrontends_rego::MAX_INPUT_BYTES);
    let diags = translate(&doc);
    assert_code(&diags, "TPX306");
}

// ---------------------------------------------------------------------------
// TPX300 — catch-all untranslatable
// ---------------------------------------------------------------------------

#[test]
fn tpx300_unknown_identifier_inside_body_is_rejected() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": some_unknown_identifier}\n    }\n}\n";
    let diags = translate(doc);
    assert_code(&diags, "TPX300");
}
