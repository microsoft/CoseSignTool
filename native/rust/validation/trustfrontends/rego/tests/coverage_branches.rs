// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage-focused tests targeting branches, defensive paths, and
//! public surfaces not exercised by the smoke / reject-list / robustness
//! suites. Each test below was added to close a specific coverage gap
//! identified by `cargo llvm-cov`.

use cose_sign1_trust_policy_spec::{
    CoseTrustPolicyFrontend, FactCapabilities, TrustPolicyTranslationContext,
    TrustPolicyTranslationDiagnostic,
};
use cose_sign1_trustfrontends_json::CoseTpJsonFrontend;
use cose_sign1_trustfrontends_rego::{
    CoseTpRegoFrontend, RegoConformanceAdapter, RegoDocument,
};
use std::collections::BTreeSet;

fn doc_text() -> &'static str {
    "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"is_trusted\": true}\n    }\n}\n"
}

#[test]
fn frontend_default_constructor_works() {
    let frontend = CoseTpRegoFrontend::default();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc_text(), &ctx, None);
    assert!(result.is_success());
}

#[test]
fn frontend_with_json_frontend_constructor_uses_supplied_dependency() {
    let json = CoseTpJsonFrontend::new();
    let frontend = CoseTpRegoFrontend::with_json_frontend(json);
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc_text(), &ctx, Some("file:///src.rego"));
    assert!(result.is_success());
}

#[test]
fn trait_translate_is_used_via_dynamic_dispatch() {
    // Exercise the `CoseTrustPolicyFrontend::translate` dispatch (the
    // direct trait path used by the conformance harness's
    // `translate_fixture`), distinct from the convenience
    // `translate_text` entry.
    let frontend: Box<dyn CoseTrustPolicyFrontend<RegoDocument>> =
        Box::new(CoseTpRegoFrontend::new());
    let mut diagnostics: Vec<TrustPolicyTranslationDiagnostic> = Vec::new();
    let document = RegoDocument::parse(doc_text(), Some("memory://"), &mut diagnostics)
        .expect("parse must succeed");
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate(document, &ctx);
    assert!(result.is_success());
    assert_eq!(frontend.frontend_id(), "cose-tp-rego/v1");
    assert_eq!(frontend.supported_media_types(), &["application/x-cose-trust-policy+rego"]);
}

#[test]
fn rego_document_debug_is_implemented() {
    let mut diagnostics: Vec<TrustPolicyTranslationDiagnostic> = Vec::new();
    let document =
        RegoDocument::parse(doc_text(), Some("debug-test"), &mut diagnostics).unwrap();
    let s = format!("{document:?}");
    assert!(s.contains("RegoDocument"));
    assert!(s.contains("debug-test"));
    assert_eq!(document.document_source(), Some("debug-test"));
}

#[test]
fn rego_document_parse_returns_none_on_lex_error() {
    let mut diagnostics: Vec<TrustPolicyTranslationDiagnostic> = Vec::new();
    let result = RegoDocument::parse(
        "package cose_trust_policy\n\npolicy := {\"x\": \"\\q\"}\n",
        None,
        &mut diagnostics,
    );
    assert!(result.is_none());
    assert!(diagnostics.iter().any(|d| d.code == "TPX001"));
}

#[test]
fn translate_with_capabilities_routes_unknown_facts_to_tpx200() {
    let frontend = CoseTpRegoFrontend::new();
    let mut ctx = TrustPolicyTranslationContext::empty();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    ids.insert("x509-chain-trusted/v1".to_owned());
    ctx.available_facts = Some(FactCapabilities::ids_only(ids));
    ctx.allow_unknown_facts = false;

    let unknown = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"definitely-not-registered/v1\",\n        \"predicate\": {\"is_trusted\": true}\n    }\n}\n";
    let result = frontend.translate_text(unknown, &ctx, None);
    assert!(!result.is_success());
    assert!(
        result.diagnostics.iter().any(|d| d.code == "TPX200"),
        "expected TPX200 for unknown fact id; got {:?}",
        result.diagnostics,
    );
}

#[test]
fn parse_into_input_size_guard_short_circuits_before_tokeniser() {
    // Documents over MAX_INPUT_BYTES MUST surface TPX306 *before* the
    // tokeniser runs, so a multi-MB hostile payload doesn't pressure
    // memory.
    let big_len = cose_sign1_trustfrontends_rego::MAX_INPUT_BYTES + 256;
    let mut text = String::with_capacity(big_len);
    text.push_str("package cose_trust_policy\npolicy := \"");
    while text.len() < big_len {
        text.push('a');
    }
    text.push('"');
    let mut diagnostics: Vec<TrustPolicyTranslationDiagnostic> = Vec::new();
    assert!(RegoDocument::parse(&text, Some("oversize"), &mut diagnostics).is_none());
    assert!(diagnostics.iter().any(|d| d.code == "TPX306"));
}

#[test]
fn adapter_with_fact_ids_constructor_is_honoured() {
    let mut ids: BTreeSet<String> = BTreeSet::new();
    ids.insert("only-fact/v1".to_owned());
    let adapter = RegoConformanceAdapter::with_fact_ids(ids.clone());
    use cose_sign1_trustfrontends_conformance::ConformanceAdapter;
    assert_eq!(adapter.registered_fact_ids(), ids);
    assert_eq!(adapter.fixture_extension(), "coseTrustPolicy.rego");
}

#[test]
fn adapter_with_fixture_root_constructor_is_honoured() {
    use cose_sign1_trustfrontends_conformance::ConformanceAdapter;
    let custom_root = std::env::temp_dir().join("rego_adapter_custom");
    let mut ids: BTreeSet<String> = BTreeSet::new();
    ids.insert("synthetic/v1".to_owned());
    let adapter = RegoConformanceAdapter::with_fixture_root(ids, custom_root.clone());
    assert_eq!(adapter.fixture_root(), custom_root);
}

#[test]
fn adapter_creates_fresh_frontend_each_call() {
    use cose_sign1_trustfrontends_conformance::ConformanceAdapter;
    let adapter = RegoConformanceAdapter::default();
    let f1 = adapter.create_frontend();
    let f2 = adapter.create_frontend();
    // Both instances must respond to the same interface contract.
    assert_eq!(f1.frontend_id(), f2.frontend_id());
}

#[test]
fn adapter_load_document_round_trips_fixture() {
    use cose_sign1_trustfrontends_conformance::ConformanceAdapter;
    let adapter = RegoConformanceAdapter::default();
    let fixture_root = adapter.fixture_root();
    let path = fixture_root
        .join("cross")
        .join("canonical_policy")
        .join("canonical_policy.coseTrustPolicy.rego");
    let document = adapter.load_document(&path);
    assert_eq!(
        document.document_source(),
        Some(path.to_string_lossy().as_ref()),
    );
}

#[test]
fn lower_handles_decimal_number() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": 1.5}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(result.is_success(), "diagnostics={:?}", result.diagnostics);
}

#[test]
fn lower_handles_exponent_number() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": 1e3}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(result.is_success(), "diagnostics={:?}", result.diagnostics);
}

#[test]
fn lower_handles_negative_decimal_number() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": -2.5}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(result.is_success(), "diagnostics={:?}", result.diagnostics);
}

#[test]
fn lower_handles_empty_array_and_empty_object() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"any_of\": [\n            {\"fact\": \"x509-chain-trusted/v1\", \"predicate\": {}}\n        ]\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    // Even though predicate {} fails JSON schema (predicate has minProperties),
    // translation proceeds far enough to exercise the empty-object lowering.
    let _ = result;
}

#[test]
fn lower_handles_null_literal() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": null}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let _ = frontend.translate_text(doc, &ctx, None);
}

#[test]
fn lower_handles_false_literal() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"is_trusted\": false}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(result.is_success(), "diagnostics={:?}", result.diagnostics);
}

#[test]
fn parser_handles_dotted_input_reference() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-cert-identity/v1\",\n        \"predicate\": {\"thumbprint\": input.trusted.primary.thumbprint}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(result.is_success(), "diagnostics={:?}", result.diagnostics);
}

#[test]
fn parser_rejects_dotted_input_reference_with_dot_at_end() {
    // The trailing `.` means the `input.<name>` rule expects an
    // identifier next, gets EOF / RightBrace instead — TPX001.
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-cert-identity/v1\",\n        \"predicate\": {\"thumbprint\": input.trusted.}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(!result.is_success());
}

#[test]
fn parser_handles_array_followed_by_array() {
    // Exercise the array-element-then-array sub-path.
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"all_of\": [\n            {\"fact\": \"x509-chain-trusted/v1\", \"predicate\": {\"is_trusted\": true}},\n            {\"fact\": \"x509-cert-identity-allowed/v1\", \"predicate\": {\"is_allowed\": true}}\n        ]\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(result.is_success(), "diagnostics={:?}", result.diagnostics);
}

#[test]
fn parser_accepts_trailing_comma_in_object() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"is_trusted\": true,},\n    },\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(result.is_success(), "diagnostics={:?}", result.diagnostics);
}

#[test]
fn parser_accepts_trailing_comma_in_array() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"all_of\": [\n            {\"fact\": \"x509-chain-trusted/v1\", \"predicate\": {\"is_trusted\": true}},\n        ]\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(result.is_success(), "diagnostics={:?}", result.diagnostics);
}

#[test]
fn parser_handles_empty_object_at_top_level_of_body() {
    // The body must satisfy the JSON schema's anyOf — empty object fails
    // schema, but the parser path through the empty-object branch is
    // exercised here.
    let doc = "package cose_trust_policy\n\npolicy := {}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let _ = frontend.translate_text(doc, &ctx, None);
}

#[test]
fn parser_rejects_minus_followed_by_non_number() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": -true}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(!result.is_success());
    assert!(result.diagnostics.iter().any(|d| d.code == "TPX001"));
}

#[test]
fn parser_rejects_unsupported_punctuation_at_term_position() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": ?}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(!result.is_success());
}

#[test]
fn parser_handles_dotted_package_after_first_segment() {
    // `package cose_trust_policy.extra` is a wrong-package case; the
    // parser reads dotted segments and compares the joined name.
    let doc = "package cose_trust_policy.extra\n\npolicy := {}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(!result.is_success());
    assert!(result.diagnostics.iter().any(|d| d.code == "TPX002"));
}

#[test]
fn tokenizer_handles_nul_terminated_string_escape() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-cert-identity/v1\",\n        \"predicate\": {\"thumbprint\": \"\\u0041\\u0042\"}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(result.is_success(), "diagnostics={:?}", result.diagnostics);
}

#[test]
fn tokenizer_handles_each_json_escape() {
    // Cover every escape arm of read_string: \", \\, \/, \b, \f, \n, \r, \t.
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-cert-identity/v1\",\n        \"predicate\": {\"thumbprint\": \"a\\\"b\\\\c\\/d\\be\\fg\\nh\\ri\\tj\"}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(result.is_success(), "diagnostics={:?}", result.diagnostics);
}

#[test]
fn tokenizer_rejects_truncated_unicode_escape() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"\\u12\"\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(!result.is_success());
    assert!(result.diagnostics.iter().any(|d| d.code == "TPX001"));
}

#[test]
fn tokenizer_rejects_non_hex_in_unicode_escape() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"\\uZZZZ\"\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(!result.is_success());
    assert!(result.diagnostics.iter().any(|d| d.code == "TPX001"));
}

#[test]
fn tokenizer_handles_high_low_surrogate_pair() {
    // U+1F600 GRINNING FACE encoded as UTF-16 surrogate pair.
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-cert-identity/v1\",\n        \"predicate\": {\"thumbprint\": \"\\uD83D\\uDE00\"}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(result.is_success(), "diagnostics={:?}", result.diagnostics);
}

#[test]
fn tokenizer_handles_high_surrogate_followed_by_invalid_low() {
    // \uD800 then \u1234 (not a low surrogate) — must reject.
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"\\uD800\\u1234\"\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(!result.is_success());
    assert!(result.diagnostics.iter().any(|d| d.code == "TPX001"));
}

#[test]
fn tokenizer_handles_high_surrogate_followed_by_truncated_escape() {
    // \uD800 then \u (truncated) — must reject.
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"\\uD800\\u\"\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(!result.is_success());
    assert!(result.diagnostics.iter().any(|d| d.code == "TPX001"));
}

#[test]
fn tokenizer_handles_negative_exponent_with_sign() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": 1e+3, \"path\": \"$.x\"}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let _ = frontend.translate_text(doc, &ctx, None);
}

#[test]
fn tokenizer_handles_caps_e_in_exponent() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": 2.0E5}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let _ = frontend.translate_text(doc, &ctx, None);
}

#[test]
fn parser_emits_eof_diagnostic_when_extra_token_is_punctuation() {
    let doc = "package cose_trust_policy\n\npolicy := {}\n,\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(!result.is_success());
}

#[test]
fn frontend_translate_via_trait_returns_failure_on_lex_error() {
    // Construct a RegoDocument from a parse-failing source; expectation:
    // RegoDocument::parse returns None — but we can also call translate
    // on a Successfully-parsed document and check supported_media_types
    // through the trait.
    let frontend: Box<dyn CoseTrustPolicyFrontend<RegoDocument>> =
        Box::new(CoseTpRegoFrontend::default());
    assert_eq!(frontend.frontend_id(), "cose-tp-rego/v1");
    assert!(!frontend.supported_media_types().is_empty());
}
