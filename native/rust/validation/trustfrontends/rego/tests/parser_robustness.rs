// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parser robustness — malformed inputs, edge-case unicode, and
//! diagnostics should never panic.

use cose_sign1_trust_policy_spec::TrustPolicyTranslationContext;
use cose_sign1_trustfrontends_rego::CoseTpRegoFrontend;

fn translate(text: &str) {
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let _ = frontend.translate_text(text, &ctx, None);
}

#[test]
fn empty_document_does_not_panic() {
    translate("");
}

#[test]
fn whitespace_only_does_not_panic() {
    translate("   \n\n  \t  \n");
}

#[test]
fn comment_only_document_does_not_panic() {
    translate("# just a banner\n# more banner\n");
}

#[test]
fn unicode_in_identifier_position_does_not_panic() {
    translate("package cose_trust_policy\n\npolicy := {\"naïve\": 1}\n");
}

#[test]
fn unicode_in_string_value_is_accepted() {
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-cert-identity/v1\",\n        \"predicate\": {\"thumbprint\": \"日本語🎌\"}\n    }\n}\n";
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(
        result.spec.is_some(),
        "valid Unicode string content must translate successfully; diagnostics={:?}",
        result.diagnostics,
    );
}

#[test]
fn emoji_via_surrogate_pair_escape_round_trips() {
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    // U+1F389 PARTY POPPER as \uD83C\uDF89 surrogate pair.
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-cert-identity/v1\",\n        \"predicate\": {\"thumbprint\": \"\\uD83C\\uDF89\"}\n    }\n}\n";
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(
        result.spec.is_some(),
        "valid surrogate-pair escape must round-trip; diagnostics={:?}",
        result.diagnostics,
    );
}

#[test]
fn unterminated_object_produces_diagnostic_not_panic() {
    translate("package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n");
}

#[test]
fn unterminated_array_produces_diagnostic_not_panic() {
    translate("package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": [\n");
}

#[test]
fn stray_punctuation_produces_diagnostic_not_panic() {
    translate("package cose_trust_policy\n\npolicy := !!!@#$%\n");
}

#[test]
fn tokenizer_handles_mixed_eol_within_one_document() {
    let doc = "package cose_trust_policy\r\n\npolicy := {\r    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\r\n        \"predicate\": {\"is_trusted\": true}\n    }\r}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(
        result.spec.is_some(),
        "mixed EOL document must translate; diagnostics={:?}",
        result.diagnostics,
    );
}

#[test]
fn missing_colon_in_object_entry_produces_tpx001() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\" 123\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(result.spec.is_none());
    assert!(result.diagnostics.iter().any(|d| d.code == "TPX001"));
}

#[test]
fn input_must_be_followed_by_dot_identifier() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-cert-identity/v1\",\n        \"predicate\": {\"thumbprint\": input}\n    }\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    assert!(result.spec.is_none());
    assert!(result.diagnostics.iter().any(|d| d.code == "TPX001"));
}

#[test]
fn document_carries_source_pointer_into_diagnostics() {
    let doc = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": invalid\n}\n";
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, Some("file:///etc/myapp.coseTrustPolicy.rego"));
    assert!(result.spec.is_none());
    let diag = result
        .diagnostics
        .iter()
        .find(|d| d.code == "TPX300")
        .expect("expected TPX300 for unknown identifier");
    let loc = diag.location.as_ref().expect("location present");
    assert!(loc.line >= 1 && loc.column >= 1);
}

#[test]
fn sniff_media_type_recognises_extension() {
    assert_eq!(
        cose_sign1_trustfrontends_rego::sniff_media_type(
            Some("policy.coseTrustPolicy.rego"),
            None,
        ),
        Some("application/x-cose-trust-policy+rego"),
    );
}

#[test]
fn sniff_media_type_recognises_package_header() {
    assert_eq!(
        cose_sign1_trustfrontends_rego::sniff_media_type(
            None,
            Some("# header banner\n\npackage cose_trust_policy\npolicy := {}\n"),
        ),
        Some("application/x-cose-trust-policy+rego"),
    );
}

#[test]
fn sniff_media_type_returns_none_for_json() {
    assert_eq!(
        cose_sign1_trustfrontends_rego::sniff_media_type(
            Some("policy.coseTrustPolicy.json"),
            Some("{\"frontend\": \"cose-tp-json/v1\"}\n"),
        ),
        None,
    );
}
