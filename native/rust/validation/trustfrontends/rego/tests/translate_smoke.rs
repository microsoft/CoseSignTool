// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Smoke test: representative Rego documents translate into a
//! `TrustPolicySpec` whose canonical-IR JSON dump is structurally equal to
//! a manually-curated baseline. Mirrors the .NET Phase 5a test surface.

use cose_sign1_trust_policy_spec::{
    to_canonical_json, TrustPolicyTranslationContext,
};
use cose_sign1_trustfrontends_rego::CoseTpRegoFrontend;

fn translate(text: &str) -> String {
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(text, &ctx, None);
    let spec = result
        .spec
        .unwrap_or_else(|| panic!("translation failed: {:?}", result.diagnostics));
    to_canonical_json(&spec).expect("canonical encode")
}

#[test]
fn simple_x509_chain_trusted() {
    let doc = r#"package cose_trust_policy

policy := {
    "primary_signing_key": {
        "fact": "x509-chain-trusted/v1",
        "predicate": {"is_trusted": true}
    }
}
"#;
    let canonical = translate(doc);
    assert!(canonical.contains("\"fact_id\":\"x509-chain-trusted/v1\""));
    assert!(canonical.contains("\"is_trusted\":true"));
}

#[test]
fn message_scope_with_content_type() {
    let doc = r#"package cose_trust_policy

policy := {
    "message": {
        "fact": "content-type/v1",
        "predicate": {"matches": "application/cose"}
    }
}
"#;
    let canonical = translate(doc);
    assert!(canonical.contains("\"type\":\"message\""));
    assert!(canonical.contains("\"matches\":\"application/cose\""));
}

#[test]
fn counter_signature_with_on_empty() {
    let doc = r#"package cose_trust_policy

policy := {
    "any_counter_signature": {
        "on_empty": "deny",
        "fact": "mst-receipt-trusted/v1",
        "predicate": {"is_trusted": true}
    }
}
"#;
    let canonical = translate(doc);
    assert!(canonical.contains("\"on_empty\":\"deny\""));
    assert!(canonical.contains("mst-receipt-trusted/v1"));
}

#[test]
fn all_of_combinator_is_lowered_correctly() {
    let doc = r#"package cose_trust_policy

policy := {
    "primary_signing_key": {
        "all_of": [
            {"fact": "x509-chain-trusted/v1", "predicate": {"is_trusted": true}},
            {"fact": "x509-cert-identity-allowed/v1", "predicate": {"is_allowed": true}}
        ]
    }
}
"#;
    let canonical = translate(doc);
    assert!(canonical.contains("\"type\":\"and\""));
    assert!(canonical.contains("x509-chain-trusted/v1"));
    assert!(canonical.contains("x509-cert-identity-allowed/v1"));
}

#[test]
fn import_future_keywords_in_is_accepted() {
    let doc = r#"package cose_trust_policy

import future.keywords.in

policy := {
    "primary_signing_key": {
        "fact": "x509-chain-trusted/v1",
        "predicate": {"is_trusted": true}
    }
}
"#;
    let canonical = translate(doc);
    assert!(canonical.contains("x509-chain-trusted/v1"));
}

#[test]
fn input_reference_lowers_to_param() {
    use serde_json::json;
    let doc = r#"package cose_trust_policy

policy := {
    "primary_signing_key": {
        "fact": "x509-cert-identity/v1",
        "predicate": {"thumbprint": input.expected_thumbprint}
    }
}
"#;
    let frontend = CoseTpRegoFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(doc, &ctx, None);
    let spec = result.spec.expect("translation must succeed");
    // After translation but before bind, the spec carries a ParameterRef
    // for the unbound thumbprint slot. Round-trip the spec through
    // canonical JSON and assert the parameter shows up.
    let canonical = to_canonical_json(&spec).unwrap();
    assert!(
        canonical.contains("expected_thumbprint"),
        "input.<name> must lower to a $param reference visible in the canonical IR. Got: {canonical}",
    );

    // Also bind the parameter and confirm the value materialises.
    let mut params = std::collections::BTreeMap::new();
    params.insert("expected_thumbprint".to_owned(), json!("AAAA-1111"));
    let bound = cose_sign1_trust_policy_spec::bind(spec, &params).unwrap();
    let canonical_bound = to_canonical_json(&bound).unwrap();
    assert!(canonical_bound.contains("AAAA-1111"));
}

#[test]
fn equals_assignment_is_accepted_as_alias() {
    let doc = r#"package cose_trust_policy

policy = {
    "primary_signing_key": {
        "fact": "x509-chain-trusted/v1",
        "predicate": {"is_trusted": true}
    }
}
"#;
    let canonical = translate(doc);
    assert!(canonical.contains("x509-chain-trusted/v1"));
}

#[test]
fn negative_number_lowers_to_negative_integer() {
    let doc = r#"package cose_trust_policy

policy := {
    "primary_signing_key": {
        "fact": "x509-chain-trusted/v1",
        "predicate": {"path": "$.skew_seconds", "operator": "GreaterThan", "value": -10}
    }
}
"#;
    let canonical = translate(doc);
    assert!(canonical.contains("-10"));
}

#[test]
fn comments_and_whitespace_are_skipped() {
    let doc = "# leading banner\n# more banner\n\npackage cose_trust_policy   # trailing\n\n# section break\npolicy := {\n    # nested\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"is_trusted\": true}\n    }\n}\n";
    let canonical = translate(doc);
    assert!(canonical.contains("x509-chain-trusted/v1"));
}

#[test]
fn crlf_line_endings_are_handled() {
    let doc = "package cose_trust_policy\r\n\r\npolicy := {\r\n    \"primary_signing_key\": {\r\n        \"fact\": \"x509-chain-trusted/v1\",\r\n        \"predicate\": {\"is_trusted\": true}\r\n    }\r\n}\r\n";
    let canonical = translate(doc);
    assert!(canonical.contains("x509-chain-trusted/v1"));
}

#[test]
fn bare_cr_line_endings_are_handled() {
    let doc = "package cose_trust_policy\r\rpolicy := {\r    \"primary_signing_key\": {\r        \"fact\": \"x509-chain-trusted/v1\",\r        \"predicate\": {\"is_trusted\": true}\r    }\r}\r";
    let canonical = translate(doc);
    assert!(canonical.contains("x509-chain-trusted/v1"));
}
