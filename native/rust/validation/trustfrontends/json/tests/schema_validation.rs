// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Schema validation produces TPX001 / TPX100 / TPX101 with the right shape.

use cose_sign1_trust_policy_spec::TrustPolicySeverity;
use cose_sign1_trustfrontends_json::{CoseTpJsonFrontend, TrustPolicyTranslationContext};

fn translate(doc: &str) -> cose_sign1_trust_policy_spec::TrustPolicyTranslationResult {
    CoseTpJsonFrontend::new().translate_text(doc, &TrustPolicyTranslationContext::empty(), None)
}

#[test]
fn malformed_json_emits_tpx001_with_line_column() {
    let doc = "{ this is not valid json }";
    let result = translate(doc);
    assert!(!result.is_success());
    let diag = result
        .diagnostics
        .iter()
        .find(|d| d.code == "TPX001")
        .expect("expected TPX001");
    assert_eq!(diag.severity, TrustPolicySeverity::Error);
    let location = diag.location.as_ref().expect("TPX001 must carry a location");
    assert!(location.line >= 1, "expected a real line number");
}

#[test]
fn unknown_top_level_key_emits_tpx100() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "message": { "allow_all": true },
        "rogue_key": "not-allowed"
    }"#;
    let result = translate(doc);
    assert!(!result.is_success());
    assert!(result.diagnostics.iter().any(|d| d.code == "TPX100"));
}

#[test]
fn wrong_frontend_const_emits_tpx101() {
    let doc = r#"{
        "frontend": "wrong-frontend/v1",
        "message": { "allow_all": true }
    }"#;
    let result = translate(doc);
    assert!(!result.is_success());
    let codes: Vec<&str> = result.diagnostics.iter().map(|d| d.code.as_str()).collect();
    assert!(
        codes.iter().any(|c| *c == "TPX101"),
        "expected TPX101 for /frontend mismatch; got {codes:?}",
    );
}

#[test]
fn missing_anyof_root_scope_emits_tpx100() {
    // Document has no message / primary_signing_key / any_counter_signature — fails the
    // anyOf gate at the root.
    let doc = r#"{
        "frontend": "cose-tp-json/v1"
    }"#;
    let result = translate(doc);
    assert!(!result.is_success());
    assert!(result.diagnostics.iter().any(|d| d.code == "TPX100"));
}

#[test]
fn invalid_predicate_operator_value_emits_tpx100() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-chain-trusted/v1",
            "predicate": { "path": "$.x", "operator": "BogusOperator" }
        }
    }"#;
    let result = translate(doc);
    assert!(!result.is_success());
    assert!(result.diagnostics.iter().any(|d| d.code == "TPX100"));
}
