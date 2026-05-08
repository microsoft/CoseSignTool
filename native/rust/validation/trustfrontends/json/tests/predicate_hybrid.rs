// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Predicate hybrid forms (D1) — property-shorthand and path/operator forms produce
//! semantically equivalent specs (modulo the variant tag). The IR's canonical-JSON
//! serializer is byte-stable for each form individually.

use cose_sign1_trust_policy_spec::{to_canonical_json, FactPredicateSpec, TrustPolicySpec};
use cose_sign1_trustfrontends_json::{CoseTpJsonFrontend, TrustPolicyTranslationContext};

fn translate(doc: &str) -> TrustPolicySpec {
    let result = CoseTpJsonFrontend::new().translate_text(
        doc,
        &TrustPolicyTranslationContext::empty(),
        None,
    );
    assert!(result.is_success(), "diag={:?}", result.diagnostics);
    result.spec.expect("ok")
}

fn extract_predicate(spec: &TrustPolicySpec) -> &FactPredicateSpec {
    let TrustPolicySpec::PrimarySigningKey { requirements } = spec else {
        panic!("expected primary_signing_key scope")
    };
    let TrustPolicySpec::RequireFact { predicate, .. } = &requirements[0] else {
        panic!("expected RequireFact")
    };
    predicate
}

#[test]
fn property_shorthand_form_translates_to_property_assertion() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-chain-trusted/v1",
            "predicate": { "is_trusted": true }
        }
    }"#;
    let spec = translate(doc);
    assert!(extract_predicate(&spec).is_property_assertion());
}

#[test]
fn path_operator_form_translates_to_path_operator() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-chain-trusted/v1",
            "predicate": { "path": "$.is_trusted", "operator": "Equals", "value": true }
        }
    }"#;
    let spec = translate(doc);
    assert!(extract_predicate(&spec).is_path_operator());
}

#[test]
fn translation_is_byte_deterministic() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-chain-trusted/v1",
            "predicate": { "is_trusted": true }
        }
    }"#;
    let spec_a = translate(doc);
    let spec_b = translate(doc);
    assert_eq!(spec_a, spec_b);
    let json_a = to_canonical_json(&spec_a).unwrap();
    let json_b = to_canonical_json(&spec_b).unwrap();
    assert_eq!(json_a, json_b);
}
