// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Translate-smoke tests covering five representative documents.

use cose_sign1_trust_policy_spec::{
    FactPredicateSpec, OnEmptyBehavior, PredicateOperator, TrustPolicySpec,
};
use cose_sign1_trustfrontends_json::{CoseTpJsonFrontend, TrustPolicyTranslationContext};

fn translate(doc: &str) -> TrustPolicySpec {
    let frontend = CoseTpJsonFrontend::new();
    let result =
        frontend.translate_text(doc, &TrustPolicyTranslationContext::empty(), Some("smoke"));
    assert!(
        result.is_success(),
        "translation should succeed for {doc}; diagnostics={:?}",
        result.diagnostics
    );
    result.spec.expect("is_success guarantees Some")
}

#[test]
fn message_with_allow_all() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "message": { "allow_all": true }
    }"#;
    let spec = translate(doc);
    assert!(matches!(
        spec,
        TrustPolicySpec::Message { ref requirements } if requirements.len() == 1
            && matches!(requirements[0], TrustPolicySpec::AllowAll)
    ));
}

#[test]
fn primary_signing_key_with_property_assertion() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-chain-trusted/v1",
            "predicate": { "is_trusted": true }
        }
    }"#;
    let spec = translate(doc);
    let TrustPolicySpec::PrimarySigningKey { requirements } = spec else {
        panic!("expected PrimarySigningKey scope")
    };
    assert_eq!(requirements.len(), 1);
    let TrustPolicySpec::RequireFact {
        fact_id,
        predicate,
        failure_message,
    } = &requirements[0]
    else {
        panic!("expected RequireFact")
    };
    assert_eq!(fact_id, "x509-chain-trusted/v1");
    assert!(predicate.is_property_assertion());
    assert_eq!(
        failure_message,
        "Fact requirement on 'x509-chain-trusted/v1' was not satisfied."
    );
}

#[test]
fn implies_with_explicit_failure_message() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "implies": {
                "antecedent": { "fact": "x509-chain-trusted/v1", "predicate": { "is_trusted": true } },
                "consequent": { "fact": "x509-cert-eku/v1",       "predicate": { "has_codesigning": true }, "failure_message": "Code-signing EKU required." }
            }
        }
    }"#;
    let spec = translate(doc);
    let TrustPolicySpec::PrimarySigningKey { requirements } = spec else {
        panic!("expected PrimarySigningKey scope")
    };
    let inner = &requirements[0];
    assert!(matches!(inner, TrustPolicySpec::Implies { .. }));
}

#[test]
fn any_counter_signature_with_on_empty_allow() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "any_counter_signature": {
            "on_empty": "allow",
            "fact": "mst-receipt-trusted/v1",
            "predicate": { "is_trusted": true }
        }
    }"#;
    let spec = translate(doc);
    let TrustPolicySpec::AnyCounterSignature {
        on_empty,
        requirements,
    } = spec
    else {
        panic!("expected AnyCounterSignature scope")
    };
    assert_eq!(on_empty, OnEmptyBehavior::Allow);
    assert_eq!(requirements.len(), 1);
    assert!(matches!(requirements[0], TrustPolicySpec::RequireFact { .. }));
}

#[test]
fn path_operator_predicate_with_value() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-cert-identity/v1",
            "predicate": { "path": "$.thumbprint", "operator": "Equals", "value": "abc123" }
        }
    }"#;
    let spec = translate(doc);
    let TrustPolicySpec::PrimarySigningKey { requirements } = spec else {
        panic!("expected PrimarySigningKey scope")
    };
    let TrustPolicySpec::RequireFact { predicate, .. } = &requirements[0] else {
        panic!("expected RequireFact")
    };
    let FactPredicateSpec::PathOperator(po) = predicate else {
        panic!("expected path-operator predicate")
    };
    assert_eq!(po.path, "$.thumbprint");
    assert_eq!(po.operator, PredicateOperator::Equals);
    assert_eq!(po.value, Some(serde_json::Value::String("abc123".to_owned())));
}

#[test]
fn top_level_combinator_or_with_two_scopes() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "combinator": "or",
        "message": { "allow_all": true },
        "primary_signing_key": { "allow_all": true }
    }"#;
    let spec = translate(doc);
    let TrustPolicySpec::Or { specs } = spec else {
        panic!("expected Or at the root with combinator=or")
    };
    assert_eq!(specs.len(), 2);
}
