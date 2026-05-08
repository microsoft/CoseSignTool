// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parameter binding (D5) — pre-bind specs carry $param literals; post-bind specs are
//! literal-free; missing-without-default raises BindError::MissingParameter (TPX400).

use cose_sign1_trust_policy_spec::{
    bind, BindError, FactPredicateSpec, ParameterRef, TrustPolicySpec,
};
use cose_sign1_trustfrontends_json::{CoseTpJsonFrontend, TrustPolicyTranslationContext};
use std::collections::BTreeMap;

const DOC_WITH_PARAM: &str = r#"{
    "frontend": "cose-tp-json/v1",
    "primary_signing_key": {
        "fact": "x509-cert-identity/v1",
        "predicate": { "thumbprint": { "$param": "expected_thumbprint" } }
    }
}"#;

#[test]
fn pre_bind_spec_carries_param_literal() {
    let result = CoseTpJsonFrontend::new().translate_text(
        DOC_WITH_PARAM,
        &TrustPolicyTranslationContext::empty(),
        None,
    );
    assert!(result.is_success());
    let spec = result.spec.unwrap();
    assert!(contains_param_literal(&spec));
}

#[test]
fn post_bind_spec_is_param_free() {
    let result = CoseTpJsonFrontend::new().translate_text(
        DOC_WITH_PARAM,
        &TrustPolicyTranslationContext::empty(),
        None,
    );
    let spec = result.spec.unwrap();
    let mut params = BTreeMap::new();
    params.insert(
        "expected_thumbprint".to_owned(),
        serde_json::Value::String("abc123".to_owned()),
    );
    let bound = bind(spec, &params).expect("bind should succeed");
    assert!(!contains_param_literal(&bound));
}

#[test]
fn missing_parameter_without_default_raises_tpx400() {
    let result = CoseTpJsonFrontend::new().translate_text(
        DOC_WITH_PARAM,
        &TrustPolicyTranslationContext::empty(),
        None,
    );
    let spec = result.spec.unwrap();
    let err = bind(spec, &BTreeMap::new()).expect_err("should fail");
    match err {
        BindError::MissingParameter { name, .. } => assert_eq!(name, "expected_thumbprint"),
        other => panic!("expected MissingParameter, got {other:?}"),
    }
}

#[test]
fn parameter_default_is_used_when_caller_omits_binding() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-cert-identity/v1",
            "predicate": { "thumbprint": { "$param": "expected_thumbprint", "default": "fallback-value" } }
        }
    }"#;
    let result =
        CoseTpJsonFrontend::new().translate_text(doc, &TrustPolicyTranslationContext::empty(), None);
    let spec = result.spec.unwrap();
    let bound = bind(spec, &BTreeMap::new()).expect("default should resolve");
    assert!(!contains_param_literal(&bound));
}

fn contains_param_literal(spec: &TrustPolicySpec) -> bool {
    match spec {
        TrustPolicySpec::AllowAll | TrustPolicySpec::DenyAll { .. } => false,
        TrustPolicySpec::And { specs } | TrustPolicySpec::Or { specs } => {
            specs.iter().any(contains_param_literal)
        }
        TrustPolicySpec::Not { spec, .. } => contains_param_literal(spec),
        TrustPolicySpec::Implies {
            antecedent,
            consequent,
        } => contains_param_literal(antecedent) || contains_param_literal(consequent),
        TrustPolicySpec::Message { requirements }
        | TrustPolicySpec::PrimarySigningKey { requirements }
        | TrustPolicySpec::AnyCounterSignature { requirements, .. } => {
            requirements.iter().any(contains_param_literal)
        }
        TrustPolicySpec::RequireFact { predicate, .. } => predicate_has_param(predicate),
        _ => false,
    }
}

fn predicate_has_param(predicate: &FactPredicateSpec) -> bool {
    match predicate {
        FactPredicateSpec::Property(p) => p.assertions.values().any(value_has_param),
        FactPredicateSpec::PathOperator(po) => po.value.as_ref().is_some_and(value_has_param),
        _ => false,
    }
}

fn value_has_param(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(_) => ParameterRef::try_recognize(value)
            .map(|opt| opt.is_some())
            .unwrap_or(false),
        serde_json::Value::Array(items) => items.iter().any(value_has_param),
        _ => false,
    }
}
