// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hybrid-predicate equivalence — `PropertyAssertionPredicateSpec` and
//! `PathOperatorPredicateSpec` expressing the same logical assertion compile to plans that
//! agree on `is_trusted` for the same input.
//!
//! Phase 1 cannot evaluate predicates against real facts (Phase 3 ships that), so this
//! file's "equivalence" is structural: both shapes reach the same Phase 1 placeholder rule
//! and both compile-error in the same way for malformed inputs.

use cose_sign1_trust_policy_spec::{
    compile, FactPredicateSpec, PathOperatorPredicateSpec, PredicateOperator,
    PropertyAssertionPredicateSpec, StaticFactRegistry, TrustPolicySpec,
};
use cose_sign1_validation_primitives::evaluation_options::TrustEvaluationOptions;
use cose_sign1_validation_primitives::facts::TrustFactEngine;
use cose_sign1_validation_primitives::subject::TrustSubject;
use serde_json::json;
use std::collections::BTreeMap;

fn run(spec: &TrustPolicySpec) -> bool {
    let registry = StaticFactRegistry::default_mappings();
    let plan = compile(spec, &registry).expect("compile");
    let engine = TrustFactEngine::new(Vec::new());
    let subject = TrustSubject::root("Test", b"hybrid-eq");
    let opts = TrustEvaluationOptions::default();
    plan.evaluate(&engine, &subject, &opts)
        .expect("evaluate")
        .is_trusted
}

#[test]
fn property_assertion_equivalent_to_path_operator_equals() {
    let prop_form = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::Property(PropertyAssertionPredicateSpec {
            assertions: {
                let mut m = BTreeMap::new();
                m.insert("is_trusted".into(), json!(true));
                m
            },
        }),
        "fail",
    );
    let path_form = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::PathOperator(PathOperatorPredicateSpec {
            path: "is_trusted".into(),
            operator: PredicateOperator::Equals,
            value: Some(json!(true)),
        }),
        "fail",
    );

    // Both forms reach the same Phase 1 placeholder rule → same `is_trusted` output.
    assert_eq!(run(&prop_form), run(&path_form));
    assert_eq!(run(&prop_form), false, "Phase 1 placeholder denies");
}

#[test]
fn untagged_serde_routing_is_unambiguous() {
    // Property-assertion shape parses as Property variant, not PathOperator.
    let json = r#"{"assertions":{"k":1}}"#;
    let parsed: FactPredicateSpec = serde_json::from_str(json).unwrap();
    assert!(parsed.is_property_assertion());

    // Path-operator shape parses as PathOperator.
    let json2 = r#"{"path":"a","operator":"exists"}"#;
    let parsed2: FactPredicateSpec = serde_json::from_str(json2).unwrap();
    assert!(parsed2.is_path_operator());
}

#[test]
fn invalid_predicate_shape_fails_to_parse() {
    // Object that matches neither variant should fail (each branch is deny_unknown_fields).
    let json = r#"{"random":"key"}"#;
    let res: Result<FactPredicateSpec, _> = serde_json::from_str(json);
    assert!(res.is_err());
}

#[test]
fn property_assertion_default_constructor_is_empty() {
    let p = PropertyAssertionPredicateSpec::default();
    assert!(p.assertions.is_empty());
}

#[test]
fn property_assertion_builder_chains() {
    let p = PropertyAssertionPredicateSpec::new()
        .with("a", json!(1))
        .with("b", json!("two"));
    assert_eq!(p.assertions.len(), 2);
    assert_eq!(p.assertions.get("a"), Some(&json!(1)));
    assert_eq!(p.assertions.get("b"), Some(&json!("two")));
}

#[test]
fn empty_property_assertion_predicate_compiles_and_denies() {
    // No assertions = vacuously satisfied at the predicate layer, but Phase 1's placeholder
    // still denies (the placeholder doesn't introspect predicate content).
    let spec = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::property_assertions::<_, &str, serde_json::Value>(
            Vec::<(&str, serde_json::Value)>::new(),
        ),
        "fail",
    );
    assert_eq!(run(&spec), false);
}
