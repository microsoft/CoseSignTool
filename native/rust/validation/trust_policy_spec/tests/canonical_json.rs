// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Determinism contract — same `(spec, params)` produces byte-identical canonical JSON
//! across thousands of iterations and across permutations of construction order.

use cose_sign1_trust_policy_spec::{
    bind, to_canonical_json, FactPredicateSpec, OnEmptyBehavior, ParameterRef, PredicateOperator,
    PropertyAssertionPredicateSpec, TrustPolicySpec,
};
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn canonical_json_is_byte_stable_across_1000_iterations() {
    let spec = TrustPolicySpec::and([
        TrustPolicySpec::message([TrustPolicySpec::AllowAll]),
        TrustPolicySpec::primary_signing_key([TrustPolicySpec::AllowAll]),
        TrustPolicySpec::any_counter_signature(
            OnEmptyBehavior::Allow,
            [TrustPolicySpec::require_fact(
                "x509-chain-trusted/v1",
                FactPredicateSpec::property_assertions([
                    ("z", json!(1)),
                    ("m", json!("hello")),
                    ("a", json!(true)),
                ]),
                "fail",
            )],
        ),
    ]);

    let baseline = to_canonical_json(&spec).expect("serialize");
    for _ in 0..1000 {
        let again = to_canonical_json(&spec).expect("serialize");
        assert_eq!(again, baseline, "byte-stable across iterations");
    }
}

#[test]
fn canonical_json_independent_of_btree_insertion_order() {
    // Two assertion sets with the same logical content but different insertion orders must
    // serialize identically (BTreeMap → sorted iteration).
    let mut assertions_a: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    assertions_a.insert("zeta".into(), json!(1));
    assertions_a.insert("alpha".into(), json!(2));
    assertions_a.insert("middle".into(), json!(3));

    let mut assertions_b: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    assertions_b.insert("middle".into(), json!(3));
    assertions_b.insert("alpha".into(), json!(2));
    assertions_b.insert("zeta".into(), json!(1));

    let spec_a = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::Property(PropertyAssertionPredicateSpec {
            assertions: assertions_a,
        }),
        "x",
    );
    let spec_b = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::Property(PropertyAssertionPredicateSpec {
            assertions: assertions_b,
        }),
        "x",
    );

    let json_a = to_canonical_json(&spec_a).unwrap();
    let json_b = to_canonical_json(&spec_b).unwrap();
    assert_eq!(json_a, json_b);
}

#[test]
fn canonical_json_post_bind_is_deterministic() {
    let spec = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::property_assertions([
            ("a", ParameterRef::with_default("a", json!(1)).to_json()),
            ("b", ParameterRef::with_default("b", json!(2)).to_json()),
        ]),
        "x",
    );

    let mut params = BTreeMap::new();
    params.insert("a".to_owned(), json!(11));
    params.insert("b".to_owned(), json!(22));

    let bound1 = bind(spec.clone(), &params).unwrap();
    let bound2 = bind(spec, &params).unwrap();
    assert_eq!(bound1, bound2);
    assert_eq!(
        to_canonical_json(&bound1).unwrap(),
        to_canonical_json(&bound2).unwrap()
    );
}

#[test]
fn pretty_form_round_trips_to_same_value_as_canonical() {
    let spec = TrustPolicySpec::and([
        TrustPolicySpec::AllowAll,
        TrustPolicySpec::DenyAll { reason: "x".into() },
    ]);
    let pretty = cose_sign1_trust_policy_spec::to_canonical_pretty(&spec).unwrap();
    let canonical = to_canonical_json(&spec).unwrap();
    let from_pretty: TrustPolicySpec = serde_json::from_str(&pretty).unwrap();
    let from_canonical: TrustPolicySpec = serde_json::from_str(&canonical).unwrap();
    assert_eq!(from_pretty, from_canonical);
    // Pretty must contain whitespace; canonical must not.
    assert!(pretty.contains('\n'));
    assert!(!canonical.contains('\n'));
}

#[test]
fn canonical_json_handles_empty_collections() {
    let spec = TrustPolicySpec::and([]);
    let json = to_canonical_json(&spec).unwrap();
    assert_eq!(json, r#"{"type":"and","specs":[]}"#);
}

#[test]
fn canonical_json_emits_predicate_operator_in_snake_case() {
    let cases = [
        (PredicateOperator::Exists, "exists"),
        (PredicateOperator::Equals, "equals"),
        (PredicateOperator::NotEquals, "not_equals"),
        (PredicateOperator::LessThan, "less_than"),
        (PredicateOperator::LessThanOrEqual, "less_than_or_equal"),
        (PredicateOperator::GreaterThan, "greater_than"),
        (PredicateOperator::GreaterThanOrEqual, "greater_than_or_equal"),
        (PredicateOperator::StartsWith, "starts_with"),
        (PredicateOperator::EndsWith, "ends_with"),
        (PredicateOperator::Contains, "contains"),
        (PredicateOperator::In, "in"),
    ];
    for (op, expected) in cases {
        let json = serde_json::to_string(&op).unwrap();
        assert_eq!(json, format!("\"{expected}\""), "operator {op:?}");
        let parsed: PredicateOperator = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, op);
    }
}

#[test]
fn predicate_is_property_vs_path_helpers() {
    let prop =
        FactPredicateSpec::property_assertions([("a", json!(1))]);
    assert!(prop.is_property_assertion());
    assert!(!prop.is_path_operator());

    let path = FactPredicateSpec::path_operator("p", PredicateOperator::Exists, None);
    assert!(!path.is_property_assertion());
    assert!(path.is_path_operator());

    assert!(PredicateOperator::Exists.is_presence_only());
    assert!(!PredicateOperator::Equals.is_presence_only());
}
