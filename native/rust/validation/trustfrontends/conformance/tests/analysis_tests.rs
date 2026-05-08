// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Direct coverage for the public [`analysis`] module helpers
//! ([`collect_fact_ids`], [`contains_param_literal`]).
//!
//! These helpers are exposed for downstream consumers and exercised by every
//! property test indirectly; the unit tests below pin every spec variant the
//! walker handles so a regression on a single arm surfaces as one focused
//! failure.

use cose_sign1_trust_policy_spec::{
    FactPredicateSpec, OnEmptyBehavior, ParameterRef, PathOperatorPredicateSpec,
    PredicateOperator, PropertyAssertionPredicateSpec, TrustPolicySpec,
};
use cose_sign1_trustfrontends_conformance::{collect_fact_ids, contains_param_literal};
use std::collections::BTreeMap;

fn require_fact_simple(id: &str) -> TrustPolicySpec {
    TrustPolicySpec::require_fact(
        id,
        FactPredicateSpec::path_operator("$.x", PredicateOperator::Exists, None),
        format!("require {id}"),
    )
}

fn require_fact_with_param_value(id: &str, name: &str) -> TrustPolicySpec {
    let mut assertions = BTreeMap::new();
    assertions.insert(
        "thumbprint".to_owned(),
        ParameterRef::required(name).to_json(),
    );
    TrustPolicySpec::require_fact(
        id,
        FactPredicateSpec::Property(PropertyAssertionPredicateSpec { assertions }),
        format!("require {id}"),
    )
}

#[test]
fn collect_fact_ids_handles_every_variant() {
    let leaf = require_fact_simple("leaf-fact/v1");
    let inner_a = require_fact_simple("a/v1");
    let inner_b = require_fact_simple("b/v1");

    // AllowAll / DenyAll → no ids.
    assert!(collect_fact_ids(&TrustPolicySpec::AllowAll).is_empty());
    assert!(collect_fact_ids(&TrustPolicySpec::DenyAll {
        reason: "x".into()
    })
    .is_empty());

    // And / Or — recurse into children.
    let and = TrustPolicySpec::and([inner_a.clone(), inner_b.clone()]);
    assert_eq!(
        collect_fact_ids(&and).into_iter().collect::<Vec<_>>(),
        vec!["a/v1", "b/v1"]
    );
    let or = TrustPolicySpec::or([inner_a.clone(), inner_b.clone()]);
    assert_eq!(
        collect_fact_ids(&or).into_iter().collect::<Vec<_>>(),
        vec!["a/v1", "b/v1"]
    );

    // Not / Implies — recurse.
    let not = TrustPolicySpec::not(leaf.clone(), Some("nope".into()));
    assert_eq!(
        collect_fact_ids(&not).into_iter().collect::<Vec<_>>(),
        vec!["leaf-fact/v1"]
    );
    let implies = TrustPolicySpec::implies(inner_a.clone(), inner_b.clone());
    assert_eq!(
        collect_fact_ids(&implies).into_iter().collect::<Vec<_>>(),
        vec!["a/v1", "b/v1"]
    );

    // Message / PrimarySigningKey / AnyCounterSignature — recurse into requirements.
    let msg = TrustPolicySpec::message([leaf.clone()]);
    assert_eq!(
        collect_fact_ids(&msg).into_iter().collect::<Vec<_>>(),
        vec!["leaf-fact/v1"]
    );
    let psk = TrustPolicySpec::primary_signing_key([leaf.clone()]);
    assert_eq!(
        collect_fact_ids(&psk).into_iter().collect::<Vec<_>>(),
        vec!["leaf-fact/v1"]
    );
    let acs = TrustPolicySpec::any_counter_signature(OnEmptyBehavior::Deny, [leaf.clone()]);
    assert_eq!(
        collect_fact_ids(&acs).into_iter().collect::<Vec<_>>(),
        vec!["leaf-fact/v1"]
    );
}

#[test]
fn contains_param_literal_handles_every_variant() {
    let leaf_no_param = require_fact_simple("a/v1");
    let leaf_with_param = require_fact_with_param_value("a/v1", "name");

    // Leaf cases.
    assert!(!contains_param_literal(&TrustPolicySpec::AllowAll));
    assert!(!contains_param_literal(&TrustPolicySpec::DenyAll {
        reason: "x".into()
    }));
    assert!(!contains_param_literal(&leaf_no_param));
    assert!(contains_param_literal(&leaf_with_param));

    // Combinators.
    let and = TrustPolicySpec::and([leaf_no_param.clone(), leaf_with_param.clone()]);
    assert!(contains_param_literal(&and));
    let or = TrustPolicySpec::or([leaf_no_param.clone(), leaf_no_param.clone()]);
    assert!(!contains_param_literal(&or));
    let not = TrustPolicySpec::not(leaf_with_param.clone(), None);
    assert!(contains_param_literal(&not));
    let implies = TrustPolicySpec::implies(leaf_no_param.clone(), leaf_with_param.clone());
    assert!(contains_param_literal(&implies));

    // Scopes.
    let msg = TrustPolicySpec::message([leaf_with_param.clone()]);
    assert!(contains_param_literal(&msg));
    let psk = TrustPolicySpec::primary_signing_key([leaf_no_param.clone()]);
    assert!(!contains_param_literal(&psk));
    let acs = TrustPolicySpec::any_counter_signature(
        OnEmptyBehavior::Allow,
        [leaf_with_param.clone()],
    );
    assert!(contains_param_literal(&acs));
}

#[test]
fn contains_param_literal_detects_path_operator_param_values() {
    // PathOperator with $param value should be detected.
    let predicate = FactPredicateSpec::PathOperator(PathOperatorPredicateSpec {
        path: "$.x".into(),
        operator: PredicateOperator::Equals,
        value: Some(ParameterRef::required("p").to_json()),
    });
    let spec = TrustPolicySpec::require_fact("a/v1", predicate, "msg");
    assert!(contains_param_literal(&spec));

    // PathOperator with no value — Exists-only — must NOT report params.
    let predicate = FactPredicateSpec::path_operator("$.x", PredicateOperator::Exists, None);
    let spec = TrustPolicySpec::require_fact("a/v1", predicate, "msg");
    assert!(!contains_param_literal(&spec));
}

#[test]
fn contains_param_literal_detects_array_nested_params() {
    let mut assertions = BTreeMap::new();
    assertions.insert(
        "tags".to_owned(),
        serde_json::Value::Array(vec![
            serde_json::Value::String("non-param".into()),
            ParameterRef::required("nested").to_json(),
        ]),
    );
    let predicate = FactPredicateSpec::Property(PropertyAssertionPredicateSpec { assertions });
    let spec = TrustPolicySpec::require_fact("a/v1", predicate, "msg");
    assert!(contains_param_literal(&spec));
}

#[test]
fn contains_param_literal_ignores_plain_objects() {
    // A plain JSON object value (without `$param`) must not be misread.
    let mut assertions = BTreeMap::new();
    assertions.insert(
        "metadata".to_owned(),
        serde_json::json!({ "version": 1, "kind": "test" }),
    );
    let predicate = FactPredicateSpec::Property(PropertyAssertionPredicateSpec { assertions });
    let spec = TrustPolicySpec::require_fact("a/v1", predicate, "msg");
    assert!(!contains_param_literal(&spec));
}

#[test]
fn collect_and_contains_handle_deeply_nested_specs() {
    let inner = require_fact_with_param_value("inner/v1", "p");
    let middle = TrustPolicySpec::not(inner, None);
    let outer = TrustPolicySpec::and([
        TrustPolicySpec::or([TrustPolicySpec::implies(
            TrustPolicySpec::AllowAll,
            middle,
        )]),
        TrustPolicySpec::message([require_fact_simple("outer/v1")]),
    ]);

    let ids = collect_fact_ids(&outer);
    assert_eq!(ids.into_iter().collect::<Vec<_>>(), vec!["inner/v1", "outer/v1"]);
    assert!(contains_param_literal(&outer));
}



