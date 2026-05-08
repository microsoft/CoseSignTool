// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the post-parse parameter substitution pass (D5).

use cose_sign1_trust_policy_spec::{
    bind, BindError, FactPredicateSpec, ParameterRef, PathOperatorPredicateSpec,
    PredicateOperator, TrustPolicySpec,
};
use serde_json::json;
use std::collections::BTreeMap;

fn require_fact_with_param_default(name: &str, default: serde_json::Value) -> TrustPolicySpec {
    TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::PathOperator(PathOperatorPredicateSpec {
            path: "is_trusted".to_owned(),
            operator: PredicateOperator::Equals,
            value: Some(ParameterRef::with_default(name, default).to_json()),
        }),
        "fail",
    )
}

#[test]
fn bind_replaces_param_with_value() {
    let spec = require_fact_with_param_default("p", json!(false));
    let mut params = BTreeMap::new();
    params.insert("p".to_owned(), json!(true));
    let bound = bind(spec, &params).expect("bind");
    if let TrustPolicySpec::RequireFact { predicate, .. } = bound {
        if let FactPredicateSpec::PathOperator(p) = predicate {
            assert_eq!(p.value, Some(json!(true)));
        } else {
            panic!("expected PathOperator");
        }
    } else {
        panic!("expected RequireFact");
    }
}

#[test]
fn bind_uses_default_when_param_missing() {
    let spec = require_fact_with_param_default("not_supplied", json!("fallback"));
    let bound = bind(spec, &BTreeMap::new()).expect("bind uses default");
    // Structural assertion: the outer variant + sibling fields must remain unchanged.
    if let TrustPolicySpec::RequireFact {
        fact_id,
        predicate,
        failure_message,
    } = bound
    {
        assert_eq!(fact_id, "x509-chain-trusted/v1");
        assert_eq!(failure_message, "fail");
        if let FactPredicateSpec::PathOperator(p) = predicate {
            assert_eq!(p.path, "is_trusted");
            assert_eq!(p.operator, PredicateOperator::Equals);
            assert_eq!(p.value, Some(json!("fallback")));
        } else {
            panic!("expected PathOperator");
        }
    } else {
        panic!("expected RequireFact");
    }
}

#[test]
fn bind_missing_without_default_errs() {
    let spec = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::PathOperator(PathOperatorPredicateSpec {
            path: "is_trusted".to_owned(),
            operator: PredicateOperator::Equals,
            value: Some(ParameterRef::required("missing").to_json()),
        }),
        "fail",
    );
    let err = bind(spec, &BTreeMap::new()).unwrap_err();
    match err {
        BindError::MissingParameter { name, location } => {
            assert_eq!(name, "missing");
            assert!(location.contains("require_fact.predicate"));
        }
        other => panic!("wrong error: {other}"),
    }
}

#[test]
fn bind_recurses_into_property_assertions() {
    let spec = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::property_assertions([
            ("is_trusted", ParameterRef::required("trusted").to_json()),
            ("element_count", json!(3)),
        ]),
        "fail",
    );
    let mut params = BTreeMap::new();
    params.insert("trusted".to_owned(), json!(true));
    let bound = bind(spec, &params).unwrap();
    if let TrustPolicySpec::RequireFact { predicate, .. } = bound {
        if let FactPredicateSpec::Property(p) = predicate {
            assert_eq!(p.assertions.get("is_trusted"), Some(&json!(true)));
            assert_eq!(p.assertions.get("element_count"), Some(&json!(3)));
        }
    }
}

#[test]
fn bind_recurses_through_logical_ops_and_scopes() {
    let spec = TrustPolicySpec::and([
        TrustPolicySpec::message([require_fact_with_param_default("a", json!(1))]),
        TrustPolicySpec::not(
            TrustPolicySpec::primary_signing_key([require_fact_with_param_default(
                "b",
                json!(2),
            )]),
            None,
        ),
        TrustPolicySpec::implies(
            require_fact_with_param_default("c", json!(3)),
            TrustPolicySpec::or([require_fact_with_param_default("d", json!(4))]),
        ),
        TrustPolicySpec::any_counter_signature(
            cose_sign1_trust_policy_spec::OnEmptyBehavior::Allow,
            [require_fact_with_param_default("e", json!(5))],
        ),
    ]);
    let mut params = BTreeMap::new();
    params.insert("a".to_owned(), json!(11));
    params.insert("b".to_owned(), json!(22));
    params.insert("c".to_owned(), json!(33));
    params.insert("d".to_owned(), json!(44));
    params.insert("e".to_owned(), json!(55));
    let bound = bind(spec, &params).expect("bind across full tree");
    let serialized = serde_json::to_string(&bound).unwrap();
    for v in [11, 22, 33, 44, 55] {
        assert!(serialized.contains(&v.to_string()), "{v} substituted");
    }
    assert!(!serialized.contains("$param"), "no parameter literals remain");
}

#[test]
fn bind_recurses_into_array_and_object_values() {
    // ParameterRef inside a nested structure: an array containing a $param object.
    let predicate = FactPredicateSpec::PathOperator(PathOperatorPredicateSpec {
        path: "allowed".to_owned(),
        operator: PredicateOperator::In,
        value: Some(json!([
            "static",
            {"$param": "dynamic"},
            { "nested": {"$param": "deep", "default": "fallback"} }
        ])),
    });
    let spec = TrustPolicySpec::require_fact("x509-chain-trusted/v1", predicate, "fail");
    let mut params = BTreeMap::new();
    params.insert("dynamic".to_owned(), json!("from-bind"));
    let bound = bind(spec, &params).unwrap();
    let json = serde_json::to_string(&bound).unwrap();
    assert!(json.contains("from-bind"));
    assert!(json.contains("fallback")); // default used
    assert!(!json.contains("$param"));
}

#[test]
fn parameter_ref_malformed_extra_keys_rejected() {
    // `$param` literal carrying an unexpected co-key fails fast.
    let value = json!({"$param": "x", "default": 1, "rogue": true});
    let err = ParameterRef::try_recognize(&value).unwrap_err();
    assert!(matches!(err, BindError::Malformed { .. }));
}

#[test]
fn parameter_ref_with_non_string_name_rejected() {
    let value = json!({"$param": 123});
    let err = ParameterRef::try_recognize(&value).unwrap_err();
    assert!(matches!(err, BindError::Malformed { .. }));
    assert!(format!("{err}").contains("must be a string"));
}

#[test]
fn parameter_ref_object_without_marker_passes_through() {
    let value = json!({"hello": "world"});
    let recognized = ParameterRef::try_recognize(&value).unwrap();
    assert!(recognized.is_none());
}

#[test]
fn bind_preserves_non_param_values_unchanged() {
    let spec = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::PathOperator(PathOperatorPredicateSpec {
            path: "depth".to_owned(),
            operator: PredicateOperator::LessThan,
            value: Some(json!(5)),
        }),
        "deep",
    );
    let bound = bind(spec.clone(), &BTreeMap::new()).unwrap();
    assert_eq!(bound, spec, "no params → no changes");
}

#[test]
fn bind_error_display_emits_location() {
    let err = BindError::MissingParameter {
        name: "p".into(),
        location: "require_fact.predicate.value".into(),
    };
    let s = format!("{err}");
    assert!(s.contains("p"));
    assert!(s.contains("require_fact.predicate.value"));
    assert!(s.contains("TPX400"), "TPX code present: {s}");
    assert_eq!(err.code(), "TPX400");

    let no_loc = BindError::MissingParameter {
        name: "p".into(),
        location: "".into(),
    };
    let s2 = format!("{no_loc}");
    assert!(s2.contains("p") && !s2.contains(" at "));
    assert!(s2.contains("TPX400"));

    let malformed = BindError::Malformed {
        detail: "bad".into(),
    };
    assert!(format!("{malformed}").contains("bad"));
    assert!(format!("{malformed}").contains("TPX401"));
    assert_eq!(malformed.code(), "TPX401");

    let recursion = BindError::RecursionLimitExceeded { limit: 5 };
    let s3 = format!("{recursion}");
    assert!(s3.contains("TPX301") && s3.contains("5"));
    assert_eq!(recursion.code(), "TPX301");
}

#[test]
fn allow_deny_allowall_specs_unchanged_by_bind() {
    // Specs without parameter-bearing slots should pass through untouched.
    let cases = vec![
        TrustPolicySpec::AllowAll,
        TrustPolicySpec::DenyAll {
            reason: "always".into(),
        },
        TrustPolicySpec::and([TrustPolicySpec::AllowAll, TrustPolicySpec::AllowAll]),
        TrustPolicySpec::or([TrustPolicySpec::AllowAll]),
        TrustPolicySpec::message([TrustPolicySpec::AllowAll]),
        TrustPolicySpec::primary_signing_key([TrustPolicySpec::AllowAll]),
        TrustPolicySpec::any_counter_signature(
            cose_sign1_trust_policy_spec::OnEmptyBehavior::Deny,
            [TrustPolicySpec::AllowAll],
        ),
        TrustPolicySpec::not(TrustPolicySpec::AllowAll, Some("nope".into())),
        TrustPolicySpec::implies(TrustPolicySpec::AllowAll, TrustPolicySpec::AllowAll),
    ];
    for spec in cases {
        let bound = bind(spec.clone(), &BTreeMap::new()).expect("bind no-op");
        assert_eq!(spec, bound);
    }
}

#[test]
fn bind_recursion_limit_enforced() {
    use cose_sign1_trust_policy_spec::{bind_with_options, BindOptions};

    fn nest(n: usize) -> TrustPolicySpec {
        if n == 0 {
            TrustPolicySpec::AllowAll
        } else {
            TrustPolicySpec::and([nest(n - 1)])
        }
    }
    let deep = nest(50);
    let err = match bind_with_options(deep, &BTreeMap::new(), &BindOptions::with_max_depth(16)) {
        Ok(_) => panic!("expected RecursionLimitExceeded"),
        Err(e) => e,
    };
    assert!(matches!(err, BindError::RecursionLimitExceeded { .. }));
    assert_eq!(err.code(), "TPX301");
}

#[test]
fn bind_recursion_limit_via_deeply_nested_value() {
    // A deeply nested JSON Value should also trip the depth cap.
    use cose_sign1_trust_policy_spec::{bind_with_options, BindOptions, FactPredicateSpec, PathOperatorPredicateSpec, PredicateOperator};

    let mut value = serde_json::json!(0);
    for _ in 0..100 {
        value = serde_json::Value::Array(vec![value]);
    }
    let spec = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::PathOperator(PathOperatorPredicateSpec {
            path: "p".into(),
            operator: PredicateOperator::Equals,
            value: Some(value),
        }),
        "x",
    );
    let err = match bind_with_options(spec, &BTreeMap::new(), &BindOptions::with_max_depth(32)) {
        Ok(_) => panic!("expected RecursionLimitExceeded"),
        Err(e) => e,
    };
    assert!(matches!(err, BindError::RecursionLimitExceeded { .. }));
}

#[test]
fn bind_options_default_matches_const() {
    use cose_sign1_trust_policy_spec::{BindOptions, BIND_DEFAULT_MAX_DEPTH};
    assert_eq!(BindOptions::default().max_depth, BIND_DEFAULT_MAX_DEPTH);
}

#[test]
fn parameter_ref_object_with_marker_but_no_object_passes_through() {
    // serde_json::Value::Bool isn't an object so try_recognize returns Ok(None).
    use cose_sign1_trust_policy_spec::ParameterRef;
    let recognized = ParameterRef::try_recognize(&serde_json::json!(true)).unwrap();
    assert!(recognized.is_none());
}

#[test]
fn parameter_ref_to_json_round_trip() {
    let pref = ParameterRef::with_default("p", json!(7));
    let value = pref.to_json();
    let recognized = ParameterRef::try_recognize(&value).unwrap().unwrap();
    assert_eq!(recognized, pref);

    let required = ParameterRef::required("q");
    let value = required.to_json();
    assert!(!value.as_object().unwrap().contains_key("default"));
    let recognized = ParameterRef::try_recognize(&value).unwrap().unwrap();
    assert_eq!(recognized.name, "q");
    assert!(recognized.default.is_none());
}
