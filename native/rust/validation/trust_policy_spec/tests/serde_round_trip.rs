// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Round-trip serde tests for [`TrustPolicySpec`] and supporting types.
//!
//! Every variant must (a) deserialize into the same value it serializes from and (b)
//! produce **byte-identical** JSON across re-serialization passes (the determinism contract
//! that backs cache-key stability — D9).

use cose_sign1_trust_policy_spec::{
    to_canonical_json, FactPredicateSpec, OnEmptyBehavior, ParameterRef, PredicateOperator,
    PropertyAssertionPredicateSpec, SourceLocation, TrustPolicySpec,
};
use serde_json::json;

fn round_trip(spec: &TrustPolicySpec) -> TrustPolicySpec {
    let serialized = to_canonical_json(spec).expect("serialize");
    let parsed: TrustPolicySpec = serde_json::from_str(&serialized).expect("parse");
    let reserialized = to_canonical_json(&parsed).expect("re-serialize");
    assert_eq!(
        serialized, reserialized,
        "byte-identical reserialization (canonical determinism)"
    );
    parsed
}

#[test]
fn allow_all_round_trip() {
    let spec = TrustPolicySpec::AllowAll;
    let parsed = round_trip(&spec);
    assert_eq!(spec, parsed);
    assert_eq!(to_canonical_json(&spec).unwrap(), r#"{"type":"allow_all"}"#);
}

#[test]
fn deny_all_round_trip() {
    let spec = TrustPolicySpec::DenyAll {
        reason: "explicit deny".to_owned(),
    };
    let parsed = round_trip(&spec);
    assert_eq!(spec, parsed);
}

#[test]
fn and_round_trip_preserves_order() {
    let spec = TrustPolicySpec::and([
        TrustPolicySpec::AllowAll,
        TrustPolicySpec::DenyAll {
            reason: "a".into(),
        },
        TrustPolicySpec::DenyAll {
            reason: "b".into(),
        },
    ]);
    let parsed = round_trip(&spec);
    assert_eq!(spec, parsed);
    // Order is semantically meaningful for short-circuit evaluation.
    let json = to_canonical_json(&spec).unwrap();
    let pos_a = json.find(r#""reason":"a""#).expect("a present");
    let pos_b = json.find(r#""reason":"b""#).expect("b present");
    assert!(pos_a < pos_b, "vector order preserved");
}

#[test]
fn or_round_trip() {
    let spec = TrustPolicySpec::or([
        TrustPolicySpec::AllowAll,
        TrustPolicySpec::DenyAll {
            reason: "x".into(),
        },
    ]);
    assert_eq!(spec, round_trip(&spec));
}

#[test]
fn not_with_reason_round_trip() {
    let spec = TrustPolicySpec::not(TrustPolicySpec::AllowAll, Some("never trust".into()));
    assert_eq!(spec, round_trip(&spec));
}

#[test]
fn not_without_reason_omits_field() {
    let spec = TrustPolicySpec::not(TrustPolicySpec::AllowAll, None);
    let json = to_canonical_json(&spec).unwrap();
    assert!(!json.contains("reason"), "skip_serializing_if elided field");
    assert_eq!(spec, round_trip(&spec));
}

#[test]
fn implies_round_trip() {
    let spec = TrustPolicySpec::implies(
        TrustPolicySpec::AllowAll,
        TrustPolicySpec::DenyAll {
            reason: "c".into(),
        },
    );
    assert_eq!(spec, round_trip(&spec));
}

#[test]
fn message_round_trip() {
    let spec = TrustPolicySpec::message([TrustPolicySpec::AllowAll]);
    assert_eq!(spec, round_trip(&spec));
}

#[test]
fn primary_signing_key_round_trip() {
    let spec = TrustPolicySpec::primary_signing_key([TrustPolicySpec::AllowAll]);
    assert_eq!(spec, round_trip(&spec));
}

#[test]
fn any_counter_signature_round_trip_explicit_allow() {
    let spec = TrustPolicySpec::any_counter_signature(
        OnEmptyBehavior::Allow,
        [TrustPolicySpec::AllowAll],
    );
    let parsed = round_trip(&spec);
    assert_eq!(spec, parsed);
    let json = to_canonical_json(&spec).unwrap();
    assert!(json.contains(r#""on_empty":"allow""#));
}

#[test]
fn any_counter_signature_default_on_empty_is_deny() {
    // Document with on_empty omitted should parse as Deny (the default).
    let json = r#"{"type":"any_counter_signature","requirements":[{"type":"allow_all"}]}"#;
    let spec: TrustPolicySpec = serde_json::from_str(json).expect("parse");
    if let TrustPolicySpec::AnyCounterSignature { on_empty, .. } = &spec {
        assert_eq!(*on_empty, OnEmptyBehavior::Deny);
    } else {
        panic!("expected AnyCounterSignature");
    }
}

#[test]
fn require_fact_with_property_assertion_round_trip() {
    let spec = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::property_assertions([
            ("is_trusted", json!(true)),
            ("element_count", json!(3)),
        ]),
        "chain not trusted",
    );
    let parsed = round_trip(&spec);
    assert_eq!(spec, parsed);
}

#[test]
fn require_fact_with_path_operator_round_trip() {
    let spec = TrustPolicySpec::require_fact(
        "mst-receipt-trusted/v1",
        FactPredicateSpec::path_operator(
            "issuer",
            PredicateOperator::StartsWith,
            Some(json!("https://contoso.example/")),
        ),
        "receipt issuer not contoso",
    );
    let parsed = round_trip(&spec);
    assert_eq!(spec, parsed);
}

#[test]
fn require_fact_exists_predicate_omits_value() {
    let spec = TrustPolicySpec::require_fact(
        "mst-receipt-present/v1",
        FactPredicateSpec::path_operator("present", PredicateOperator::Exists, None),
        "receipt missing",
    );
    let json = to_canonical_json(&spec).unwrap();
    assert!(!json.contains(r#""value""#), "skip_serializing_if elided value");
    assert_eq!(spec, round_trip(&spec));
}

#[test]
fn deny_unknown_fields_rejects_typos() {
    let bad = r#"{"type":"deny_all","reason":"x","extra":"y"}"#;
    let res: Result<TrustPolicySpec, _> = serde_json::from_str(bad);
    assert!(res.is_err(), "deny_unknown_fields rejected the typo");
}

#[test]
fn deeply_nested_round_trip() {
    let spec = TrustPolicySpec::and([
        TrustPolicySpec::not(
            TrustPolicySpec::or([
                TrustPolicySpec::message([TrustPolicySpec::primary_signing_key([
                    TrustPolicySpec::AllowAll,
                ])]),
                TrustPolicySpec::any_counter_signature(
                    OnEmptyBehavior::Allow,
                    [TrustPolicySpec::implies(
                        TrustPolicySpec::AllowAll,
                        TrustPolicySpec::DenyAll {
                            reason: "deep".into(),
                        },
                    )],
                ),
            ]),
            Some("not the negation".into()),
        ),
    ]);
    assert_eq!(spec, round_trip(&spec));
}

#[test]
fn parameter_ref_round_trip() {
    let pref = ParameterRef::with_default("max_chain_length", json!(5));
    let json = serde_json::to_string(&pref).unwrap();
    assert!(json.contains(r#""$param":"max_chain_length""#));
    let parsed: ParameterRef = serde_json::from_str(&json).unwrap();
    assert_eq!(pref, parsed);
}

#[test]
fn property_assertion_predicate_keys_emit_in_sorted_order() {
    // BTreeMap iteration is sorted — the canonical form encodes "a" before "b" regardless of
    // insertion order.
    let mut a_first = PropertyAssertionPredicateSpec::new();
    a_first = a_first.with("z", json!(1));
    a_first = a_first.with("a", json!(2));

    let json = serde_json::to_string(&a_first).unwrap();
    let pos_a = json.find(r#""a""#).unwrap();
    let pos_z = json.find(r#""z""#).unwrap();
    assert!(pos_a < pos_z, "BTreeMap sorted output");
}

#[test]
fn variant_tag_string_matches_serialization() {
    let cases = [
        (TrustPolicySpec::AllowAll, "allow_all"),
        (
            TrustPolicySpec::DenyAll {
                reason: "x".into(),
            },
            "deny_all",
        ),
        (TrustPolicySpec::and([]), "and"),
        (TrustPolicySpec::or([]), "or"),
        (
            TrustPolicySpec::not(TrustPolicySpec::AllowAll, None),
            "not",
        ),
        (
            TrustPolicySpec::implies(TrustPolicySpec::AllowAll, TrustPolicySpec::AllowAll),
            "implies",
        ),
        (TrustPolicySpec::message([]), "message"),
        (
            TrustPolicySpec::primary_signing_key([]),
            "primary_signing_key",
        ),
        (
            TrustPolicySpec::any_counter_signature(OnEmptyBehavior::Deny, []),
            "any_counter_signature",
        ),
        (
            TrustPolicySpec::require_fact(
                "x509-chain-trusted/v1",
                FactPredicateSpec::property_assertions::<_, &str, serde_json::Value>(
                    Vec::<(&str, serde_json::Value)>::new(),
                ),
                "x",
            ),
            "require_fact",
        ),
    ];
    for (spec, tag) in cases {
        assert_eq!(spec.variant_tag(), tag);
        let json = to_canonical_json(&spec).unwrap();
        assert!(
            json.contains(&format!(r#""type":"{tag}""#)),
            "tag {tag} present in {json}"
        );
    }
}

#[test]
fn source_location_round_trip() {
    let loc = SourceLocation::at_offset(12, 7, 314);
    let json = serde_json::to_string(&loc).unwrap();
    let parsed: SourceLocation = serde_json::from_str(&json).unwrap();
    assert_eq!(loc, parsed);
    let no_offset = SourceLocation::at(1, 1);
    let json = serde_json::to_string(&no_offset).unwrap();
    assert!(!json.contains("byte_offset"));
    assert_eq!(no_offset, serde_json::from_str(&json).unwrap());
    assert_eq!(format!("{}", loc), "line 12 column 7");
}
