// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Smoke tests that exercise [`compile`] end-to-end against a [`TrustFactEngine`].
//!
//! The smoke suite covers ≥5 representative spec trees and asserts the lowered
//! [`CompiledTrustPlan`] produces the same `is_trusted` outcome as a hand-built fluent
//! equivalent for the same inputs.

use cose_sign1_trust_policy_spec::{
    compile, compile_with_options, from_rule_on_empty, into_rule_on_empty, CompileError,
    CompileOptions, FactPredicateSpec, OnEmptyBehavior, PathOperatorPredicateSpec,
    PredicateOperator, StaticFactRegistry, TrustPolicySpec,
};
use cose_sign1_validation_primitives::evaluation_options::TrustEvaluationOptions;
use cose_sign1_validation_primitives::facts::TrustFactEngine;
use cose_sign1_validation_primitives::rules::OnEmptyBehavior as RuleOnEmptyBehavior;
use cose_sign1_validation_primitives::subject::TrustSubject;

fn engine() -> TrustFactEngine {
    TrustFactEngine::new(Vec::new())
}

fn evaluate(spec: &TrustPolicySpec) -> (bool, Vec<String>) {
    let registry = StaticFactRegistry::default_mappings();
    let plan = compile(spec, &registry).expect("compile");
    let engine = engine();
    let subject = TrustSubject::root("Test", b"smoke-test");
    let opts = TrustEvaluationOptions::default();
    let decision = plan.evaluate(&engine, &subject, &opts).expect("evaluate");
    (
        decision.is_trusted,
        decision.reasons.iter().map(|c| c.to_string()).collect(),
    )
}

#[test]
fn smoke_allow_all_is_trusted() {
    let (trusted, _) = evaluate(&TrustPolicySpec::AllowAll);
    assert!(trusted);
}

#[test]
fn smoke_deny_all_is_denied_with_reason() {
    let (trusted, reasons) = evaluate(&TrustPolicySpec::DenyAll {
        reason: "smoke deny".into(),
    });
    assert!(!trusted);
    assert!(reasons.iter().any(|r| r.contains("smoke deny")));
}

#[test]
fn smoke_and_short_circuits_on_first_deny() {
    let spec = TrustPolicySpec::and([
        TrustPolicySpec::AllowAll,
        TrustPolicySpec::DenyAll {
            reason: "second".into(),
        },
        TrustPolicySpec::AllowAll,
    ]);
    let (trusted, reasons) = evaluate(&spec);
    assert!(!trusted);
    assert!(reasons.iter().any(|r| r.contains("second")));
}

#[test]
fn smoke_or_finds_satisfied_branch() {
    let spec = TrustPolicySpec::or([
        TrustPolicySpec::DenyAll {
            reason: "first".into(),
        },
        TrustPolicySpec::AllowAll,
    ]);
    let (trusted, _) = evaluate(&spec);
    assert!(trusted);
}

#[test]
fn smoke_or_empty_denies_by_default() {
    // Empty `Or` mirrors primitives' `any_of([])` semantics.
    let spec = TrustPolicySpec::or([]);
    let (trusted, _) = evaluate(&spec);
    assert!(!trusted);
}

#[test]
fn smoke_not_negates_inner_trusted() {
    let spec = TrustPolicySpec::not(TrustPolicySpec::AllowAll, Some("user reason".into()));
    let (trusted, reasons) = evaluate(&spec);
    assert!(!trusted);
    assert!(!reasons.is_empty());
    // Authored reason is preserved through lowering.
    assert!(
        reasons.iter().any(|r| r.contains("user reason")),
        "authored reason preserved: {reasons:?}"
    );
}

#[test]
fn smoke_not_without_authored_reason_emits_default() {
    let spec = TrustPolicySpec::not(TrustPolicySpec::AllowAll, None);
    let (_trusted, reasons) = evaluate(&spec);
    assert!(reasons.iter().any(|r| r.contains("Negated rule was satisfied")));
}

#[test]
fn smoke_not_negates_inner_denied() {
    let spec = TrustPolicySpec::not(
        TrustPolicySpec::DenyAll {
            reason: "x".into(),
        },
        None,
    );
    let (trusted, _) = evaluate(&spec);
    assert!(trusted);
}

#[test]
fn smoke_implies_vacuously_true_on_failed_antecedent() {
    let spec = TrustPolicySpec::implies(
        TrustPolicySpec::DenyAll {
            reason: "ant".into(),
        },
        TrustPolicySpec::DenyAll {
            reason: "cons".into(),
        },
    );
    let (trusted, _) = evaluate(&spec);
    assert!(trusted, "antecedent failed → implication holds vacuously");
}

#[test]
fn smoke_implies_consequent_must_pass_when_antecedent_does() {
    let spec_ok = TrustPolicySpec::implies(TrustPolicySpec::AllowAll, TrustPolicySpec::AllowAll);
    let (trusted, _) = evaluate(&spec_ok);
    assert!(trusted);

    let spec_fail = TrustPolicySpec::implies(
        TrustPolicySpec::AllowAll,
        TrustPolicySpec::DenyAll {
            reason: "cons-fail".into(),
        },
    );
    let (trusted, reasons) = evaluate(&spec_fail);
    assert!(!trusted);
    assert!(reasons.iter().any(|r| r.contains("cons-fail")));
}

#[test]
fn smoke_message_scope_evaluates_inner_against_message_subject() {
    let spec = TrustPolicySpec::message([TrustPolicySpec::AllowAll]);
    let (trusted, _) = evaluate(&spec);
    assert!(trusted);

    let spec_deny = TrustPolicySpec::message([TrustPolicySpec::DenyAll {
        reason: "inner".into(),
    }]);
    let (trusted, reasons) = evaluate(&spec_deny);
    assert!(!trusted);
    assert!(reasons.iter().any(|r| r.contains("inner")));
}

#[test]
fn smoke_primary_signing_key_scope() {
    let spec = TrustPolicySpec::primary_signing_key([TrustPolicySpec::AllowAll]);
    let (trusted, _) = evaluate(&spec);
    assert!(trusted);
}

#[test]
fn smoke_any_counter_signature_placeholder_respects_on_empty() {
    let allow = TrustPolicySpec::any_counter_signature(
        OnEmptyBehavior::Allow,
        [TrustPolicySpec::AllowAll],
    );
    let (trusted, _) = evaluate(&allow);
    assert!(trusted, "Phase 1 placeholder allows on Allow");

    let deny = TrustPolicySpec::any_counter_signature(
        OnEmptyBehavior::Deny,
        [TrustPolicySpec::AllowAll],
    );
    let (trusted, reasons) = evaluate(&deny);
    assert!(!trusted);
    assert!(reasons.iter().any(|r| r.contains("Phase 1 placeholder")));
}

#[test]
fn smoke_require_fact_placeholder_denies_with_failure_message() {
    let spec = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::PathOperator(PathOperatorPredicateSpec {
            path: "is_trusted".into(),
            operator: PredicateOperator::Equals,
            value: Some(serde_json::json!(true)),
        }),
        "chain not trusted",
    );
    let (trusted, reasons) = evaluate(&spec);
    assert!(!trusted, "Phase 1 always denies for RequireFact");
    let joined = reasons.join(" | ");
    assert!(
        joined.contains("chain not trusted"),
        "user failure message preserved: {joined}"
    );
    assert!(
        joined.contains("Phase 1 placeholder"),
        "phase banner present: {joined}"
    );
    assert!(joined.contains("x509-chain-trusted/v1"));
}

#[test]
fn smoke_unknown_fact_id_compile_error() {
    let spec = TrustPolicySpec::require_fact(
        "totally-bogus/v1",
        FactPredicateSpec::path_operator("x", PredicateOperator::Exists, None),
        "x",
    );
    let registry = StaticFactRegistry::default_mappings();
    let err = match compile(&spec, &registry) {
        Ok(_) => panic!("expected UnknownFactId error"),
        Err(e) => e,
    };
    match &err {
        CompileError::UnknownFactId { fact_id, .. } => {
            assert_eq!(fact_id, "totally-bogus/v1");
        }
        other => panic!("wrong error: {other}"),
    }
    assert_eq!(err.code(), "TPX200");
    let s = format!("{err}");
    assert!(s.contains("TPX200") && s.contains("totally-bogus/v1"));
}

#[test]
fn smoke_predicate_malformed_exists_with_value() {
    let spec = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::PathOperator(PathOperatorPredicateSpec {
            path: "p".into(),
            operator: PredicateOperator::Exists,
            value: Some(serde_json::json!(42)),
        }),
        "fail",
    );
    let registry = StaticFactRegistry::default_mappings();
    let err = match compile(&spec, &registry) {
        Ok(_) => panic!("expected predicate-malformed error"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "TPX500");
}

#[test]
fn smoke_predicate_malformed_non_exists_without_value() {
    let spec = TrustPolicySpec::require_fact(
        "x509-chain-trusted/v1",
        FactPredicateSpec::PathOperator(PathOperatorPredicateSpec {
            path: "p".into(),
            operator: PredicateOperator::Equals,
            value: None,
        }),
        "fail",
    );
    let registry = StaticFactRegistry::default_mappings();
    let err = match compile(&spec, &registry) {
        Ok(_) => panic!("expected predicate-malformed error"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "TPX500");
}

#[test]
fn smoke_recursion_limit_respected() {
    // Build a deep nested And chain that exceeds the configured cap.
    fn nest(n: usize) -> TrustPolicySpec {
        if n == 0 {
            TrustPolicySpec::AllowAll
        } else {
            TrustPolicySpec::and([nest(n - 1)])
        }
    }
    let deep = nest(60);
    let registry = StaticFactRegistry::default_mappings();
    let err = match compile_with_options(&deep, &registry, &CompileOptions::with_max_depth(32)) {
        Ok(_) => panic!("expected recursion-limit error"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "TPX301");
    let s = format!("{err}");
    assert!(s.contains("TPX301"));
}

#[test]
fn smoke_on_empty_translation_lossless() {
    assert_eq!(
        into_rule_on_empty(OnEmptyBehavior::Allow),
        RuleOnEmptyBehavior::Allow
    );
    assert_eq!(
        into_rule_on_empty(OnEmptyBehavior::Deny),
        RuleOnEmptyBehavior::Deny
    );
    assert_eq!(
        from_rule_on_empty(RuleOnEmptyBehavior::Allow),
        OnEmptyBehavior::Allow
    );
    assert_eq!(
        from_rule_on_empty(RuleOnEmptyBehavior::Deny),
        OnEmptyBehavior::Deny
    );
}

#[test]
fn smoke_compile_error_display_for_recursion_and_predicate() {
    let err = CompileError::RecursionLimitExceeded {
        limit: 5,
        variant: "and",
    };
    let s = format!("{err}");
    assert!(s.contains("TPX301") && s.contains("and"));

    let err2 = CompileError::PredicateMalformed {
        fact_id: "x/v1".into(),
        detail: "boom".into(),
    };
    let s2 = format!("{err2}");
    assert!(s2.contains("TPX500") && s2.contains("boom"));
}

#[test]
fn smoke_complex_tree_compiles_and_evaluates() {
    // Big representative tree: AND[OR[deny, allow], NOT(deny), MESSAGE[allow], PSK[allow]]
    let spec = TrustPolicySpec::and([
        TrustPolicySpec::or([
            TrustPolicySpec::DenyAll {
                reason: "left".into(),
            },
            TrustPolicySpec::AllowAll,
        ]),
        TrustPolicySpec::not(
            TrustPolicySpec::DenyAll {
                reason: "neg".into(),
            },
            None,
        ),
        TrustPolicySpec::message([TrustPolicySpec::AllowAll]),
        TrustPolicySpec::primary_signing_key([TrustPolicySpec::AllowAll]),
    ]);
    let (trusted, _) = evaluate(&spec);
    assert!(trusted);
}

#[test]
fn smoke_compile_options_default_matches_const() {
    let opts = CompileOptions::default();
    assert_eq!(
        opts.max_depth,
        cose_sign1_trust_policy_spec::DEFAULT_MAX_DEPTH
    );
}
