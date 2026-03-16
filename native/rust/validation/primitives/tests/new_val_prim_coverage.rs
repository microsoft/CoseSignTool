// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Edge-case coverage for validation primitives: TrustDecision, TrustError,
//! TrustFactEngine, CompiledTrustPlan, TrustPolicyBuilder, Field, and subjects.

use cose_sign1_validation_primitives::decision::TrustDecision;
use cose_sign1_validation_primitives::error::TrustError;
use cose_sign1_validation_primitives::evaluation_options::{CoseHeaderLocation, TrustEvaluationOptions};
use cose_sign1_validation_primitives::facts::{FactKey, TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::field::Field;
use cose_sign1_validation_primitives::plan::CompiledTrustPlan;
use cose_sign1_validation_primitives::policy::TrustPolicyBuilder;
use cose_sign1_validation_primitives::subject::TrustSubject;

// ---------- TrustError Display ----------

#[test]
fn error_display_all_variants() {
    let cases: Vec<(TrustError, &str)> = vec![
        (TrustError::FactProduction("fp".into()), "fact production failed: fp"),
        (TrustError::RuleEvaluation("re".into()), "rule evaluation failed: re"),
        (TrustError::DeadlineExceeded, "deadline exceeded"),
    ];
    for (err, expected) in cases {
        assert_eq!(format!("{err}"), expected);
    }
}

#[test]
fn error_implements_std_error() {
    let err = TrustError::DeadlineExceeded;
    let _: &dyn std::error::Error = &err;
}

// ---------- TrustDecision ----------

#[test]
fn decision_trusted_no_reasons() {
    let d = TrustDecision::trusted();
    assert!(d.is_trusted);
    assert!(d.reasons.is_empty());
}

#[test]
fn decision_trusted_with_empty_vec_returns_trusted() {
    let d = TrustDecision::trusted_with(Vec::new());
    assert!(d.is_trusted);
    assert!(d.reasons.is_empty());
}

#[test]
fn decision_trusted_reason_single() {
    let d = TrustDecision::trusted_reason("ok");
    assert!(d.is_trusted);
    assert_eq!(d.reasons, vec!["ok"]);
}

#[test]
fn decision_denied_preserves_reasons() {
    let d = TrustDecision::denied(vec!["a".into(), "b".into()]);
    assert!(!d.is_trusted);
    assert_eq!(d.reasons.len(), 2);
}

// ---------- TrustFactSet helpers ----------

#[test]
fn fact_set_missing_is_missing() {
    let fs: TrustFactSet<String> = TrustFactSet::Missing { reason: "gone".into() };
    assert!(fs.is_missing());
    assert!(fs.as_available().is_none());
}

#[test]
fn fact_set_available_empty_not_missing() {
    let fs: TrustFactSet<u32> = TrustFactSet::Available(Vec::new());
    assert!(!fs.is_missing());
    assert!(fs.as_available().unwrap().is_empty());
}

// ---------- FactKey ----------

#[test]
fn fact_key_of_same_type_is_equal() {
    let k1 = FactKey::of::<String>();
    let k2 = FactKey::of::<String>();
    assert_eq!(k1, k2);
}

// ---------- TrustFactEngine no-producers ----------

#[test]
fn engine_empty_producers_returns_empty_facts() {
    let engine = TrustFactEngine::new(Vec::new());
    let subject = TrustSubject::message(b"hello");
    let facts = engine.get_facts::<String>(&subject).unwrap();
    assert!(facts.is_empty());
}

// ---------- CompiledTrustPlan empty rules ----------

#[test]
fn compiled_plan_no_trust_sources_denies() {
    let plan = CompiledTrustPlan::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let engine = TrustFactEngine::new(Vec::new());
    let subject = TrustSubject::message(b"msg");
    let opts = TrustEvaluationOptions::default();
    let decision = plan.evaluate(&engine, &subject, &opts).unwrap();
    assert!(!decision.is_trusted, "empty trust sources should deny");
}

#[test]
fn compiled_plan_bypass_trust_returns_trusted() {
    let plan = CompiledTrustPlan::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let engine = TrustFactEngine::new(Vec::new());
    let subject = TrustSubject::message(b"msg");
    let opts = TrustEvaluationOptions { bypass_trust: true, ..Default::default() };
    let decision = plan.evaluate(&engine, &subject, &opts).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn compiled_plan_or_plans_empty_denies() {
    let plan = CompiledTrustPlan::or_plans(Vec::new());
    let engine = TrustFactEngine::new(Vec::new());
    let subject = TrustSubject::message(b"x");
    let opts = TrustEvaluationOptions::default();
    let decision = plan.evaluate(&engine, &subject, &opts).unwrap();
    assert!(!decision.is_trusted);
}

// ---------- TrustPolicyBuilder ----------

#[test]
fn policy_builder_empty_compiles_deny_all() {
    let policy = TrustPolicyBuilder::new().build();
    let plan = policy.compile();
    let engine = TrustFactEngine::new(Vec::new());
    let subject = TrustSubject::message(b"p");
    let opts = TrustEvaluationOptions::default();
    let decision = plan.evaluate(&engine, &subject, &opts).unwrap();
    assert!(!decision.is_trusted);
}

// ---------- Subject constructors ----------

#[test]
fn subject_deterministic_ids() {
    let s1 = TrustSubject::message(b"abc");
    let s2 = TrustSubject::message(b"abc");
    assert_eq!(s1.id, s2.id);
    assert_eq!(s1.kind, "Message");
}

#[test]
fn subject_root_creates_unique_kind() {
    let s = TrustSubject::root("Custom", b"seed");
    assert_eq!(s.kind, "Custom");
}

// ---------- CoseHeaderLocation ----------

#[test]
fn cose_header_location_default_is_protected() {
    assert_eq!(CoseHeaderLocation::default(), CoseHeaderLocation::Protected);
}

// ---------- Field ----------

#[test]
fn field_name_returns_name() {
    let f: Field<String, i64> = Field::new("test_field");
    assert_eq!(f.name(), "test_field");
}
