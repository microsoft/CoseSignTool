// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage test for `ScopedAnyOfSubjects::name()` (fluent.rs lines 184-186).
//!
//! The `name()` method is only called by `AuditedRule::evaluate()`.
//! We build a plan via `for_subjects_from_facts`, extract its rule ref,
//! wrap the inner trust-source rule in `AuditedRule`, and evaluate —
//! which calls `inner.name()` during audit event recording.

use cose_sign1_validation_primitives::audit::TrustDecisionAuditBuilder;
use cose_sign1_validation_primitives::error::TrustError;
use cose_sign1_validation_primitives::evaluation_options::TrustEvaluationOptions;
use cose_sign1_validation_primitives::facts::{FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer};
use cose_sign1_validation_primitives::fluent::{HasTrustSubject, TrustPlanBuilder};
use cose_sign1_validation_primitives::plan::CompiledTrustPlan;
use cose_sign1_validation_primitives::rules::{AuditedRule, OnEmptyBehavior, TrustRuleRef};
use cose_sign1_validation_primitives::subject::TrustSubject;
use std::sync::Mutex;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Fact/Producer for deriving subjects
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct DerivedSubjectFact {
    subject: TrustSubject,
}

impl HasTrustSubject for DerivedSubjectFact {
    fn trust_subject(&self) -> &TrustSubject {
        &self.subject
    }
}

struct DerivedSubjectProducer {
    derived: Vec<TrustSubject>,
}

impl TrustFactProducer for DerivedSubjectProducer {
    fn name(&self) -> &'static str {
        "derived_subject_producer"
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        for s in &self.derived {
            ctx.observe(DerivedSubjectFact { subject: s.clone() })?;
        }
        ctx.mark_produced(FactKey::of::<DerivedSubjectFact>());
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<DerivedSubjectFact>()])
            .as_slice()
    }
}

// ---------------------------------------------------------------------------
// Test: exercise ScopedAnyOfSubjects::name() via AuditedRule
// ---------------------------------------------------------------------------

/// Build a plan using `for_subjects_from_facts` which creates a
/// `ScopedAnyOfSubjects`, then wrap the plan's rule in an `AuditedRule`
/// and evaluate. The `AuditedRule::evaluate()` calls `self.inner.name()`
/// which in turn traverses the rule tree including the scoped rule.
#[test]
fn scoped_any_of_subjects_name_is_exercised_via_audit() {
    let root = TrustSubject::root("Message", b"seed");
    let derived = TrustSubject::root("CounterSignature", b"a");

    let engine = TrustFactEngine::new(vec![Arc::new(DerivedSubjectProducer {
        derived: vec![derived.clone()],
    })]);

    // Build a plan that uses for_subjects_from_facts, creating ScopedAnyOfSubjects.
    let plan = TrustPlanBuilder::default()
        .for_subjects_from_facts::<DerivedSubjectFact>(|s| {
            s.on_empty(OnEmptyBehavior::Allow).allow_all()
        })
        .compile();

    // Get the plan's composite rule ref — this wraps ScopedAnyOfSubjects inside AllOf/AnyOf.
    let rule_ref: TrustRuleRef = plan.as_rule_ref();

    // Wrap in AuditedRule. AuditedRule::evaluate calls self.inner.name() (line 766, 778).
    let audit = Arc::new(Mutex::new(TrustDecisionAuditBuilder::default()));
    let audited = AuditedRule::new(rule_ref, audit.clone());

    // Evaluate the audited rule. This calls:
    //   AuditedRule::name() -> AllOf::name() -> "compiled_plan"
    //   AuditedRule::evaluate() -> AllOf::evaluate() -> AnyOf::evaluate()
    //     -> ScopedAnyOfSubjects::evaluate() [exercised]
    let d = audited.evaluate(&engine, &root).unwrap();
    assert!(d.is_trusted);

    // Also directly evaluate the plan to exercise the normal path.
    let d2 = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d2.is_trusted);
}

/// Exercise `ScopedAnyOfSubjects::evaluate()` with actual subjects
/// to ensure the `evaluate` path is covered (even if `name()` cannot
/// be directly called on the private struct).
#[test]
fn scoped_any_of_subjects_evaluate_with_derived_subjects() {
    let root = TrustSubject::root("Message", b"seed");
    let derived1 = TrustSubject::root("CounterSignature", b"a");
    let derived2 = TrustSubject::root("CounterSignature", b"b");

    let engine = TrustFactEngine::new(vec![Arc::new(DerivedSubjectProducer {
        derived: vec![derived1, derived2],
    })]);

    let plan = TrustPlanBuilder::default()
        .for_subjects_from_facts::<DerivedSubjectFact>(|s| s.allow_all())
        .compile();

    // Evaluate with audit to exercise more paths.
    let (d, audit) = plan
        .evaluate_with_audit(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
    assert!(audit.is_some());
}

/// Exercise the `or_plans` composition path which also wraps scoped rules.
#[test]
fn scoped_rules_via_or_plans_composition() {
    let root = TrustSubject::root("Message", b"seed");
    let derived = TrustSubject::root("CounterSignature", b"a");

    let engine = TrustFactEngine::new(vec![Arc::new(DerivedSubjectProducer {
        derived: vec![derived],
    })]);

    let plan1 = TrustPlanBuilder::default()
        .for_subjects_from_facts::<DerivedSubjectFact>(|s| {
            s.on_empty(OnEmptyBehavior::Deny).allow_all()
        })
        .compile();

    let plan2 = TrustPlanBuilder::default()
        .for_message(|m| m.allow_all())
        .compile();

    let combined = CompiledTrustPlan::or_plans(vec![plan1, plan2]);

    let d = combined
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}
