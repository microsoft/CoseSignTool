// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::facts::{
    FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer,
};
use cose_sign1_validation_trust::policy::TrustPolicyBuilder;
use cose_sign1_validation_trust::rules::{FnRule, TrustRuleRef};
use cose_sign1_validation_trust::subject::TrustSubject;
use cose_sign1_validation_trust::{TrustDecision, TrustEvaluationOptions};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExampleFact;

struct ExampleProducer {
    calls: Arc<AtomicUsize>,
}

impl TrustFactProducer for ExampleProducer {
    fn name(&self) -> &'static str {
        "example_producer"
    }

    fn produce(
        &self,
        ctx: &mut TrustFactContext<'_>,
    ) -> Result<(), cose_sign1_validation_trust::error::TrustError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ctx.observe(ExampleFact)?;
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<ExampleFact>()])
            .as_slice()
    }
}

#[test]
fn deny_by_default_when_no_trust_sources() {
    let subject = TrustSubject::root("message", b"seed");
    let policy = TrustPolicyBuilder::new().build();
    let plan = policy.compile();
    let engine = TrustFactEngine::new(vec![]);

    let decision = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .expect("plan evaluation");
    assert!(!decision.is_trusted);
}

#[test]
fn trust_sources_can_allow() {
    let subject = TrustSubject::root("message", b"seed");
    let allow_rule: TrustRuleRef = Arc::new(FnRule::new(
        "allow",
        |_e: &TrustFactEngine, _s: &TrustSubject| Ok(TrustDecision::trusted()),
    ));
    let policy = TrustPolicyBuilder::new()
        .add_trust_source(allow_rule)
        .build();
    let plan = policy.compile();
    let engine = TrustFactEngine::new(vec![]);

    let decision = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .expect("plan evaluation");
    assert!(decision.is_trusted);
}

#[test]
fn fact_engine_memoizes_by_subject_and_type() {
    let subject = TrustSubject::root("message", b"seed");
    let calls = Arc::new(AtomicUsize::new(0));
    let producer = Arc::new(ExampleProducer {
        calls: calls.clone(),
    });
    let engine = TrustFactEngine::new(vec![producer]);

    assert!(engine.has_fact::<ExampleFact>(&subject).unwrap());
    assert!(engine.has_fact::<ExampleFact>(&subject).unwrap());

    assert_eq!(1, calls.load(Ordering::SeqCst));
}

#[test]
fn required_facts_are_produced_by_plan_evaluation() {
    let subject = TrustSubject::root("message", b"seed");
    let calls = Arc::new(AtomicUsize::new(0));
    let producer = Arc::new(ExampleProducer {
        calls: calls.clone(),
    });
    let engine = TrustFactEngine::new(vec![producer]);

    let allow_rule: TrustRuleRef = Arc::new(FnRule::new(
        "allow",
        |_e: &TrustFactEngine, _s: &TrustSubject| Ok(TrustDecision::trusted()),
    ));
    let policy = TrustPolicyBuilder::new()
        .require_fact(FactKey::of::<ExampleFact>())
        .add_trust_source(allow_rule)
        .build();
    let plan = policy.compile();

    let decision = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .expect("plan evaluation");
    assert!(decision.is_trusted);
    assert_eq!(1, calls.load(Ordering::SeqCst));
}
