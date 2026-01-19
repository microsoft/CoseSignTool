// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::audit::{AuditEvent, TrustDecisionAuditBuilder};
use cose_sign1_validation_trust::{
    error::TrustError,
    facts::{FactKey, TrustFactEngine, TrustFactProducer},
    ids::SubjectId,
    plan::CompiledTrustPlan,
    policy::TrustPolicyBuilder,
    rules::{all_of, any_of, not, not_with_reason, AuditedRule, FnRule, TrustRuleRef},
    subject::TrustSubject,
    TrustDecision,
};
use parking_lot::Mutex;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
struct DummyFact {
    value: u32,
}

struct DummyProducer {
    name: &'static str,
    called: Arc<AtomicUsize>,
    behavior:
        fn(&cose_sign1_validation_trust::facts::TrustFactContext<'_>) -> Result<(), TrustError>,
}

impl TrustFactProducer for DummyProducer {
    fn name(&self) -> &'static str {
        self.name
    }

    fn produce(
        &self,
        ctx: &mut cose_sign1_validation_trust::facts::TrustFactContext<'_>,
    ) -> Result<(), TrustError> {
        self.called.fetch_add(1, Ordering::SeqCst);
        (self.behavior)(ctx)
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<DummyFact>()])
            .as_slice()
    }
}

fn engine_and_subject() -> (TrustFactEngine, TrustSubject) {
    let engine = TrustFactEngine::new(vec![]);
    let subject = TrustSubject::message(b"msg");
    (engine, subject)
}

#[test]
fn all_of_aggregates_denial_reasons() {
    let (engine, subject) = engine_and_subject();

    let r1: TrustRuleRef = Arc::new(FnRule::new(
        "r1",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::trusted())
        },
    ));
    let r2: TrustRuleRef = Arc::new(FnRule::new(
        "r2",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::denied(vec!["nope".to_string()]))
        },
    ));
    let r3: TrustRuleRef = Arc::new(FnRule::new(
        "r3",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::denied(vec!["still nope".to_string()]))
        },
    ));

    let rule = all_of("all", vec![r1, r2, r3]);
    let d = rule.evaluate(&engine, &subject).unwrap();

    assert!(!d.is_trusted);
    assert_eq!(
        vec!["nope".to_string(), "still nope".to_string()],
        d.reasons
    );
}

#[test]
fn any_of_empty_denies_with_default_reason() {
    let (engine, subject) = engine_and_subject();

    let rule = any_of("any", vec![]);
    let d = rule.evaluate(&engine, &subject).unwrap();

    assert!(!d.is_trusted);
    assert_eq!(
        vec!["No trust sources were satisfied".to_string()],
        d.reasons
    );
}

#[test]
fn any_of_short_circuits_on_first_trusted() {
    let (engine, subject) = engine_and_subject();

    let called = Arc::new(AtomicUsize::new(0));

    let r1_called = called.clone();
    let r1: TrustRuleRef = Arc::new(FnRule::new(
        "r1",
        move |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            r1_called.fetch_add(1, Ordering::SeqCst);
            Ok(TrustDecision::trusted())
        },
    ));

    let r2_called = called.clone();
    let r2: TrustRuleRef = Arc::new(FnRule::new(
        "r2",
        move |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            r2_called.fetch_add(100, Ordering::SeqCst);
            Ok(TrustDecision::denied(vec!["should not run".to_string()]))
        },
    ));

    let rule = any_of("any", vec![r1, r2]);
    let d = rule.evaluate(&engine, &subject).unwrap();

    assert!(d.is_trusted);
    assert_eq!(1, called.load(Ordering::SeqCst));
}

#[test]
fn not_inverts_decision_and_emits_reason() {
    let (engine, subject) = engine_and_subject();

    let inner: TrustRuleRef = Arc::new(FnRule::new(
        "inner",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::trusted())
        },
    ));

    let d = not("not", inner).evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(vec!["Negated rule was satisfied".to_string()], d.reasons);

    let inner: TrustRuleRef = Arc::new(FnRule::new(
        "inner",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::denied(vec!["deny".to_string()]))
        },
    ));
    let d = not_with_reason("not", inner, "custom")
        .evaluate(&engine, &subject)
        .unwrap();
    assert!(d.is_trusted);
    assert!(d.reasons.is_empty());
}

#[test]
fn audited_rule_records_audit_event() {
    let (engine, subject) = engine_and_subject();

    let audit = Arc::new(Mutex::new(TrustDecisionAuditBuilder::default()));
    let inner: TrustRuleRef = Arc::new(FnRule::new(
        "inner",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::denied(vec!["x".to_string()]))
        },
    ));

    let audited = AuditedRule::new(inner, audit.clone());
    let d = audited.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);

    let mut guard = audit.lock();
    let built = std::mem::take(&mut *guard).build();
    drop(guard);

    assert_eq!(1, built.events().len());
    match &built.events()[0] {
        AuditEvent::RuleEvaluated {
            subject: s,
            rule_name,
            decision,
        } => {
            assert_eq!(subject.id, *s);
            assert_eq!(*rule_name, "inner");
            assert_eq!(decision.clone(), d);
        }
        _ => panic!("unexpected audit event"),
    }
}

#[test]
fn policy_builder_collects_rules_and_required_facts() {
    // This exercises builder paths and ensures we don't duplicate required facts.
    let policy = TrustPolicyBuilder::new()
        .require_fact(cose_sign1_validation_trust::facts::FactKey::of::<u8>())
        .require_fact(cose_sign1_validation_trust::facts::FactKey::of::<u8>())
        .build();

    assert_eq!(1, policy.required_facts.len());

    // Also sanity check audit builder push/build roundtrip.
    let mut b = TrustDecisionAuditBuilder::default();
    b.push(AuditEvent::FactObserved {
        subject: SubjectId([0u8; 32]),
        fact_type: "X",
    });
    let a = b.build();
    assert_eq!(1, a.events().len());
}

#[test]
fn policy_builder_adds_rules_and_compiles() {
    let (engine, subject) = engine_and_subject();

    let allow: TrustRuleRef = Arc::new(FnRule::new(
        "allow",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::trusted())
        },
    ));
    let deny: TrustRuleRef = Arc::new(FnRule::new(
        "deny",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::denied(vec!["no".to_string()]))
        },
    ));

    // constraint allows, trust source allows, veto denies (so NOT(vetoes) => trusted)
    let policy = TrustPolicyBuilder::new()
        .add_constraint(allow.clone())
        .add_trust_source(allow.clone())
        .add_veto(deny.clone())
        .build();

    let plan = policy.compile();
    let decision = plan
        .evaluate(&engine, &subject, &Default::default())
        .unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn fact_engine_audit_records_observed_facts() {
    let called = Arc::new(AtomicUsize::new(0));
    let producer = DummyProducer {
        name: "dummy",
        called: called.clone(),
        behavior: |ctx| ctx.observe(DummyFact { value: 42 }),
    };
    let engine = TrustFactEngine::new(vec![Arc::new(producer)]);
    engine.enable_audit();

    let subject = TrustSubject::message(b"msg");
    let facts = engine.get_facts::<DummyFact>(&subject).unwrap();
    assert_eq!(1, facts.len());
    assert_eq!(42, facts[0].value);

    // Verify produced caching: second call does not re-run producer.
    let _ = engine.get_facts::<DummyFact>(&subject).unwrap();
    assert_eq!(1, called.load(Ordering::SeqCst));

    let audit = engine.take_audit().unwrap();
    assert!(audit
        .events()
        .iter()
        .any(|e| matches!(e, AuditEvent::FactObserved { .. })));
}

#[test]
fn fact_engine_deadline_exceeded_before_production() {
    let producer = DummyProducer {
        name: "dummy",
        called: Arc::new(AtomicUsize::new(0)),
        behavior: |_ctx| Ok(()),
    };
    let engine = TrustFactEngine::new(vec![Arc::new(producer)])
        .with_deadline(Instant::now() - Duration::from_secs(1));

    let subject = TrustSubject::message(b"msg");
    let err = engine.get_facts::<DummyFact>(&subject).unwrap_err();
    assert!(matches!(err, TrustError::DeadlineExceeded));
}

#[test]
fn fact_engine_per_fact_timeout_triggers_deadline_exceeded() {
    let producer = DummyProducer {
        name: "dummy",
        called: Arc::new(AtomicUsize::new(0)),
        behavior: |_ctx| Ok(()),
    };

    let options = cose_sign1_validation_trust::TrustEvaluationOptions {
        overall_timeout: None,
        per_fact_timeout: Some(Duration::ZERO),
        per_producer_timeout: None,
        bypass_trust: false,
    };
    let engine = TrustFactEngine::new(vec![Arc::new(producer)]).with_evaluation_options(&options);

    let subject = TrustSubject::message(b"msg");
    let err = engine.get_fact_set::<DummyFact>(&subject).unwrap_err();
    assert!(matches!(err, TrustError::DeadlineExceeded));
}

#[test]
fn fact_engine_per_producer_timeout_triggers_deadline_exceeded() {
    let producer = DummyProducer {
        name: "dummy",
        called: Arc::new(AtomicUsize::new(0)),
        behavior: |_ctx| Ok(()),
    };

    let options = cose_sign1_validation_trust::TrustEvaluationOptions {
        overall_timeout: None,
        per_fact_timeout: None,
        per_producer_timeout: Some(Duration::ZERO),
        bypass_trust: false,
    };
    let engine = TrustFactEngine::new(vec![Arc::new(producer)]).with_evaluation_options(&options);

    let subject = TrustSubject::message(b"msg");
    let err = engine.get_fact_set::<DummyFact>(&subject).unwrap_err();
    assert!(matches!(err, TrustError::DeadlineExceeded));
}

#[test]
fn fact_engine_missing_and_error_fact_sets() {
    let missing = DummyProducer {
        name: "missing",
        called: Arc::new(AtomicUsize::new(0)),
        behavior: |ctx| {
            ctx.mark_missing::<DummyFact>("nope");
            Ok(())
        },
    };
    let error = DummyProducer {
        name: "error",
        called: Arc::new(AtomicUsize::new(0)),
        behavior: |ctx| {
            ctx.mark_error::<DummyFact>("boom");
            Ok(())
        },
    };

    let subject = TrustSubject::message(b"msg");

    let engine = TrustFactEngine::new(vec![Arc::new(missing)]);
    let set = engine.get_fact_set::<DummyFact>(&subject).unwrap();
    assert!(matches!(
        set,
        cose_sign1_validation_trust::facts::TrustFactSet::Missing { .. }
    ));
    assert!(engine.get_facts::<DummyFact>(&subject).unwrap().is_empty());

    let engine = TrustFactEngine::new(vec![Arc::new(error)]);
    let err = engine.get_facts::<DummyFact>(&subject).unwrap_err();
    assert!(matches!(err, TrustError::FactProduction(_)));
}

#[test]
fn compiled_plan_from_rule_and_bypass_paths() {
    let (engine, subject) = engine_and_subject();

    let deny: TrustRuleRef = Arc::new(FnRule::new(
        "deny",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::denied(vec!["no".to_string()]))
        },
    ));

    let plan = CompiledTrustPlan::new(vec![], vec![], vec![deny], vec![]);
    let d = plan
        .evaluate(&engine, &subject, &Default::default())
        .unwrap();
    assert!(!d.is_trusted);

    let options = cose_sign1_validation_trust::TrustEvaluationOptions {
        bypass_trust: true,
        ..Default::default()
    };
    let d = plan.evaluate(&engine, &subject, &options).unwrap();
    assert!(d.is_trusted);
    assert_eq!(vec!["BypassTrust".to_string()], d.reasons);
}

#[test]
fn not_uses_default_reason_and_fnrule_name_is_exposed() {
    let (engine, subject) = engine_and_subject();

    let inner: TrustRuleRef = Arc::new(FnRule::new(
        "inner_rule_name",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::trusted())
        },
    ));

    assert_eq!("inner_rule_name", inner.name());

    let d = not("negated", inner).evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(vec!["Negated rule was satisfied".to_string()], d.reasons);
}
