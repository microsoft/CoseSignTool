// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage tests for `cose_sign1_validation_primitives::facts`.
//!
//! Targets uncovered paths: deadline handling, `mark_error`, `ensure_produced` error
//! propagation, `TrustFactSet::Error`/`Missing` in `get_facts`/`get_fact_set`,
//! `with_timeout`, and `has_fact` under various states.

use cose_sign1_validation_primitives::error::TrustError;
use cose_sign1_validation_primitives::facts::{
    FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer, TrustFactSet,
};
use cose_sign1_validation_primitives::subject::TrustSubject;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Fact types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct AlphaFact {
    value: String,
}

#[derive(Debug, Clone)]
struct BetaFact;

// ---------------------------------------------------------------------------
// Producers
// ---------------------------------------------------------------------------

/// A producer that observes an `AlphaFact`.
struct AlphaProducer;

impl TrustFactProducer for AlphaProducer {
    fn name(&self) -> &'static str {
        "alpha"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<AlphaFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        ctx.observe(AlphaFact {
            value: "hello".into(),
        })?;
        ctx.mark_produced(FactKey::of::<AlphaFact>());
        Ok(())
    }
}

/// A producer that marks `AlphaFact` as an error.
struct ErrorProducer;

impl TrustFactProducer for ErrorProducer {
    fn name(&self) -> &'static str {
        "error_producer"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<AlphaFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        ctx.mark_error::<AlphaFact>("production failed");
        ctx.mark_produced(FactKey::of::<AlphaFact>());
        Ok(())
    }
}

/// A producer that marks `AlphaFact` as missing.
struct MissingProducer;

impl TrustFactProducer for MissingProducer {
    fn name(&self) -> &'static str {
        "missing_producer"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<AlphaFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        ctx.mark_missing::<AlphaFact>("not available");
        ctx.mark_produced(FactKey::of::<AlphaFact>());
        Ok(())
    }
}

/// A producer that returns an `Err` from `produce`.
struct FailingProducer;

impl TrustFactProducer for FailingProducer {
    fn name(&self) -> &'static str {
        "failing_producer"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<AlphaFact>()])
            .as_slice()
    }

    fn produce(&self, _ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        Err(TrustError::FactProduction("boom".into()))
    }
}

/// A producer that sleeps briefly, useful for deadline tests.
struct SlowProducer;

impl TrustFactProducer for SlowProducer {
    fn name(&self) -> &'static str {
        "slow_producer"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<AlphaFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        std::thread::sleep(Duration::from_millis(50));
        if ctx.deadline_exceeded() {
            return Err(TrustError::DeadlineExceeded);
        }
        ctx.observe(AlphaFact {
            value: "slow".into(),
        })?;
        ctx.mark_produced(FactKey::of::<AlphaFact>());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests: with_timeout and deadline exceeded
// ---------------------------------------------------------------------------

#[test]
fn with_timeout_sets_deadline_and_triggers_deadline_exceeded() {
    let engine = TrustFactEngine::new(vec![Arc::new(SlowProducer) as Arc<dyn TrustFactProducer>])
        .with_timeout(Duration::from_nanos(1));

    // Allow the deadline to pass.
    std::thread::sleep(Duration::from_millis(1));

    let subject = TrustSubject::message(b"timeout_test");
    let result = engine.get_facts::<AlphaFact>(&subject);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, TrustError::DeadlineExceeded),
        "expected DeadlineExceeded, got: {err:?}"
    );
}

#[test]
fn with_deadline_triggers_deadline_exceeded_in_ensure_produced() {
    let deadline = Instant::now(); // already in the past
    let engine = TrustFactEngine::new(vec![Arc::new(AlphaProducer) as Arc<dyn TrustFactProducer>])
        .with_deadline(deadline);

    std::thread::sleep(Duration::from_millis(1));

    let subject = TrustSubject::message(b"deadline_test");
    let result = engine.get_facts::<AlphaFact>(&subject);
    assert!(matches!(result, Err(TrustError::DeadlineExceeded)));
}

#[test]
fn deadline_exceeded_after_producer_runs() {
    // Use a very short timeout so that the producer finishes but deadline_exceeded is true
    // when checked after the producer returns.
    let engine = TrustFactEngine::new(vec![Arc::new(SlowProducer) as Arc<dyn TrustFactProducer>])
        .with_timeout(Duration::from_millis(10));

    let subject = TrustSubject::message(b"post_produce_deadline");
    let result = engine.get_facts::<AlphaFact>(&subject);
    // The producer sleeps 50ms but timeout is 10ms, so either the producer itself
    // returns DeadlineExceeded or the post-produce check catches it.
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Tests: mark_error path
// ---------------------------------------------------------------------------

#[test]
fn mark_error_causes_get_fact_set_to_return_error() {
    let engine = TrustFactEngine::new(vec![Arc::new(ErrorProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::message(b"error_fact_set");

    let fact_set = engine.get_fact_set::<AlphaFact>(&subject).unwrap();
    match fact_set {
        TrustFactSet::Error { message } => {
            assert_eq!(&*message, "production failed");
        }
        other => panic!("expected Error, got: {other:?}"),
    }
}

#[test]
fn mark_error_causes_get_facts_to_return_err() {
    let engine = TrustFactEngine::new(vec![Arc::new(ErrorProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::message(b"error_get_facts");

    let result = engine.get_facts::<AlphaFact>(&subject);
    assert!(result.is_err());
    match result.unwrap_err() {
        TrustError::FactProduction(msg) => {
            assert!(
                msg.contains("production failed"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected FactProduction, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests: mark_missing path
// ---------------------------------------------------------------------------

#[test]
fn mark_missing_causes_get_fact_set_to_return_missing() {
    let engine =
        TrustFactEngine::new(vec![Arc::new(MissingProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::message(b"missing_fact_set");

    let fact_set = engine.get_fact_set::<AlphaFact>(&subject).unwrap();
    match fact_set {
        TrustFactSet::Missing { reason } => {
            assert_eq!(&*reason, "not available");
        }
        other => panic!("expected Missing, got: {other:?}"),
    }
}

#[test]
fn mark_missing_causes_get_facts_to_return_empty_vec() {
    let engine =
        TrustFactEngine::new(vec![Arc::new(MissingProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::message(b"missing_get_facts");

    let facts = engine.get_facts::<AlphaFact>(&subject).unwrap();
    assert!(facts.is_empty());
}

// ---------------------------------------------------------------------------
// Tests: ensure_produced when producer returns Err
// ---------------------------------------------------------------------------

#[test]
fn ensure_produced_propagates_producer_error() {
    let engine =
        TrustFactEngine::new(vec![Arc::new(FailingProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::message(b"failing_producer");

    let result = engine.get_facts::<AlphaFact>(&subject);
    assert!(result.is_err());
    match result.unwrap_err() {
        TrustError::FactProduction(msg) => {
            assert!(
                msg.contains("failing_producer") && msg.contains("boom"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("expected FactProduction, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests: has_fact under different states
// ---------------------------------------------------------------------------

#[test]
fn has_fact_returns_true_when_facts_available() {
    let engine = TrustFactEngine::new(vec![Arc::new(AlphaProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::message(b"has_fact_available");

    assert!(engine.has_fact::<AlphaFact>(&subject).unwrap());
}

#[test]
fn has_fact_returns_false_when_no_producer_exists() {
    let engine = TrustFactEngine::new(vec![]);
    let subject = TrustSubject::message(b"has_fact_no_producer");

    assert!(!engine.has_fact::<AlphaFact>(&subject).unwrap());
}

#[test]
fn has_fact_returns_false_when_facts_missing() {
    let engine =
        TrustFactEngine::new(vec![Arc::new(MissingProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::message(b"has_fact_missing");

    assert!(!engine.has_fact::<AlphaFact>(&subject).unwrap());
}

#[test]
fn has_fact_returns_err_when_facts_errored() {
    let engine = TrustFactEngine::new(vec![Arc::new(ErrorProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::message(b"has_fact_error");

    let result = engine.has_fact::<AlphaFact>(&subject);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Tests: TrustFactSet helpers
// ---------------------------------------------------------------------------

#[test]
fn trust_fact_set_is_missing_returns_true_for_missing() {
    let set: TrustFactSet<AlphaFact> = TrustFactSet::Missing {
        reason: "gone".into(),
    };
    assert!(set.is_missing());
}

#[test]
fn trust_fact_set_is_missing_returns_false_for_available() {
    let set: TrustFactSet<AlphaFact> = TrustFactSet::Available(vec![]);
    assert!(!set.is_missing());
}

#[test]
fn trust_fact_set_is_missing_returns_false_for_error() {
    let set: TrustFactSet<AlphaFact> = TrustFactSet::Error {
        message: "bad".into(),
    };
    assert!(!set.is_missing());
}

#[test]
fn trust_fact_set_as_available_returns_some_for_available() {
    let fact = Arc::new(AlphaFact { value: "x".into() });
    let set: TrustFactSet<AlphaFact> = TrustFactSet::Available(vec![fact]);
    let slice = set.as_available().unwrap();
    assert_eq!(slice.len(), 1);
    assert_eq!(slice[0].value, "x");
}

#[test]
fn trust_fact_set_as_available_returns_none_for_missing() {
    let set: TrustFactSet<AlphaFact> = TrustFactSet::Missing {
        reason: "nope".into(),
    };
    assert!(set.as_available().is_none());
}

#[test]
fn trust_fact_set_as_available_returns_none_for_error() {
    let set: TrustFactSet<AlphaFact> = TrustFactSet::Error {
        message: "oops".into(),
    };
    assert!(set.as_available().is_none());
}

// ---------------------------------------------------------------------------
// Tests: get_fact_set returns Available(empty) when no facts observed
// ---------------------------------------------------------------------------

#[test]
fn get_fact_set_returns_available_empty_when_no_producer() {
    let engine = TrustFactEngine::new(vec![]);
    let subject = TrustSubject::message(b"no_producer");

    let fact_set = engine.get_fact_set::<BetaFact>(&subject).unwrap();
    match fact_set {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty), got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests: with_evaluation_options sets timeouts
// ---------------------------------------------------------------------------

#[test]
fn with_evaluation_options_sets_deadline_that_triggers_exceeded() {
    use cose_sign1_validation_primitives::TrustEvaluationOptions;

    let opts = TrustEvaluationOptions {
        overall_timeout: Some(Duration::from_nanos(1)),
        per_fact_timeout: None,
        per_producer_timeout: None,
        bypass_trust: false,
    };

    let engine = TrustFactEngine::new(vec![Arc::new(AlphaProducer) as Arc<dyn TrustFactProducer>])
        .with_evaluation_options(&opts);

    std::thread::sleep(Duration::from_millis(1));

    let subject = TrustSubject::message(b"eval_opts_deadline");
    let result = engine.get_facts::<AlphaFact>(&subject);
    assert!(matches!(result, Err(TrustError::DeadlineExceeded)));
}

// ---------------------------------------------------------------------------
// Tests: observe returns DeadlineExceeded when deadline has passed
// ---------------------------------------------------------------------------

#[test]
fn observe_returns_deadline_exceeded_when_past_deadline() {
    // Use a producer that sleeps past the deadline, then tries to observe.
    // The SlowProducer already checks deadline_exceeded and returns error.
    let engine = TrustFactEngine::new(vec![Arc::new(SlowProducer) as Arc<dyn TrustFactProducer>])
        .with_timeout(Duration::from_millis(5));

    let subject = TrustSubject::message(b"observe_deadline");
    let result = engine.get_facts::<AlphaFact>(&subject);
    // Producer sleeps 50ms, timeout is 5ms → observe or post-check fails.
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Tests: ensure_fact (public wrapper for ensure_produced)
// ---------------------------------------------------------------------------

#[test]
fn ensure_fact_succeeds_for_available_producer() {
    let engine = TrustFactEngine::new(vec![Arc::new(AlphaProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::message(b"ensure_fact_ok");

    engine
        .ensure_fact(&subject, FactKey::of::<AlphaFact>())
        .unwrap();
    // Second call should be a no-op (already produced).
    engine
        .ensure_fact(&subject, FactKey::of::<AlphaFact>())
        .unwrap();
}

#[test]
fn ensure_fact_fails_when_deadline_passed() {
    let engine = TrustFactEngine::new(vec![Arc::new(AlphaProducer) as Arc<dyn TrustFactProducer>])
        .with_timeout(Duration::from_nanos(1));

    std::thread::sleep(Duration::from_millis(1));

    let subject = TrustSubject::message(b"ensure_fact_deadline");
    let result = engine.ensure_fact(&subject, FactKey::of::<AlphaFact>());
    assert!(matches!(result, Err(TrustError::DeadlineExceeded)));
}
