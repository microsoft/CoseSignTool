// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage test for `TrustFactContext::observe()` returning
//! `Err(TrustError::DeadlineExceeded)` (facts.rs line 134).
//!
//! We create a producer that calls `observe()` after the deadline has passed,
//! which should return `DeadlineExceeded` and propagate as an error.

use cose_sign1_validation_primitives::error::TrustError;
use cose_sign1_validation_primitives::facts::{
    FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer,
};
use cose_sign1_validation_primitives::subject::TrustSubject;
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Fact type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ObserveFact {
    value: String,
}

// ---------------------------------------------------------------------------
// Producer that always calls observe() — relying on deadline to trigger error
// ---------------------------------------------------------------------------

/// A producer that always calls `observe()`. When the engine's deadline has
/// already passed, `observe()` returns `Err(TrustError::DeadlineExceeded)`,
/// which covers line 134 in facts.rs.
struct ObserveAfterDeadlineProducer;

impl TrustFactProducer for ObserveAfterDeadlineProducer {
    fn name(&self) -> &'static str {
        "observe_after_deadline"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<ObserveFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        // The deadline should already be exceeded by the time we get here.
        // ctx.observe() checks deadline_exceeded() and returns Err if true.
        let result = ctx.observe(ObserveFact {
            value: "should fail".into(),
        });
        // Propagate the DeadlineExceeded error
        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn observe_returns_deadline_exceeded_when_deadline_passed() {
    // Set a timeout of 1ns so the deadline is already exceeded before produce() runs.
    let engine = TrustFactEngine::new(vec![
        Arc::new(ObserveAfterDeadlineProducer) as Arc<dyn TrustFactProducer>
    ])
    .with_timeout(Duration::from_nanos(1));

    // Wait for the deadline to pass.
    std::thread::sleep(Duration::from_millis(5));

    let subject = TrustSubject::message(b"observe_deadline_test");
    let result = engine.get_facts::<ObserveFact>(&subject);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, TrustError::DeadlineExceeded),
        "expected DeadlineExceeded, got: {err:?}"
    );
}

#[test]
fn observe_succeeds_when_no_deadline() {
    // Sanity check: without a deadline, observe works fine.
    let engine = TrustFactEngine::new(vec![
        Arc::new(ObserveAfterDeadlineProducer) as Arc<dyn TrustFactProducer>
    ]);

    let subject = TrustSubject::message(b"observe_no_deadline");
    let facts = engine.get_facts::<ObserveFact>(&subject).unwrap();

    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].value, "should fail");
}
