// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for `cose_sign1_validation_primitives::rules`.
//!
//! Targets uncovered branches in `require_facts_match`, `require_fact_matches_with_missing_behavior`,
//! and combinators like `all_of`.

use cose_sign1_validation_primitives::error::TrustError;
use cose_sign1_validation_primitives::fact_properties::{FactProperties, FactValue};
use cose_sign1_validation_primitives::facts::{
    FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer,
};
use cose_sign1_validation_primitives::rules::{
    all_of, allow_all, require_fact_matches_with_missing_behavior, require_facts_match,
    FactSelector, MissingBehavior,
};
use cose_sign1_validation_primitives::subject::TrustSubject;
use std::borrow::Cow;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Fact types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LFact {
    id: String,
    name: String,
}

impl FactProperties for LFact {
    fn get_property<'a>(&'a self, prop: &str) -> Option<FactValue<'a>> {
        match prop {
            "id" => Some(FactValue::Str(Cow::Borrowed(self.id.as_str()))),
            "name" => Some(FactValue::Str(Cow::Borrowed(self.name.as_str()))),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct RFact {
    id: String,
    name: String,
}

impl FactProperties for RFact {
    fn get_property<'a>(&'a self, prop: &str) -> Option<FactValue<'a>> {
        match prop {
            "id" => Some(FactValue::Str(Cow::Borrowed(self.id.as_str()))),
            "name" => Some(FactValue::Str(Cow::Borrowed(self.name.as_str()))),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct SimpleFact {
    tag: String,
}

impl FactProperties for SimpleFact {
    fn get_property<'a>(&'a self, prop: &str) -> Option<FactValue<'a>> {
        match prop {
            "tag" => Some(FactValue::Str(Cow::Borrowed(self.tag.as_str()))),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Producers
// ---------------------------------------------------------------------------

/// Produces an error for LFact and a normal RFact.
struct ErrorLeftProducer;

impl TrustFactProducer for ErrorLeftProducer {
    fn name(&self) -> &'static str {
        "error_left"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<LFact>(), FactKey::of::<RFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<LFact>() {
            ctx.mark_error::<LFact>("LeftError");
            ctx.mark_produced(FactKey::of::<LFact>());
        }
        if ctx.requested_fact() == FactKey::of::<RFact>() {
            ctx.observe(RFact {
                id: "1".into(),
                name: "r".into(),
            })?;
            ctx.mark_produced(FactKey::of::<RFact>());
        }
        Ok(())
    }
}

/// Produces a normal LFact and marks RFact as missing.
struct MissingRightProducer;

impl TrustFactProducer for MissingRightProducer {
    fn name(&self) -> &'static str {
        "missing_right"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<LFact>(), FactKey::of::<RFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<LFact>() {
            ctx.observe(LFact {
                id: "1".into(),
                name: "left".into(),
            })?;
            ctx.mark_produced(FactKey::of::<LFact>());
        }
        if ctx.requested_fact() == FactKey::of::<RFact>() {
            ctx.mark_missing::<RFact>("RightMissing");
            ctx.mark_produced(FactKey::of::<RFact>());
        }
        Ok(())
    }
}

/// Produces a normal LFact and marks RFact as error.
struct ErrorRightProducer;

impl TrustFactProducer for ErrorRightProducer {
    fn name(&self) -> &'static str {
        "error_right"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<LFact>(), FactKey::of::<RFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<LFact>() {
            ctx.observe(LFact {
                id: "1".into(),
                name: "left".into(),
            })?;
            ctx.mark_produced(FactKey::of::<LFact>());
        }
        if ctx.requested_fact() == FactKey::of::<RFact>() {
            ctx.mark_error::<RFact>("RightBoom");
            ctx.mark_produced(FactKey::of::<RFact>());
        }
        Ok(())
    }
}

/// Produces matching LFact and RFact with multiple properties.
struct MatchingPairProducer;

impl TrustFactProducer for MatchingPairProducer {
    fn name(&self) -> &'static str {
        "matching_pair"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<LFact>(), FactKey::of::<RFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<LFact>() {
            ctx.observe(LFact {
                id: "abc".into(),
                name: "shared".into(),
            })?;
            ctx.mark_produced(FactKey::of::<LFact>());
        }
        if ctx.requested_fact() == FactKey::of::<RFact>() {
            ctx.observe(RFact {
                id: "abc".into(),
                name: "shared".into(),
            })?;
            ctx.mark_produced(FactKey::of::<RFact>());
        }
        Ok(())
    }
}

/// Produces LFact and RFact where values don't match.
struct MismatchPairProducer;

impl TrustFactProducer for MismatchPairProducer {
    fn name(&self) -> &'static str {
        "mismatch_pair"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<LFact>(), FactKey::of::<RFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<LFact>() {
            ctx.observe(LFact {
                id: "abc".into(),
                name: "left_name".into(),
            })?;
            ctx.mark_produced(FactKey::of::<LFact>());
        }
        if ctx.requested_fact() == FactKey::of::<RFact>() {
            ctx.observe(RFact {
                id: "abc".into(),
                name: "right_name".into(),
            })?;
            ctx.mark_produced(FactKey::of::<RFact>());
        }
        Ok(())
    }
}

/// Produces SimpleFact with a specific tag.
struct SimpleProducer {
    tag: &'static str,
}

impl TrustFactProducer for SimpleProducer {
    fn name(&self) -> &'static str {
        "simple"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<SimpleFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<SimpleFact>() {
            ctx.observe(SimpleFact {
                tag: self.tag.to_string(),
            })?;
            ctx.mark_produced(FactKey::of::<SimpleFact>());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests: require_facts_match – left Error
// ---------------------------------------------------------------------------

#[test]
fn require_facts_match_denies_when_left_fact_set_is_error() {
    let engine = TrustFactEngine::new(vec![Arc::new(ErrorLeftProducer)]);
    let subject = TrustSubject::message(b"rc1");

    let rule = require_facts_match::<LFact, RFact, _>(
        "left_error",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("id", "id")],
        MissingBehavior::Deny,
        "PairDeny",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert!(
        d.reasons.iter().any(|r| r.contains("LeftError")),
        "expected deny reason to contain 'LeftError', got: {:?}",
        d.reasons
    );
}

// ---------------------------------------------------------------------------
// Tests: require_facts_match – right Missing (TrustFactSet level)
// ---------------------------------------------------------------------------

#[test]
fn require_facts_match_denies_when_right_fact_set_is_missing() {
    let engine = TrustFactEngine::new(vec![Arc::new(MissingRightProducer)]);
    let subject = TrustSubject::message(b"rc2");

    let rule = require_facts_match::<LFact, RFact, _>(
        "right_missing",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("id", "id")],
        MissingBehavior::Deny,
        "PairDeny",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert!(
        d.reasons.iter().any(|r| r.contains("RightMissing")),
        "expected deny reason to contain 'RightMissing', got: {:?}",
        d.reasons
    );
}

// ---------------------------------------------------------------------------
// Tests: require_facts_match – right Error (TrustFactSet level)
// ---------------------------------------------------------------------------

#[test]
fn require_facts_match_denies_when_right_fact_set_is_error() {
    let engine = TrustFactEngine::new(vec![Arc::new(ErrorRightProducer)]);
    let subject = TrustSubject::message(b"rc3");

    let rule = require_facts_match::<LFact, RFact, _>(
        "right_error",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("id", "id")],
        MissingBehavior::Deny,
        "PairDeny",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert!(
        d.reasons.iter().any(|r| r.contains("RightBoom")),
        "expected deny reason to contain 'RightBoom', got: {:?}",
        d.reasons
    );
}

// ---------------------------------------------------------------------------
// Tests: require_facts_match – happy path with multiple property pairs
// ---------------------------------------------------------------------------

#[test]
fn require_facts_match_trusts_when_all_property_pairs_match() {
    let engine = TrustFactEngine::new(vec![Arc::new(MatchingPairProducer)]);
    let subject = TrustSubject::message(b"rc4");

    let rule = require_facts_match::<LFact, RFact, _>(
        "match_ok",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("id", "id"), ("name", "name")],
        MissingBehavior::Deny,
        "PairDeny",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(d.is_trusted);
}

// ---------------------------------------------------------------------------
// Tests: require_facts_match – property value mismatch on second pair
// ---------------------------------------------------------------------------

#[test]
fn require_facts_match_denies_when_second_property_pair_mismatches() {
    let engine = TrustFactEngine::new(vec![Arc::new(MismatchPairProducer)]);
    let subject = TrustSubject::message(b"rc5");

    // id matches ("abc" == "abc") but name differs
    let rule = require_facts_match::<LFact, RFact, _>(
        "mismatch_second",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("id", "id"), ("name", "name")],
        MissingBehavior::Deny,
        "PairDeny",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["PairDeny".to_string()]);
}

// ---------------------------------------------------------------------------
// Tests: require_facts_match – left property missing on selected fact
// ---------------------------------------------------------------------------

#[test]
fn require_facts_match_denies_when_left_property_is_missing() {
    let engine = TrustFactEngine::new(vec![Arc::new(MatchingPairProducer)]);
    let subject = TrustSubject::message(b"rc6");

    let rule = require_facts_match::<LFact, RFact, _>(
        "left_prop_missing",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("nonexistent", "id")],
        MissingBehavior::Deny,
        "PropMissing",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["PropMissing".to_string()]);
}

// ---------------------------------------------------------------------------
// Tests: require_facts_match – right property missing on selected fact
// ---------------------------------------------------------------------------

#[test]
fn require_facts_match_denies_when_right_property_is_missing() {
    let engine = TrustFactEngine::new(vec![Arc::new(MatchingPairProducer)]);
    let subject = TrustSubject::message(b"rc7");

    let rule = require_facts_match::<LFact, RFact, _>(
        "right_prop_missing",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("id", "nonexistent")],
        MissingBehavior::Deny,
        "PropMissing",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["PropMissing".to_string()]);
}

// ---------------------------------------------------------------------------
// Tests: require_fact_matches_with_missing_behavior – Allow when selector finds no match
// ---------------------------------------------------------------------------

#[test]
fn require_fact_matches_with_missing_behavior_allow_trusts_when_no_selector_match() {
    let engine = TrustFactEngine::new(vec![Arc::new(SimpleProducer { tag: "actual" })]);
    let subject = TrustSubject::message(b"rc8");

    // Facts are Available but the selector won't match any of them.
    let rule = require_fact_matches_with_missing_behavior::<SimpleFact, _>(
        "allow_no_match",
        |s: &TrustSubject| s.clone(),
        FactSelector::first().where_eq(
            "tag",
            cose_sign1_validation_primitives::fact_properties::FactValueOwned::String(
                "does_not_exist".to_string(),
            ),
        ),
        MissingBehavior::Allow,
        "Denied",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(d.is_trusted);
}

// ---------------------------------------------------------------------------
// Tests: require_fact_matches_with_missing_behavior – Deny when selector finds no match
// ---------------------------------------------------------------------------

#[test]
fn require_fact_matches_with_missing_behavior_deny_denies_when_no_selector_match() {
    let engine = TrustFactEngine::new(vec![Arc::new(SimpleProducer { tag: "actual" })]);
    let subject = TrustSubject::message(b"rc9");

    let rule = require_fact_matches_with_missing_behavior::<SimpleFact, _>(
        "deny_no_match",
        |s: &TrustSubject| s.clone(),
        FactSelector::first().where_eq(
            "tag",
            cose_sign1_validation_primitives::fact_properties::FactValueOwned::String(
                "does_not_exist".to_string(),
            ),
        ),
        MissingBehavior::Deny,
        "Denied",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["Denied".to_string()]);
}

// ---------------------------------------------------------------------------
// Tests: all_of – all rules trusted
// ---------------------------------------------------------------------------

#[test]
fn all_of_trusts_when_every_rule_trusts() {
    let engine = TrustFactEngine::new(vec![]);
    let subject = TrustSubject::message(b"rc10");

    let rule = all_of(
        "all_ok",
        vec![allow_all("a1"), allow_all("a2"), allow_all("a3")],
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(d.is_trusted);
    assert!(d.reasons.is_empty());
}

// ---------------------------------------------------------------------------
// Tests: require_facts_match – left selector finds no fact
// ---------------------------------------------------------------------------

#[test]
fn require_facts_match_denies_when_left_selector_yields_no_match() {
    let engine = TrustFactEngine::new(vec![Arc::new(MatchingPairProducer)]);
    let subject = TrustSubject::message(b"rc11");

    let rule = require_facts_match::<LFact, RFact, _>(
        "left_no_select",
        |s: &TrustSubject| s.clone(),
        FactSelector::first().where_eq(
            "id",
            cose_sign1_validation_primitives::fact_properties::FactValueOwned::String(
                "no_such_id".to_string(),
            ),
        ),
        FactSelector::first(),
        vec![("id", "id")],
        MissingBehavior::Deny,
        "NoLeft",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["NoLeft".to_string()]);
}

// ---------------------------------------------------------------------------
// Tests: require_facts_match – right selector finds no fact (Allow)
// ---------------------------------------------------------------------------

#[test]
fn require_facts_match_trusts_when_right_selector_misses_with_allow() {
    let engine = TrustFactEngine::new(vec![Arc::new(MatchingPairProducer)]);
    let subject = TrustSubject::message(b"rc12");

    let rule = require_facts_match::<LFact, RFact, _>(
        "right_no_select_allow",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first().where_eq(
            "id",
            cose_sign1_validation_primitives::fact_properties::FactValueOwned::String(
                "no_such_id".to_string(),
            ),
        ),
        vec![("id", "id")],
        MissingBehavior::Allow,
        "NoRight",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(d.is_trusted);
}

// ---------------------------------------------------------------------------
// Tests: require_facts_match – right selector finds no fact (Deny)
// ---------------------------------------------------------------------------

#[test]
fn require_facts_match_denies_when_right_selector_misses_with_deny() {
    let engine = TrustFactEngine::new(vec![Arc::new(MatchingPairProducer)]);
    let subject = TrustSubject::message(b"rc13");

    let rule = require_facts_match::<LFact, RFact, _>(
        "right_no_select_deny",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first().where_eq(
            "id",
            cose_sign1_validation_primitives::fact_properties::FactValueOwned::String(
                "no_such_id".to_string(),
            ),
        ),
        vec![("id", "id")],
        MissingBehavior::Deny,
        "NoRight",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["NoRight".to_string()]);
}
