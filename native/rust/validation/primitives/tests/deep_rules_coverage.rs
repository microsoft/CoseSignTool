// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for validation primitives rules.rs.
//!
//! Targets uncovered lines in rules.rs:
//! - PropertyPredicate variants driven via require_fact_property
//! - require_fact_property with Missing/Error fact sets
//! - require_fact_matches with Missing/Error fact sets
//! - require_fact_matches_with_missing_behavior Allow paths
//! - require_fact_bool, require_fact_str_non_empty
//! - AuditedRule wrapper
//! - not / not_with_reason
//! - AnyOf empty rules, AnyOf all denied
//! - FactSelector convenience builders

extern crate cbor_primitives_everparse;

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::Mutex;

use cose_sign1_validation_primitives::audit::TrustDecisionAuditBuilder;
use cose_sign1_validation_primitives::error::TrustError;
use cose_sign1_validation_primitives::fact_properties::{FactProperties, FactValue, FactValueOwned};
use cose_sign1_validation_primitives::facts::{
    FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer,
};
use cose_sign1_validation_primitives::rules::*;
use cose_sign1_validation_primitives::subject::TrustSubject;

// =========================================================================
// Test fact types
// =========================================================================

#[derive(Debug, Clone)]
struct NumFact {
    name: String,
    count: i64,
    active: bool,
    size_u32: u32,
    index: usize,
}

impl FactProperties for NumFact {
    fn get_property(&self, prop: &str) -> Option<FactValue<'_>> {
        match prop {
            "name" => Some(FactValue::Str(Cow::Borrowed(&self.name))),
            "count" => Some(FactValue::I64(self.count)),
            "active" => Some(FactValue::Bool(self.active)),
            "size_u32" => Some(FactValue::U32(self.size_u32)),
            "index" => Some(FactValue::Usize(self.index)),
            _ => None,
        }
    }
}

// =========================================================================
// Producers
// =========================================================================

struct NumFactProducer {
    fact: NumFact,
}

impl TrustFactProducer for NumFactProducer {
    fn name(&self) -> &'static str {
        "num_fact_producer"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<NumFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<NumFact>() {
            ctx.observe(self.fact.clone())?;
            ctx.mark_produced(FactKey::of::<NumFact>());
        }
        Ok(())
    }
}

struct MissingFactProducer;

impl TrustFactProducer for MissingFactProducer {
    fn name(&self) -> &'static str {
        "missing_fact_producer"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<NumFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<NumFact>() {
            ctx.mark_missing::<NumFact>("fact_unavailable");
            ctx.mark_produced(FactKey::of::<NumFact>());
        }
        Ok(())
    }
}

struct ErrorFactProducer;

impl TrustFactProducer for ErrorFactProducer {
    fn name(&self) -> &'static str {
        "error_fact_producer"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<NumFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<NumFact>() {
            ctx.mark_error::<NumFact>("producer_error");
            ctx.mark_produced(FactKey::of::<NumFact>());
        }
        Ok(())
    }
}

fn make_engine(producer: impl TrustFactProducer + 'static) -> TrustFactEngine {
    TrustFactEngine::new(vec![Arc::new(producer)])
}

fn subject() -> TrustSubject {
    TrustSubject::message(b"deep_rules_test")
}

fn id(s: &TrustSubject) -> TrustSubject {
    s.clone()
}

fn default_num_fact() -> NumFact {
    NumFact {
        name: "test-value".to_string(),
        count: 42,
        active: true,
        size_u32: 10,
        index: 5,
    }
}

// =========================================================================
// Rule combinators: allow_all, all_of, any_of, not, not_with_reason
// =========================================================================

#[test]
fn allow_all_returns_trusted() {
    let rule = allow_all("test_allow_all");
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
    assert_eq!(rule.name(), "test_allow_all");
}

#[test]
fn all_of_all_trusted() {
    let rules = vec![allow_all("r1"), allow_all("r2")];
    let rule = all_of("all_trusted", rules);
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn all_of_one_denied() {
    let deny_rule = not("deny", allow_all("inner"));
    let rules = vec![allow_all("r1"), deny_rule];
    let rule = all_of("one_denied", rules);
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn any_of_empty_rules_denies() {
    let rule = any_of("empty", vec![]);
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
    assert!(decision.reasons.iter().any(|r| r.contains("No trust sources")));
}

#[test]
fn any_of_one_trusted() {
    let deny_rule = not("deny", allow_all("inner"));
    let rules = vec![deny_rule, allow_all("ok")];
    let rule = any_of("one_ok", rules);
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn any_of_all_denied() {
    let deny1 = not("d1", allow_all("i1"));
    let deny2 = not("d2", allow_all("i2"));
    let rule = any_of("all_denied", vec![deny1, deny2]);
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn not_inverts_trusted_to_denied() {
    let rule = not("negate_allow", allow_all("inner"));
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
    assert!(decision.reasons.iter().any(|r| r.contains("Negated rule")));
}

#[test]
fn not_inverts_denied_to_trusted() {
    let deny = not("inner_deny", allow_all("deep"));
    let rule = not("double_neg", deny);
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn not_with_reason_custom_message() {
    let rule = not_with_reason("custom_negate", allow_all("inner"), "Custom deny reason");
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
    assert!(decision.reasons.iter().any(|r| r.contains("Custom deny reason")));
}

// =========================================================================
// AuditedRule coverage
// =========================================================================

#[test]
fn audited_rule_records_event() {
    let audit = Arc::new(Mutex::new(TrustDecisionAuditBuilder::default()));
    let inner = allow_all("audited_inner");
    let rule = AuditedRule::new(inner, audit.clone());
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
    // The audit builder was pushed to; we just verify it runs without error.
}

#[test]
fn audited_rule_name_delegates() {
    let audit = Arc::new(Mutex::new(TrustDecisionAuditBuilder::default()));
    let inner = allow_all("my_rule");
    let rule = AuditedRule::new(inner, audit);
    assert_eq!(rule.name(), "my_rule");
}

// =========================================================================
// require_fact_property via require_fact_property_eq and friends
// =========================================================================

#[test]
fn require_fact_property_eq_i64_match() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_property_eq::<NumFact, _>(
        "count_eq", id, FactSelector::first(), "count",
        FactValueOwned::I64(42), "count mismatch",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_property_eq_i64_no_match() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_property_eq::<NumFact, _>(
        "count_eq", id, FactSelector::first(), "count",
        FactValueOwned::I64(999), "count mismatch",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_fact_property_eq_missing_property() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_property_eq::<NumFact, _>(
        "missing_prop", id, FactSelector::first(), "nonexistent",
        FactValueOwned::I64(0), "missing property",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_fact_property_missing_fact_set() {
    let engine = make_engine(MissingFactProducer);
    let rule = require_fact_property_eq::<NumFact, _>(
        "missing_set", id, FactSelector::first(), "count",
        FactValueOwned::I64(42), "fact missing",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
    assert!(decision.reasons.iter().any(|r| r.contains("fact_unavailable")));
}

#[test]
fn require_fact_property_error_fact_set() {
    let engine = make_engine(ErrorFactProducer);
    let rule = require_fact_property_eq::<NumFact, _>(
        "error_set", id, FactSelector::first(), "count",
        FactValueOwned::I64(42), "fact error",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
    assert!(decision.reasons.iter().any(|r| r.contains("producer_error")));
}

// =========================================================================
// require_fact_property with different PropertyPredicate variants
// =========================================================================

#[test]
fn require_fact_property_str_non_empty() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_str_non_empty::<NumFact, _>(
        "name_non_empty", id, FactSelector::first(), "name", "name empty",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_property_str_non_empty_on_non_str() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_str_non_empty::<NumFact, _>(
        "count_non_empty", id, FactSelector::first(), "count", "not a string",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_fact_bool_match() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_bool::<NumFact, _>(
        "active_true", id, FactSelector::first(), "active", true, "not active",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_bool_mismatch() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_bool::<NumFact, _>(
        "active_false", id, FactSelector::first(), "active", false, "expected inactive",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

// =========================================================================
// require_fact_matches
// =========================================================================

#[test]
fn require_fact_matches_trusted() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_matches::<NumFact, _>(
        "match_any", id, FactSelector::first(), "no match",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_matches_missing_set() {
    let engine = make_engine(MissingFactProducer);
    let rule = require_fact_matches::<NumFact, _>(
        "match_missing", id, FactSelector::first(), "fact missing",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_fact_matches_error_set() {
    let engine = make_engine(ErrorFactProducer);
    let rule = require_fact_matches::<NumFact, _>(
        "match_error", id, FactSelector::first(), "fact error",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

// =========================================================================
// require_fact_matches_with_missing_behavior
// =========================================================================

#[test]
fn require_fact_matches_with_missing_allow() {
    let engine = make_engine(MissingFactProducer);
    let rule = require_fact_matches_with_missing_behavior::<NumFact, _>(
        "missing_allow", id, FactSelector::first(), MissingBehavior::Allow, "optional",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_matches_with_missing_deny() {
    let engine = make_engine(MissingFactProducer);
    let rule = require_fact_matches_with_missing_behavior::<NumFact, _>(
        "missing_deny", id, FactSelector::first(), MissingBehavior::Deny, "required",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_fact_matches_with_missing_behavior_no_match_allow() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_matches_with_missing_behavior::<NumFact, _>(
        "no_match_allow", id,
        FactSelector::first().where_bool("active", false),
        MissingBehavior::Allow, "optional",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_matches_with_missing_behavior_no_match_deny() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_matches_with_missing_behavior::<NumFact, _>(
        "no_match_deny", id,
        FactSelector::first().where_bool("active", false),
        MissingBehavior::Deny, "required",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

// =========================================================================
// require_fact_property with StrContains/StrStartsWith/StrEndsWith/NumGe/NumLe/NotEq
// =========================================================================

#[test]
fn require_fact_property_str_contains() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_property::<NumFact, _>(
        "name_contains", id, FactSelector::first(), "name",
        PropertyPredicate::StrContains("value".to_string()), "no contain",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_property_str_starts_with() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_property::<NumFact, _>(
        "name_starts", id, FactSelector::first(), "name",
        PropertyPredicate::StrStartsWith("test".to_string()), "no prefix",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_property_str_ends_with() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_property::<NumFact, _>(
        "name_ends", id, FactSelector::first(), "name",
        PropertyPredicate::StrEndsWith("value".to_string()), "no suffix",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_property_num_ge_i64() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_property::<NumFact, _>(
        "count_ge", id, FactSelector::first(), "count",
        PropertyPredicate::NumGeI64(40), "too small",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_property_num_le_i64() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_property::<NumFact, _>(
        "count_le", id, FactSelector::first(), "count",
        PropertyPredicate::NumLeI64(100), "too big",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_property_not_eq() {
    let engine = make_engine(NumFactProducer { fact: default_num_fact() });
    let rule = require_fact_property::<NumFact, _>(
        "count_ne", id, FactSelector::first(), "count",
        PropertyPredicate::NotEq(FactValueOwned::I64(999)), "unexpected value",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

// =========================================================================
// FactSelector convenience builders (exercised for coverage)
// =========================================================================

#[test]
fn fact_selector_where_eq_usage() {
    let _sel = FactSelector::first()
        .where_eq("name", FactValueOwned::String("test".to_string()));
}

#[test]
fn fact_selector_where_usize_usage() {
    let _sel = FactSelector::first().where_usize("index", 5);
}

#[test]
fn fact_selector_where_u32_usage() {
    let _sel = FactSelector::first().where_u32("size_u32", 10);
}

#[test]
fn fact_selector_where_i64_usage() {
    let _sel = FactSelector::first().where_i64("count", 42);
}

#[test]
fn fact_selector_where_pred_usage() {
    let _sel = FactSelector::first()
        .where_pred("name", PropertyPredicate::StrNonEmpty);
}

// =========================================================================
// Enum Debug/Clone/Eq coverage
// =========================================================================

#[test]
fn missing_behavior_debug_eq() {
    assert_eq!(format!("{:?}", MissingBehavior::Allow), "Allow");
    assert_ne!(MissingBehavior::Allow, MissingBehavior::Deny);
}

#[test]
fn on_empty_behavior_debug_eq() {
    assert_eq!(format!("{:?}", OnEmptyBehavior::Allow), "Allow");
    assert_ne!(OnEmptyBehavior::Allow, OnEmptyBehavior::Deny);
}

#[test]
fn property_predicate_debug_clone_eq() {
    let pred = PropertyPredicate::StrContains("hello".to_string());
    let cloned = pred.clone();
    assert_eq!(pred, cloned);
    assert!(!format!("{:?}", pred).is_empty());
}
