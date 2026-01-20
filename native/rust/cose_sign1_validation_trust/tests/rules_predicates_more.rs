// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::error::TrustError;
use cose_sign1_validation_trust::fact_properties::{FactProperties, FactValue, FactValueOwned};
use cose_sign1_validation_trust::facts::{FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer};
use cose_sign1_validation_trust::rules::{
    require_any, require_bool, require_fact_matches_with_missing_behavior, require_fact_property,
    require_fact_matches, require_fact_property_eq, require_present, FactSelector, MissingBehavior,
    PropertyPredicate,
};
use cose_sign1_validation_trust::subject::TrustSubject;
use std::borrow::Cow;
use std::sync::Arc;

#[derive(Debug, Clone)]
struct BoolFact {
    ok: bool,
}

struct BoolFactProducer {
    mode: &'static str,
}

impl TrustFactProducer for BoolFactProducer {
    fn name(&self) -> &'static str {
        "bool_fact_producer"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<BoolFact>()]).as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() != FactKey::of::<BoolFact>() {
            return Ok(());
        }

        match self.mode {
            "available" => {
                ctx.observe(BoolFact { ok: false })?;
                ctx.observe(BoolFact { ok: true })?;
            }
            "missing" => ctx.mark_missing::<BoolFact>("NoBoolFact"),
            "error" => ctx.mark_error::<BoolFact>("Boom"),
            _ => {}
        }

        ctx.mark_produced(FactKey::of::<BoolFact>());
        Ok(())
    }
}

#[test]
fn require_any_present_bool_cover_available_missing_and_error_branches() {
    let subject = TrustSubject::message(b"msg");

    // Available: predicate matches one element.
    let engine = TrustFactEngine::new(vec![Arc::new(BoolFactProducer { mode: "available" })]);
    let rule = require_any::<BoolFact, _, _>(
        "any_ok",
        |s: &TrustSubject| s.clone(),
        |f| f.ok,
        "NoMatch",
    );
    assert!(rule.evaluate(&engine, &subject).unwrap().is_trusted);

    // Available: predicate matches none.
    let rule = require_any::<BoolFact, _, _>(
        "any_false",
        |s: &TrustSubject| s.clone(),
        |f| !f.ok && false,
        "NoMatch",
    );
    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["NoMatch".to_string()]);

    // Missing -> denied with formatted reason.
    let engine = TrustFactEngine::new(vec![Arc::new(BoolFactProducer { mode: "missing" })]);
    let rule = require_present::<BoolFact, _>("present", |s: &TrustSubject| s.clone(), "Nope");
    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["Nope: NoBoolFact".to_string()]);

    // Error -> denied with formatted message.
    let engine = TrustFactEngine::new(vec![Arc::new(BoolFactProducer { mode: "error" })]);
    let rule = require_bool::<BoolFact, _, _>(
        "bool_true",
        |s: &TrustSubject| s.clone(),
        |f| f.ok,
        true,
        "Nope",
    );
    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["Nope: Boom".to_string()]);
}

#[derive(Debug, Clone)]
struct PropsFact {
    s: String,
    ws: String,
    u: u32,
    n: usize,
    b: bool,
    i: i64,
}

impl FactProperties for PropsFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "s" => Some(FactValue::Str(Cow::Borrowed(self.s.as_str()))),
            "ws" => Some(FactValue::Str(Cow::Borrowed(self.ws.as_str()))),
            "u" => Some(FactValue::U32(self.u)),
            "n" => Some(FactValue::Usize(self.n)),
            "b" => Some(FactValue::Bool(self.b)),
            "i" => Some(FactValue::I64(self.i)),
            _ => None,
        }
    }
}

struct PropsProducer;

impl TrustFactProducer for PropsProducer {
    fn name(&self) -> &'static str {
        "props"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<PropsFact>()]).as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() != FactKey::of::<PropsFact>() {
            return Ok(());
        }

        ctx.observe(PropsFact {
            s: "hello-world".to_string(),
            ws: "   ".to_string(),
            u: 10,
            n: 5,
            b: true,
            i: -5,
        })?;
        ctx.mark_produced(FactKey::of::<PropsFact>());
        Ok(())
    }
}

#[test]
fn property_predicates_cover_unhit_variants_and_type_mismatches() {
    let subject = TrustSubject::message(b"msg");
    let engine = TrustFactEngine::new(vec![Arc::new(PropsProducer)]);

    let starts = require_fact_property::<PropsFact, _>(
        "starts",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "s",
        PropertyPredicate::StrStartsWith("hello".to_string()),
        "NoMatch",
    );
    assert!(starts.evaluate(&engine, &subject).unwrap().is_trusted);

    let ends = require_fact_property::<PropsFact, _>(
        "ends",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "s",
        PropertyPredicate::StrEndsWith("world".to_string()),
        "NoMatch",
    );
    assert!(ends.evaluate(&engine, &subject).unwrap().is_trusted);

    let not_eq = require_fact_property_eq::<PropsFact, _>(
        "not_eq",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "s",
        FactValueOwned::String("not-the-same".to_string()),
        "NoMatch",
    );
    // Eq(not-the-same) should deny.
    assert!(!not_eq.evaluate(&engine, &subject).unwrap().is_trusted);

    let not_eq_pred = require_fact_property::<PropsFact, _>(
        "not_eq_pred",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "s",
        PropertyPredicate::NotEq(FactValueOwned::String("nope".to_string())),
        "NoMatch",
    );
    assert!(not_eq_pred.evaluate(&engine, &subject).unwrap().is_trusted);

    // Whitespace-only string should fail StrNonEmpty.
    let non_empty = require_fact_property::<PropsFact, _>(
        "non_empty",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "ws",
        PropertyPredicate::StrNonEmpty,
        "NoMatch",
    );
    assert!(!non_empty.evaluate(&engine, &subject).unwrap().is_trusted);

    // Invalid regex should be treated as non-match.
    let bad_regex = require_fact_property::<PropsFact, _>(
        "bad_regex",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "s",
        PropertyPredicate::StrMatchesRegex("(".to_string()),
        "NoMatch",
    );
    assert!(!bad_regex.evaluate(&engine, &subject).unwrap().is_trusted);

    // Valid regex should match.
    let good_regex = require_fact_property::<PropsFact, _>(
        "good_regex",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "s",
        PropertyPredicate::StrMatchesRegex("hello.*world".to_string()),
        "NoMatch",
    );
    assert!(good_regex.evaluate(&engine, &subject).unwrap().is_trusted);

    // StrContains success path.
    let contains = require_fact_property::<PropsFact, _>(
        "contains",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "s",
        PropertyPredicate::StrContains("world".to_string()),
        "NoMatch",
    );
    assert!(contains.evaluate(&engine, &subject).unwrap().is_trusted);

    // Numeric comparisons: cover U32/Usize paths.
    let num_le = require_fact_property::<PropsFact, _>(
        "num_le",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "u",
        PropertyPredicate::NumLeI64(10),
        "NoMatch",
    );
    assert!(num_le.evaluate(&engine, &subject).unwrap().is_trusted);

    let num_ge_usize = require_fact_property::<PropsFact, _>(
        "num_ge_usize",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "n",
        PropertyPredicate::NumGeI64(5),
        "NoMatch",
    );
    assert!(num_ge_usize.evaluate(&engine, &subject).unwrap().is_trusted);

    // Numeric comparisons: cover I64 paths.
    let num_ge_i64 = require_fact_property::<PropsFact, _>(
        "num_ge_i64",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "i",
        PropertyPredicate::NumGeI64(-5),
        "NoMatch",
    );
    assert!(num_ge_i64.evaluate(&engine, &subject).unwrap().is_trusted);

    let num_le_i64 = require_fact_property::<PropsFact, _>(
        "num_le_i64",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "i",
        PropertyPredicate::NumLeI64(-5),
        "NoMatch",
    );
    assert!(num_le_i64.evaluate(&engine, &subject).unwrap().is_trusted);

    // Type mismatch: StrContains applied to a numeric property should deny.
    let type_mismatch = require_fact_property::<PropsFact, _>(
        "type_mismatch",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "u",
        PropertyPredicate::StrContains("10".to_string()),
        "NoMatch",
    );
    assert!(!type_mismatch.evaluate(&engine, &subject).unwrap().is_trusted);
}

#[test]
fn fact_selector_convenience_methods_build_and_match() {
    let subject = TrustSubject::message(b"msg");
    let engine = TrustFactEngine::new(vec![Arc::new(PropsProducer)]);

    let selector = FactSelector::first()
        .where_bool("b", true)
        .where_u32("u", 10)
        .where_usize("n", 5)
        .where_i64("i", -5)
        .where_eq("s", FactValueOwned::String("hello-world".to_string()));

    let rule = require_fact_matches::<PropsFact, _>(
        "selector_convenience",
        |s: &TrustSubject| s.clone(),
        selector,
        "NoMatch",
    );

    assert!(rule.evaluate(&engine, &subject).unwrap().is_trusted);
}

#[derive(Debug, Clone)]
struct MissingFact;

impl FactProperties for MissingFact {
    fn get_property<'a>(&'a self, _name: &str) -> Option<FactValue<'a>> {
        None
    }
}

struct MissingProducer;

impl TrustFactProducer for MissingProducer {
    fn name(&self) -> &'static str {
        "missing"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<MissingFact>()]).as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        ctx.mark_missing::<MissingFact>("Nope");
        ctx.mark_produced(FactKey::of::<MissingFact>());
        Ok(())
    }
}

struct ErrorProducer;

impl TrustFactProducer for ErrorProducer {
    fn name(&self) -> &'static str {
        "error"
    }

    fn provides(&self) -> &'static [FactKey] {
        MissingProducer.provides()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        ctx.mark_error::<MissingFact>("Boom");
        ctx.mark_produced(FactKey::of::<MissingFact>());
        Ok(())
    }
}

#[test]
fn require_fact_matches_with_missing_behavior_allow_can_succeed() {
    let subject = TrustSubject::message(b"msg");
    let engine = TrustFactEngine::new(vec![Arc::new(MissingProducer)]);

    // Selector doesn't matter; MissingBehavior::Allow should short-circuit to trusted.
    let rule = require_fact_matches_with_missing_behavior::<MissingFact, _>(
        "allow_when_missing",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        MissingBehavior::Allow,
        "NoMatch",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(d.is_trusted);
    assert_eq!(d.reasons, Vec::<String>::new());
}

#[test]
fn require_fact_matches_with_missing_behavior_deny_on_missing_and_allow_on_error() {
    let subject = TrustSubject::message(b"msg");

    // Missing + Deny => denied with the caller's deny reason.
    let engine = TrustFactEngine::new(vec![Arc::new(MissingProducer)]);
    let deny_when_missing = require_fact_matches_with_missing_behavior::<MissingFact, _>(
        "deny_when_missing",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        MissingBehavior::Deny,
        "NoMatch",
    );
    let d = deny_when_missing.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["NoMatch".to_string()]);

    // Error + Allow => trusted.
    let engine = TrustFactEngine::new(vec![Arc::new(ErrorProducer)]);
    let allow_on_error = require_fact_matches_with_missing_behavior::<MissingFact, _>(
        "allow_on_error",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        MissingBehavior::Allow,
        "NoMatch",
    );
    let d = allow_on_error.evaluate(&engine, &subject).unwrap();
    assert!(d.is_trusted);
}

#[test]
fn require_fact_matches_denies_with_formatted_reasons_for_missing_and_error_sets() {
    let subject = TrustSubject::message(b"msg");

    let rule = require_fact_matches::<MissingFact, _>(
        "req",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "NoMatch",
    );

    let engine = TrustFactEngine::new(vec![Arc::new(MissingProducer)]);
    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["NoMatch: Nope".to_string()]);

    let engine = TrustFactEngine::new(vec![Arc::new(ErrorProducer)]);
    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["NoMatch: Boom".to_string()]);
}

#[test]
fn require_fact_property_denies_with_formatted_reasons_for_missing_and_error_sets() {
    let subject = TrustSubject::message(b"msg");

    let rule = require_fact_property::<MissingFact, _>(
        "req_prop",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "x",
        PropertyPredicate::StrNonEmpty,
        "NoMatch",
    );

    let engine = TrustFactEngine::new(vec![Arc::new(MissingProducer)]);
    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["NoMatch: Nope".to_string()]);

    let engine = TrustFactEngine::new(vec![Arc::new(ErrorProducer)]);
    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert_eq!(d.reasons, vec!["NoMatch: Boom".to_string()]);
}

#[test]
fn property_predicate_type_mismatch_paths_are_exercised() {
    let subject = TrustSubject::message(b"msg");
    let engine = TrustFactEngine::new(vec![Arc::new(PropsProducer)]);

    let starts_on_num = require_fact_property::<PropsFact, _>(
        "starts_on_num",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "u",
        PropertyPredicate::StrStartsWith("1".to_string()),
        "NoMatch",
    );
    assert!(!starts_on_num.evaluate(&engine, &subject).unwrap().is_trusted);

    let ends_on_num = require_fact_property::<PropsFact, _>(
        "ends_on_num",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "u",
        PropertyPredicate::StrEndsWith("0".to_string()),
        "NoMatch",
    );
    assert!(!ends_on_num.evaluate(&engine, &subject).unwrap().is_trusted);

    let regex_on_num = require_fact_property::<PropsFact, _>(
        "regex_on_num",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "u",
        PropertyPredicate::StrMatchesRegex(".*".to_string()),
        "NoMatch",
    );
    assert!(!regex_on_num.evaluate(&engine, &subject).unwrap().is_trusted);

    let num_on_str = require_fact_property::<PropsFact, _>(
        "num_on_str",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "s",
        PropertyPredicate::NumGeI64(1),
        "NoMatch",
    );
    assert!(!num_on_str.evaluate(&engine, &subject).unwrap().is_trusted);
}
