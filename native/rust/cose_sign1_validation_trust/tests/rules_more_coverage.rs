// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::error::TrustError;
use cose_sign1_validation_trust::audit::{AuditEvent, TrustDecisionAuditBuilder};
use cose_sign1_validation_trust::fact_properties::{FactProperties, FactValue, FactValueOwned};
use cose_sign1_validation_trust::facts::{FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer};
use cose_sign1_validation_trust::rules::{
    all_of, allow_all, any_of, not, not_with_reason,
    AuditedRule, require_fact_bool, require_fact_matches, require_fact_matches_with_missing_behavior,
    require_fact_property, require_fact_property_eq, require_fact_str_non_empty, require_facts_match,
    FactSelector, MissingBehavior,
};
use cose_sign1_validation_trust::subject::TrustSubject;
use cose_sign1_validation_trust::TrustDecision;
use parking_lot::Mutex;
use std::borrow::Cow;
use std::sync::Arc;

#[derive(Debug, Clone)]
struct PropFact {
    b: bool,
    s: String,
    n: usize,
    u: u32,
    i: i64,
}

impl FactProperties for PropFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "b" => Some(FactValue::Bool(self.b)),
            "s" => Some(FactValue::Str(Cow::Borrowed(self.s.as_str()))),
            "n" => Some(FactValue::Usize(self.n)),
            "u" => Some(FactValue::U32(self.u)),
            "i" => Some(FactValue::I64(self.i)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct LeftFact {
    v: String,
}

impl FactProperties for LeftFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "v" => Some(FactValue::Str(Cow::Borrowed(self.v.as_str()))),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct RightFact {
    v: String,
}

impl FactProperties for RightFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "v" => Some(FactValue::Str(Cow::Borrowed(self.v.as_str()))),
            _ => None,
        }
    }
}

struct MultiProducer;

impl TrustFactProducer for MultiProducer {
    fn name(&self) -> &'static str {
        "multi"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| {
            vec![
                FactKey::of::<PropFact>(),
                FactKey::of::<LeftFact>(),
                FactKey::of::<RightFact>(),
            ]
        })
        .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<PropFact>() {
            ctx.observe(PropFact {
                b: true,
                s: "hello".to_string(),
                n: 7,
                u: 42,
                i: -5,
            })?;
            ctx.observe(PropFact {
                b: false,
                s: "".to_string(),
                n: 0,
                u: 0,
                i: 0,
            })?;
            ctx.mark_produced(FactKey::of::<PropFact>());
            return Ok(());
        }

        if ctx.requested_fact() == FactKey::of::<LeftFact>() {
            ctx.observe(LeftFact { v: "same".to_string() })?;
            ctx.mark_produced(FactKey::of::<LeftFact>());
            return Ok(());
        }

        if ctx.requested_fact() == FactKey::of::<RightFact>() {
            ctx.observe(RightFact { v: "same".to_string() })?;
            ctx.mark_produced(FactKey::of::<RightFact>());
            return Ok(());
        }

        Ok(())
    }
}

struct ErrorProducer;

impl TrustFactProducer for ErrorProducer {
    fn name(&self) -> &'static str {
        "error"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<PropFact>()]).as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        ctx.mark_error::<PropFact>("boom");
        ctx.mark_produced(FactKey::of::<PropFact>());
        Ok(())
    }
}

struct EmptyRightProducer;

impl TrustFactProducer for EmptyRightProducer {
    fn name(&self) -> &'static str {
        "empty-right"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<LeftFact>(), FactKey::of::<RightFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<LeftFact>() {
            ctx.observe(LeftFact { v: "left".to_string() })?;
            ctx.mark_produced(FactKey::of::<LeftFact>());
            return Ok(());
        }

        if ctx.requested_fact() == FactKey::of::<RightFact>() {
            // Mark as produced but observe nothing => Available(empty)
            ctx.mark_produced(FactKey::of::<RightFact>());
            return Ok(());
        }

        Ok(())
    }
}

#[test]
fn require_fact_property_and_matches_cover_common_branches() {
    let engine = TrustFactEngine::new(vec![Arc::new(MultiProducer)]);
    let subject = TrustSubject::message(b"msg");

    let s = |x: &TrustSubject| x.clone();

    let rule_ok = require_fact_property_eq::<PropFact, _>(
        "prop_eq",
        s,
        FactSelector::first().where_bool("b", true),
        "s",
        FactValueOwned::String("hello".to_string()),
        "NoMatch",
    );
    assert!(rule_ok.evaluate(&engine, &subject).unwrap().is_trusted);

    let rule_bad = require_fact_property::<PropFact, _>(
        "prop_pred",
        |x: &TrustSubject| x.clone(),
        FactSelector::first().where_usize("n", 7),
        "s",
        cose_sign1_validation_trust::rules::PropertyPredicate::StrContains("nope".to_string()),
        "NoMatch",
    );
    assert!(!rule_bad.evaluate(&engine, &subject).unwrap().is_trusted);

    let rule_missing_property = require_fact_property::<PropFact, _>(
        "prop_missing",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        "does_not_exist",
        cose_sign1_validation_trust::rules::PropertyPredicate::StrNonEmpty,
        "NoMatch",
    );
    assert!(!rule_missing_property
        .evaluate(&engine, &subject)
        .unwrap()
        .is_trusted);

    let rule_fact_matches = require_fact_matches::<PropFact, _>(
        "matches",
        |x: &TrustSubject| x.clone(),
        FactSelector::first().where_u32("u", 42).where_i64("i", -5),
        "NoMatch",
    );
    assert!(rule_fact_matches.evaluate(&engine, &subject).unwrap().is_trusted);

    let rule_bool = require_fact_bool::<PropFact, _>(
        "bool",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        "b",
        true,
        "NoMatch",
    );
    assert!(rule_bool.evaluate(&engine, &subject).unwrap().is_trusted);

    let rule_non_empty = require_fact_str_non_empty::<PropFact, _>(
        "non_empty",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        "s",
        "NoMatch",
    );
    assert!(rule_non_empty.evaluate(&engine, &subject).unwrap().is_trusted);
}

#[test]
fn require_fact_matches_with_missing_behavior_handles_error() {
    let engine = TrustFactEngine::new(vec![Arc::new(ErrorProducer)]);
    let subject = TrustSubject::message(b"msg");

    let allow_on_error = require_fact_matches_with_missing_behavior::<PropFact, _>(
        "allow",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        MissingBehavior::Allow,
        "NoMatch",
    );
    assert!(allow_on_error.evaluate(&engine, &subject).unwrap().is_trusted);

    let deny_on_error = require_fact_matches_with_missing_behavior::<PropFact, _>(
        "deny",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        MissingBehavior::Deny,
        "NoMatch",
    );
    assert!(!deny_on_error.evaluate(&engine, &subject).unwrap().is_trusted);
}

#[test]
fn property_predicates_cover_more_match_arms() {
    use cose_sign1_validation_trust::rules::PropertyPredicate;

    let engine = TrustFactEngine::new(vec![Arc::new(MultiProducer)]);
    let subject = TrustSubject::message(b"msg");

    let not_eq = require_fact_property::<PropFact, _>(
        "not_eq",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        "s",
        PropertyPredicate::NotEq(FactValueOwned::String("nope".to_string())),
        "NoMatch",
    );
    assert!(not_eq.evaluate(&engine, &subject).unwrap().is_trusted);

    let starts = require_fact_property::<PropFact, _>(
        "starts",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        "s",
        PropertyPredicate::StrStartsWith("he".to_string()),
        "NoMatch",
    );
    assert!(starts.evaluate(&engine, &subject).unwrap().is_trusted);

    let ends = require_fact_property::<PropFact, _>(
        "ends",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        "s",
        PropertyPredicate::StrEndsWith("lo".to_string()),
        "NoMatch",
    );
    assert!(ends.evaluate(&engine, &subject).unwrap().is_trusted);

    let bad_re = require_fact_property::<PropFact, _>(
        "bad_re",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        "s",
        PropertyPredicate::StrMatchesRegex("[".to_string()),
        "NoMatch",
    );
    assert!(!bad_re.evaluate(&engine, &subject).unwrap().is_trusted);

    let ge_u32 = require_fact_property::<PropFact, _>(
        "ge_u32",
        |x: &TrustSubject| x.clone(),
        FactSelector::first().where_u32("u", 42),
        "u",
        PropertyPredicate::NumGeI64(40),
        "NoMatch",
    );
    assert!(ge_u32.evaluate(&engine, &subject).unwrap().is_trusted);

    let le_usize = require_fact_property::<PropFact, _>(
        "le_usize",
        |x: &TrustSubject| x.clone(),
        FactSelector::first().where_usize("n", 7),
        "n",
        PropertyPredicate::NumLeI64(7),
        "NoMatch",
    );
    assert!(le_usize.evaluate(&engine, &subject).unwrap().is_trusted);
}

#[test]
fn property_predicates_return_false_on_type_mismatch() {
    use cose_sign1_validation_trust::rules::PropertyPredicate;

    let engine = TrustFactEngine::new(vec![Arc::new(MultiProducer)]);
    let subject = TrustSubject::message(b"msg");

    // String predicates should return false when the property is not a string.
    let non_empty_on_bool = require_fact_property::<PropFact, _>(
        "non_empty_on_bool",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        "b",
        PropertyPredicate::StrNonEmpty,
        "NoMatch",
    );
    assert!(!non_empty_on_bool
        .evaluate(&engine, &subject)
        .unwrap()
        .is_trusted);

    let contains_on_u32 = require_fact_property::<PropFact, _>(
        "contains_on_u32",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        "u",
        PropertyPredicate::StrContains("x".to_string()),
        "NoMatch",
    );
    assert!(!contains_on_u32
        .evaluate(&engine, &subject)
        .unwrap()
        .is_trusted);

    // Numeric predicates should return false when the property is not numeric.
    let ge_on_str = require_fact_property::<PropFact, _>(
        "ge_on_str",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        "s",
        PropertyPredicate::NumGeI64(0),
        "NoMatch",
    );
    assert!(!ge_on_str.evaluate(&engine, &subject).unwrap().is_trusted);

    let le_on_bool = require_fact_property::<PropFact, _>(
        "le_on_bool",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        "b",
        PropertyPredicate::NumLeI64(1),
        "NoMatch",
    );
    assert!(!le_on_bool.evaluate(&engine, &subject).unwrap().is_trusted);
}

#[test]
fn selectors_and_fact_set_missing_error_branches_are_exercised() {
    // Cover FactSelector::matches() missing-property branch by using a selector filter
    // that references a non-existent property.
    let engine = TrustFactEngine::new(vec![Arc::new(MultiProducer)]);
    let subject = TrustSubject::message(b"msg");

    let deny_when_selector_filter_property_missing = require_fact_matches::<PropFact, _>(
        "selector_filter_missing_property",
        |x: &TrustSubject| x.clone(),
        FactSelector::first().where_eq("does_not_exist", FactValueOwned::Bool(true)),
        "NoMatch",
    );
    assert!(!deny_when_selector_filter_property_missing
        .evaluate(&engine, &subject)
        .unwrap()
        .is_trusted);

    // Cover require_fact_property() path where no facts match the selector.
    let deny_when_no_fact_matches_selector = require_fact_property::<PropFact, _>(
        "no_fact_matches_selector",
        |x: &TrustSubject| x.clone(),
        FactSelector::first().where_eq("s", FactValueOwned::String("nope".to_string())),
        "s",
        cose_sign1_validation_trust::rules::PropertyPredicate::StrNonEmpty,
        "NoMatch",
    );
    assert!(!deny_when_no_fact_matches_selector
        .evaluate(&engine, &subject)
        .unwrap()
        .is_trusted);

    // Cover require_fact_matches() deny branch when selector yields no match.
    let deny_when_require_fact_matches_no_match = require_fact_matches::<PropFact, _>(
        "require_fact_matches_no_match",
        |x: &TrustSubject| x.clone(),
        FactSelector::first().where_u32("u", 999),
        "NoMatch",
    );
    assert!(!deny_when_require_fact_matches_no_match
        .evaluate(&engine, &subject)
        .unwrap()
        .is_trusted);

    // Cover require_facts_match() fact-set Missing/Error formatting branches.
    struct MissingLeftProducer;
    impl TrustFactProducer for MissingLeftProducer {
        fn name(&self) -> &'static str {
            "missing-left"
        }

        fn provides(&self) -> &'static [FactKey] {
            static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
            ONCE.get_or_init(|| vec![FactKey::of::<LeftFact>(), FactKey::of::<RightFact>()])
                .as_slice()
        }

        fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
            if ctx.requested_fact() == FactKey::of::<LeftFact>() {
                ctx.mark_missing::<LeftFact>("MissingLeft");
                ctx.mark_produced(FactKey::of::<LeftFact>());
                return Ok(());
            }

            if ctx.requested_fact() == FactKey::of::<RightFact>() {
                ctx.observe(RightFact { v: "same".to_string() })?;
                ctx.mark_produced(FactKey::of::<RightFact>());
                return Ok(());
            }

            Ok(())
        }
    }

    struct ErrorRightProducer;
    impl TrustFactProducer for ErrorRightProducer {
        fn name(&self) -> &'static str {
            "error-right"
        }

        fn provides(&self) -> &'static [FactKey] {
            static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
            ONCE.get_or_init(|| vec![FactKey::of::<LeftFact>(), FactKey::of::<RightFact>()])
                .as_slice()
        }

        fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
            if ctx.requested_fact() == FactKey::of::<LeftFact>() {
                ctx.observe(LeftFact { v: "same".to_string() })?;
                ctx.mark_produced(FactKey::of::<LeftFact>());
                return Ok(());
            }

            if ctx.requested_fact() == FactKey::of::<RightFact>() {
                ctx.mark_error::<RightFact>("BoomRight");
                ctx.mark_produced(FactKey::of::<RightFact>());
                return Ok(());
            }

            Ok(())
        }
    }

    let require_pair = |engine: &TrustFactEngine| {
        require_facts_match::<LeftFact, RightFact, _>(
            "pair",
            |x: &TrustSubject| x.clone(),
            FactSelector::first(),
            FactSelector::first(),
            vec![("v", "v")],
            MissingBehavior::Deny,
            "PairNoMatch",
        )
        .evaluate(engine, &subject)
        .unwrap()
    };

    let missing_left_engine = TrustFactEngine::new(vec![Arc::new(MissingLeftProducer)]);
    let d1 = require_pair(&missing_left_engine);
    assert!(!d1.is_trusted);

    let error_right_engine = TrustFactEngine::new(vec![Arc::new(ErrorRightProducer)]);
    let d2 = require_pair(&error_right_engine);
    assert!(!d2.is_trusted);
}

#[test]
fn require_facts_match_allows_or_denies_when_right_empty() {
    let engine = TrustFactEngine::new(vec![Arc::new(EmptyRightProducer)]);
    let subject = TrustSubject::message(b"msg");

    let allow = require_facts_match::<LeftFact, RightFact, _>(
        "allow",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("v", "v")],
        MissingBehavior::Allow,
        "NoMatch",
    );
    assert!(allow.evaluate(&engine, &subject).unwrap().is_trusted);

    let deny = require_facts_match::<LeftFact, RightFact, _>(
        "deny",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("v", "v")],
        MissingBehavior::Deny,
        "NoMatch",
    );
    assert!(!deny.evaluate(&engine, &subject).unwrap().is_trusted);
}

#[test]
fn require_facts_match_denies_on_property_mismatch() {
    struct MismatchProducer;

    impl TrustFactProducer for MismatchProducer {
        fn name(&self) -> &'static str {
            "mismatch"
        }

        fn provides(&self) -> &'static [FactKey] {
            static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
            ONCE.get_or_init(|| vec![FactKey::of::<LeftFact>(), FactKey::of::<RightFact>()])
                .as_slice()
        }

        fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
            if ctx.requested_fact() == FactKey::of::<LeftFact>() {
                ctx.observe(LeftFact { v: "left".to_string() })?;
                ctx.mark_produced(FactKey::of::<LeftFact>());
                return Ok(());
            }

            if ctx.requested_fact() == FactKey::of::<RightFact>() {
                ctx.observe(RightFact { v: "right".to_string() })?;
                ctx.mark_produced(FactKey::of::<RightFact>());
                return Ok(());
            }

            Ok(())
        }
    }

    let engine = TrustFactEngine::new(vec![Arc::new(MismatchProducer)]);
    let subject = TrustSubject::message(b"msg");

    let rule = require_facts_match::<LeftFact, RightFact, _>(
        "mismatch",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("v", "v")],
        MissingBehavior::Deny,
        "NoMatch",
    );

    let d: TrustDecision = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
}

#[test]
fn rule_combinator_names_are_exposed() {
    let a = allow_all("allow_all_rule");
    assert_eq!("allow_all_rule", a.name());

    let all = all_of("all", vec![allow_all("inner")]);
    assert_eq!("all", all.name());

    let any = any_of("any", vec![allow_all("inner")]);
    assert_eq!("any", any.name());

    let neg = not("not", allow_all("inner"));
    assert_eq!("not", neg.name());

    let neg2 = not_with_reason("not2", allow_all("inner"), "reason");
    assert_eq!("not2", neg2.name());
}

#[test]
fn require_facts_match_denies_when_left_selector_finds_no_fact() {
    let engine = TrustFactEngine::new(vec![Arc::new(MultiProducer)]);
    let subject = TrustSubject::message(b"msg");

    let rule = require_facts_match::<LeftFact, RightFact, _>(
        "no_left",
        |x: &TrustSubject| x.clone(),
        FactSelector::first().where_eq("v", FactValueOwned::String("nope".to_string())),
        FactSelector::first(),
        vec![("v", "v")],
        MissingBehavior::Deny,
        "NoMatch",
    );

    assert!(!rule.evaluate(&engine, &subject).unwrap().is_trusted);
}

#[test]
fn require_facts_match_denies_when_properties_are_missing_on_selected_facts() {
    let engine = TrustFactEngine::new(vec![Arc::new(MultiProducer)]);
    let subject = TrustSubject::message(b"msg");

    let missing_left_prop = require_facts_match::<LeftFact, RightFact, _>(
        "missing_left_prop",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("missing", "v")],
        MissingBehavior::Deny,
        "NoMatch",
    );
    assert!(!missing_left_prop
        .evaluate(&engine, &subject)
        .unwrap()
        .is_trusted);

    let missing_right_prop = require_facts_match::<LeftFact, RightFact, _>(
        "missing_right_prop",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("v", "missing")],
        MissingBehavior::Deny,
        "NoMatch",
    );
    assert!(!missing_right_prop
        .evaluate(&engine, &subject)
        .unwrap()
        .is_trusted);
}

#[test]
fn require_facts_match_denies_when_right_fact_set_is_missing() {
    struct MissingRightSetProducer;

    impl TrustFactProducer for MissingRightSetProducer {
        fn name(&self) -> &'static str {
            "missing_right_set"
        }

        fn provides(&self) -> &'static [FactKey] {
            static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
            ONCE.get_or_init(|| vec![FactKey::of::<LeftFact>(), FactKey::of::<RightFact>()])
                .as_slice()
        }

        fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
            if ctx.requested_fact() == FactKey::of::<LeftFact>() {
                ctx.observe(LeftFact { v: "left".to_string() })?;
                ctx.mark_produced(FactKey::of::<LeftFact>());
                return Ok(());
            }

            if ctx.requested_fact() == FactKey::of::<RightFact>() {
                ctx.mark_missing::<RightFact>("MissingRight");
                ctx.mark_produced(FactKey::of::<RightFact>());
                return Ok(());
            }

            Ok(())
        }
    }

    let engine = TrustFactEngine::new(vec![Arc::new(MissingRightSetProducer)]);
    let subject = TrustSubject::message(b"msg");

    let rule = require_facts_match::<LeftFact, RightFact, _>(
        "missing_right_set",
        |x: &TrustSubject| x.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("v", "v")],
        MissingBehavior::Deny,
        "NoMatch",
    );

    assert!(!rule.evaluate(&engine, &subject).unwrap().is_trusted);
}

#[test]
fn audited_rule_records_rule_evaluation_events() {
    let subject = TrustSubject::message(b"msg");
    let engine = TrustFactEngine::new(vec![]);

    let audit = Arc::new(Mutex::new(TrustDecisionAuditBuilder::default()));
    let audited = AuditedRule::new(allow_all("allow_all"), audit.clone());
    assert_eq!("allow_all", audited.name());

    let decision = audited.evaluate(&engine, &subject).unwrap();
    assert!(decision.is_trusted);

    let audit_snapshot = {
        let mut g = audit.lock();
        std::mem::take(&mut *g).build()
    };

    let events = audit_snapshot.events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        AuditEvent::RuleEvaluated {
            subject: s,
            rule_name: "allow_all",
            decision: d,
        } if *s == subject.id && d.is_trusted
    ));
}
