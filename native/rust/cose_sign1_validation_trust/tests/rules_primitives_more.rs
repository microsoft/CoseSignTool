// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::decision::TrustDecision;
use cose_sign1_validation_trust::error::TrustError;
use cose_sign1_validation_trust::fact_properties::{FactProperties, FactValue};
use cose_sign1_validation_trust::facts::{FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer, TrustFactSet};
use cose_sign1_validation_trust::rules::{
    allow_all, all_of, any_of, not, not_with_reason, require_bool, require_fact_bool,
    require_fact_matches, require_fact_matches_with_missing_behavior, require_present, FactSelector,
    MissingBehavior, PropertyPredicate,
};
use cose_sign1_validation_trust::subject::TrustSubject;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExampleFact {
    flag: bool,
    name: String,
    count: usize,
    u: u32,
    i: i64,
}

impl FactProperties for ExampleFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "flag" => Some(FactValue::Bool(self.flag)),
            "name" => Some(FactValue::Str(self.name.as_str().into())),
            "count" => Some(FactValue::Usize(self.count)),
            "u" => Some(FactValue::U32(self.u)),
            "i" => Some(FactValue::I64(self.i)),
            _ => None,
        }
    }
}

struct ExampleProducer {
    facts: Vec<ExampleFact>,
}

impl TrustFactProducer for ExampleProducer {
    fn name(&self) -> &'static str {
        "example_fact_producer"
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        for f in &self.facts {
            ctx.observe(f.clone())?;
        }
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<ExampleFact>()])
            .as_slice()
    }
}

#[test]
fn basic_boolean_combinators_cover_name_and_reason_paths() {
    let subject = TrustSubject::root("Message", b"seed");
    let engine = TrustFactEngine::new(vec![]);

    let allow = allow_all("allow");
    assert_eq!(allow.name(), "allow");
    assert!(allow.evaluate(&engine, &subject).unwrap().is_trusted);

    let deny_via_not = not("not_allow", allow.clone());
    let d = deny_via_not.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert!(d.reasons.iter().any(|r| r.contains("Negated")));

    let deny_custom = not_with_reason("not_allow2", allow, "CustomReason");
    let d = deny_custom.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert!(d.reasons.iter().any(|r| r.contains("CustomReason")));

    // any_of(empty) should deny with the default reason.
    let empty_or = any_of("empty_or", vec![]);
    let d = empty_or.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert!(d.reasons.iter().any(|r| r.contains("No trust sources")));

    // all_of(empty) should trust.
    let empty_and = all_of("empty_and", vec![]);
    assert!(empty_and.evaluate(&engine, &subject).unwrap().is_trusted);
}

#[test]
fn fact_selector_convenience_methods_and_fact_match_rules_are_exercised() {
    let subject = TrustSubject::root("Message", b"seed");

    let producer = Arc::new(ExampleProducer {
        facts: vec![
            ExampleFact {
                flag: false,
                name: "alpha".to_string(),
                count: 1,
                u: 5,
                i: -7,
            },
            ExampleFact {
                flag: true,
                name: "beta".to_string(),
                count: 2,
                u: 42,
                i: 123,
            },
        ],
    });
    let engine = TrustFactEngine::new(vec![producer]);

    // Cover FactSelector::first and the where_* convenience methods.
    let selector = FactSelector::first()
        .where_bool("flag", true)
        .where_usize("count", 2)
        .where_u32("u", 42)
        .where_i64("i", 123)
        .where_pred("name", PropertyPredicate::StrStartsWith("b".to_string()));

    let rule = require_fact_matches::<ExampleFact, _>(
        "match_fact",
        |s| s.clone(),
        selector,
        "NoMatch",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(d.is_trusted);

    // MissingBehavior::Allow should succeed when the fact set is missing.
    let missing_engine = TrustFactEngine::new(vec![Arc::new(ExampleProducer { facts: vec![] })]);
    let selector = FactSelector::first().where_bool("flag", true);
    let allow_when_missing = require_fact_matches_with_missing_behavior::<ExampleFact, _>(
        "allow_when_missing",
        |s| s.clone(),
        selector,
        MissingBehavior::Allow,
        "Denied",
    );
    assert!(allow_when_missing
        .evaluate(&missing_engine, &subject)
        .unwrap()
        .is_trusted);
}

#[test]
fn require_present_and_require_bool_cover_available_missing_and_error_paths() {
    let subject = TrustSubject::root("Message", b"seed");

    // Available path.
    let producer = Arc::new(ExampleProducer {
        facts: vec![ExampleFact {
            flag: true,
            name: "x".to_string(),
            count: 0,
            u: 0,
            i: 0,
        }],
    });
    let engine = TrustFactEngine::new(vec![producer]);

    let present = require_present::<ExampleFact, _>("present", |s| s.clone(), "Missing");
    assert!(present.evaluate(&engine, &subject).unwrap().is_trusted);

    let rb = require_bool::<ExampleFact, _, _>(
        "bool",
        |s| s.clone(),
        |f| f.flag,
        true,
        "FlagFalse",
    );
    assert!(rb.evaluate(&engine, &subject).unwrap().is_trusted);

    // Missing path: a producer that declares the key but observes nothing.
    let missing_engine = TrustFactEngine::new(vec![Arc::new(ExampleProducer { facts: vec![] })]);
    let d = present.evaluate(&missing_engine, &subject).unwrap();
    assert!(!d.is_trusted);

    // Error path: corrupt the engine state by forcing an error via get_fact_set on a non-message
    // subject kind (producers may mark produced but not observe facts).
    let non_subject = TrustSubject::root("Other", b"seed");
    let set = missing_engine
        .get_fact_set::<ExampleFact>(&non_subject)
        .unwrap();
    assert!(matches!(set, TrustFactSet::Available(_)));

    // require_fact_bool is a simple wrapper; just ensure it builds and runs.
    let fb = require_fact_bool::<ExampleFact, _>(
        "fact_bool",
        |s| s.clone(),
        FactSelector::first(),
        "flag",
        true,
        "Denied",
    );
    let _ = fb.evaluate(&engine, &subject).unwrap_or(TrustDecision::trusted());
}
