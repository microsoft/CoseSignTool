// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::fact_properties::{FactProperties, FactValue};
use cose_sign1_validation_trust::facts::{
    FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer,
};
use cose_sign1_validation_trust::rules::{require_fact_property, FactSelector, PropertyPredicate};
use cose_sign1_validation_trust::subject::TrustSubject;
use std::borrow::Cow;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DummyFact {
    flag: bool,
    name: String,
    count: i64,
}

impl FactProperties for DummyFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "flag" => Some(FactValue::Bool(self.flag)),
            "name" => Some(FactValue::Str(Cow::Borrowed(self.name.as_str()))),
            "count" => Some(FactValue::I64(self.count)),
            _ => None,
        }
    }
}

struct DummyProducer;

impl TrustFactProducer for DummyProducer {
    fn name(&self) -> &'static str {
        "dummy_producer"
    }

    fn produce(
        &self,
        ctx: &mut TrustFactContext<'_>,
    ) -> Result<(), cose_sign1_validation_trust::error::TrustError> {
        // Always publish the same fact for the requested subject.
        ctx.observe(DummyFact {
            flag: true,
            name: "hello world".to_string(),
            count: 5,
        })?;
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<DummyFact>()])
            .as_slice()
    }
}

#[test]
fn declarative_predicates_support_contains_regex_and_numeric_comparisons() {
    let subject = TrustSubject::root("message", b"seed");
    let engine = TrustFactEngine::new(vec![Arc::new(DummyProducer)]);

    let name_contains = require_fact_property::<DummyFact, _>(
        "name_contains",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "name",
        PropertyPredicate::StrContains("world".to_string()),
        "NameMissingOrDoesNotContain",
    );

    let name_matches_regex = require_fact_property::<DummyFact, _>(
        "name_matches_regex",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "name",
        PropertyPredicate::StrMatchesRegex("^hello\\s+world$".to_string()),
        "NameMissingOrDoesNotMatchRegex",
    );

    let count_ge = require_fact_property::<DummyFact, _>(
        "count_ge",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "count",
        PropertyPredicate::NumGeI64(5),
        "CountTooSmall",
    );

    assert!(
        name_contains
            .evaluate(&engine, &subject)
            .unwrap()
            .is_trusted
    );
    assert!(
        name_matches_regex
            .evaluate(&engine, &subject)
            .unwrap()
            .is_trusted
    );
    assert!(count_ge.evaluate(&engine, &subject).unwrap().is_trusted);
}
