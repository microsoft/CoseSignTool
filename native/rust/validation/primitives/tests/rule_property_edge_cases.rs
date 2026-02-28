// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for rule selection and property matching edge cases.

use cose_sign1_validation_primitives::decision::TrustDecision;
use cose_sign1_validation_primitives::error::TrustError;
use cose_sign1_validation_primitives::fact_properties::{FactProperties, FactValue};
use cose_sign1_validation_primitives::facts::{FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer};
use cose_sign1_validation_primitives::rules::{
    require_fact_matches, require_fact_property, require_fact_property_eq, FactSelector, PropertyPredicate,
};
use cose_sign1_validation_primitives::subject::TrustSubject;
use std::borrow::Cow;
use std::sync::Arc;

#[derive(Debug, Clone)]
struct PropertyTestFact {
    string_prop: String,
    bool_prop: bool,
    u32_prop: u32,
    i64_prop: i64,
    usize_prop: usize,
    optional_prop: Option<String>,
}

impl FactProperties for PropertyTestFact {
    fn get_property<'a>(&'a self, prop: &str) -> Option<FactValue<'a>> {
        match prop {
            "string_prop" => Some(FactValue::Str(Cow::Borrowed(&self.string_prop))),
            "bool_prop" => Some(FactValue::Bool(self.bool_prop)),
            "u32_prop" => Some(FactValue::U32(self.u32_prop)),
            "i64_prop" => Some(FactValue::I64(self.i64_prop)),
            "usize_prop" => Some(FactValue::Usize(self.usize_prop)),
            "optional_prop" => self.optional_prop.as_ref().map(|s| FactValue::Str(Cow::Borrowed(s))),
            _ => None,
        }
    }
}

struct PropertyTestProducer {
    facts: Vec<PropertyTestFact>,
}

impl TrustFactProducer for PropertyTestProducer {
    fn name(&self) -> &'static str {
        "property_test_producer"
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        for fact in &self.facts {
            ctx.observe(fact.clone())?;
        }
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<PropertyTestFact>()])
            .as_slice()
    }
}

#[test]
fn require_fact_property_eq_missing_property() {
    let subject = TrustSubject::root("Message", b"seed");
    
    // Fact that doesn't have the requested property
    let producer = Arc::new(PropertyTestProducer {
        facts: vec![PropertyTestFact {
            string_prop: "test".to_string(),
            bool_prop: true,
            u32_prop: 42,
            i64_prop: -123,
            usize_prop: 100,
            optional_prop: Some("optional".to_string()),
        }],
    });
    
    let engine = TrustFactEngine::new(vec![producer]);
    
    // Rule that asks for a property that doesn't exist
    let rule = require_fact_property_eq::<PropertyTestFact, _>(
        "missing_prop_rule",
        |s| s.clone(),
        FactSelector::first(),
        "nonexistent_prop",
        cose_sign1_validation_primitives::fact_properties::FactValueOwned::Bool(true),
        "Property missing",
    );
    
    let decision = rule.evaluate(&engine, &subject).unwrap();
    assert!(!decision.is_trusted);
    assert!(decision.reasons.iter().any(|r| r.contains("Property missing")));
}

#[test]
fn require_fact_property_with_predicate_no_matching_facts() {
    let subject = TrustSubject::root("Message", b"seed");
    
    // Facts that don't match the selector
    let producer = Arc::new(PropertyTestProducer {
        facts: vec![
            PropertyTestFact {
                string_prop: "alpha".to_string(),
                bool_prop: false,
                u32_prop: 1,
                i64_prop: -1,
                usize_prop: 1,
                optional_prop: None,
            },
            PropertyTestFact {
                string_prop: "beta".to_string(),
                bool_prop: false,
                u32_prop: 2,
                i64_prop: -2,
                usize_prop: 2,
                optional_prop: None,
            },
        ],
    });
    
    let engine = TrustFactEngine::new(vec![producer]);
    
    // Selector that won't match any facts
    let selector = FactSelector::first().where_bool("bool_prop", true);
    
    let rule = require_fact_property::<PropertyTestFact, _>(
        "no_match_rule",
        |s| s.clone(),
        selector,
        "string_prop",
        PropertyPredicate::StrStartsWith("gamma".to_string()),
        "No matching facts",
    );
    
    let decision = rule.evaluate(&engine, &subject).unwrap();
    assert!(!decision.is_trusted);
    assert!(decision.reasons.iter().any(|r| r.contains("No matching facts")));
}

#[test]
fn require_fact_matches_property_mismatch() {
    let subject = TrustSubject::root("Message", b"seed");
    
    let producer = Arc::new(PropertyTestProducer {
        facts: vec![PropertyTestFact {
            string_prop: "actual_value".to_string(),
            bool_prop: true,
            u32_prop: 42,
            i64_prop: -123,
            usize_prop: 100,
            optional_prop: Some("optional".to_string()),
        }],
    });
    
    let engine = TrustFactEngine::new(vec![producer]);
    
    // Rule that matches the fact but has a property predicate that fails
    let rule = require_fact_property::<PropertyTestFact, _>(
        "prop_mismatch_rule",
        |s| s.clone(),
        FactSelector::first().where_bool("bool_prop", true), // This will match
        "string_prop", // But this property check will fail
        PropertyPredicate::StrStartsWith("expected".to_string()),
        "Property value mismatch",
    );
    
    let decision = rule.evaluate(&engine, &subject).unwrap();
    assert!(!decision.is_trusted);
    assert!(decision.reasons.iter().any(|r| r.contains("Property value mismatch")));
}

#[test]
fn fact_selector_multiple_where_clauses_all_must_match() {
    let subject = TrustSubject::root("Message", b"seed");
    
    let producer = Arc::new(PropertyTestProducer {
        facts: vec![
            // This fact matches some but not all criteria
            PropertyTestFact {
                string_prop: "correct_string".to_string(),
                bool_prop: true,  // matches
                u32_prop: 42,     // matches
                i64_prop: -999,   // doesn't match
                usize_prop: 100,  // matches
                optional_prop: None,
            },
            // This fact matches all criteria  
            PropertyTestFact {
                string_prop: "correct_string".to_string(),
                bool_prop: true,  // matches
                u32_prop: 42,     // matches
                i64_prop: -123,   // matches
                usize_prop: 100,  // matches
                optional_prop: None,
            },
        ],
    });
    
    let engine = TrustFactEngine::new(vec![producer]);
    
    // Selector with multiple where clauses - ALL must match
    let selector = FactSelector::first()
        .where_bool("bool_prop", true)
        .where_u32("u32_prop", 42)
        .where_i64("i64_prop", -123)
        .where_usize("usize_prop", 100);
    
    let rule = require_fact_matches::<PropertyTestFact, _>(
        "multi_where_rule",
        |s| s.clone(),
        selector,
        "All criteria not met",
    );
    
    let decision = rule.evaluate(&engine, &subject).unwrap();
    assert!(decision.is_trusted); // Should find the second fact that matches all criteria
}

#[test]
fn property_predicate_type_mismatches() {
    let subject = TrustSubject::root("Message", b"seed");
    
    let producer = Arc::new(PropertyTestProducer {
        facts: vec![PropertyTestFact {
            string_prop: "test_string".to_string(),
            bool_prop: true,
            u32_prop: 42,
            i64_prop: -123,
            usize_prop: 100,
            optional_prop: None,
        }],
    });
    
    let engine = TrustFactEngine::new(vec![producer]);
    
    // Try to use a string predicate on a bool property (type mismatch)
    let rule = require_fact_property::<PropertyTestFact, _>(
        "type_mismatch_rule",
        |s| s.clone(),
        FactSelector::first(),
        "bool_prop", // This is a bool property
        PropertyPredicate::StrStartsWith("should_fail".to_string()), // But we're using a string predicate
        "Type mismatch",
    );
    
    let decision = rule.evaluate(&engine, &subject).unwrap();
    assert!(!decision.is_trusted);
    assert!(decision.reasons.iter().any(|r| r.contains("Type mismatch")));
}