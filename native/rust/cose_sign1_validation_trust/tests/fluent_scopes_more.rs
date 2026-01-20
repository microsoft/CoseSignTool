// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::error::TrustError;
use cose_sign1_validation_trust::evaluation_options::TrustEvaluationOptions;
use cose_sign1_validation_trust::fact_properties::{FactProperties, FactValue};
use cose_sign1_validation_trust::facts::{FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer};
use cose_sign1_validation_trust::field::Field;
use cose_sign1_validation_trust::fluent::{
    HasTrustSubject, MessageScope, PrimarySigningKeyScope, ScopeProvider, SubjectsFromFactsScope,
    TrustPlanBuilder,
};
use cose_sign1_validation_trust::rules::OnEmptyBehavior;
use cose_sign1_validation_trust::subject::TrustSubject;
use std::borrow::Cow;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DerivedSubjectFact {
    subject: TrustSubject,
}

impl HasTrustSubject for DerivedSubjectFact {
    fn trust_subject(&self) -> &TrustSubject {
        &self.subject
    }
}

struct DerivedSubjectProducer {
    derived: Vec<TrustSubject>,
}

impl TrustFactProducer for DerivedSubjectProducer {
    fn name(&self) -> &'static str {
        "derived_subject_producer"
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        for s in &self.derived {
            ctx.observe(DerivedSubjectFact { subject: s.clone() })?;
        }
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<DerivedSubjectFact>()])
            .as_slice()
    }
}

#[test]
fn scope_providers_enumerate_expected_subjects() {
    let root = TrustSubject::root("Message", b"seed");
    let engine = TrustFactEngine::new(vec![]);

    let msg = MessageScope;
    assert_eq!(msg.scope_name(), "Message");
    assert_eq!(msg.subjects(&engine, &root).unwrap(), vec![root.clone()]);

    let psk = PrimarySigningKeyScope;
    assert_eq!(psk.scope_name(), "PrimarySigningKey");
    let derived = psk.subjects(&engine, &root).unwrap();
    assert_eq!(derived.len(), 1);
    assert_eq!(derived[0], TrustSubject::primary_signing_key(&root));
}

#[test]
fn subjects_from_facts_scope_derives_subjects_from_facts() {
    let root = TrustSubject::root("Message", b"seed");

    let derived1 = TrustSubject::root("CounterSignature", b"a");
    let derived2 = TrustSubject::root("CounterSignature", b"b");

    let producer = Arc::new(DerivedSubjectProducer {
        derived: vec![derived1.clone(), derived2.clone()],
    });
    let engine = TrustFactEngine::new(vec![producer]);

    let scope = SubjectsFromFactsScope::<DerivedSubjectFact>::new();
    // Exercise Clone/Copy/Default code paths.
    let _scope2 = scope;
    let _scope3 = SubjectsFromFactsScope::<DerivedSubjectFact>::default();

    assert!(scope.scope_name().contains("DerivedSubjectFact"));

    let subjects = scope.subjects(&engine, &root).unwrap();
    assert_eq!(subjects, vec![derived1, derived2]);
}

#[test]
fn trust_plan_builder_scoped_dsl_compiles() {
    // This is primarily a coverage test for the fluent builder glue.
    let plan = TrustPlanBuilder::default()
        .for_message(|m| m.and().or().and())
        .for_primary_signing_key(|k| k.or().and())
        .compile()
        ;

    // Touch the compiled plan API; this also ensures the derived-Default path is executed.
    let _ = plan.required_facts();
}

#[test]
fn scoped_rules_on_empty_allow_allows_when_no_derived_subjects() {
    let root = TrustSubject::root("Message", b"seed");

    // Producer provides the fact but yields no derived subjects.
    let engine = TrustFactEngine::new(vec![Arc::new(DerivedSubjectProducer { derived: vec![] })]);

    let plan = TrustPlanBuilder::default()
        .for_subjects_from_facts::<DerivedSubjectFact>(|s| s.on_empty(OnEmptyBehavior::Allow).allow_all())
        .compile();

    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

#[test]
fn scoped_rules_on_empty_deny_denies_when_no_derived_subjects() {
    let root = TrustSubject::root("Message", b"seed");
    let engine = TrustFactEngine::new(vec![Arc::new(DerivedSubjectProducer { derived: vec![] })]);

    let plan = TrustPlanBuilder::default()
        .for_subjects_from_facts::<DerivedSubjectFact>(|s| s.on_empty(OnEmptyBehavior::Deny).allow_all())
        .compile();

    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(!d.is_trusted);
    assert!(d.reasons.join(" ").contains("No subjects in scope"));
}

#[derive(Debug, Clone)]
struct MarkerFact {
    ok: bool,
}

impl FactProperties for MarkerFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "ok" => Some(FactValue::Bool(self.ok)),
            _ => None,
        }
    }
}

struct MarkerProducer {
    trusted_subject: TrustSubject,
}

impl TrustFactProducer for MarkerProducer {
    fn name(&self) -> &'static str {
        "marker"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<MarkerFact>()]).as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() != FactKey::of::<MarkerFact>() {
            return Ok(());
        }

        if ctx.subject() == &self.trusted_subject {
            ctx.observe(MarkerFact { ok: true })?;
        } else {
            ctx.mark_missing::<MarkerFact>("NoMarker");
        }

        ctx.mark_produced(FactKey::of::<MarkerFact>());
        Ok(())
    }
}

#[test]
fn scoped_rules_or_short_circuits_on_trusted_derived_subject() {
    let root = TrustSubject::root("Message", b"seed");
    let derived1 = TrustSubject::root("CounterSignature", b"a");
    let derived2 = TrustSubject::root("CounterSignature", b"b");

    let engine = TrustFactEngine::new(vec![
        Arc::new(DerivedSubjectProducer {
            derived: vec![derived1.clone(), derived2.clone()],
        }),
        Arc::new(MarkerProducer {
            trusted_subject: derived2.clone(),
        }),
    ]);

    // Use `.or()` to exercise the DNF "start a new OR term" branch.
    let plan = TrustPlanBuilder::default()
        .for_subjects_from_facts::<DerivedSubjectFact>(|s| {
            s.or().require::<MarkerFact>(|w| w.r#true(Field::new("ok")))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

#[derive(Debug, Clone)]
struct StringFact {
    value: String,
}

impl FactProperties for StringFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "value" => Some(FactValue::Str(Cow::Borrowed(self.value.as_str()))),
            _ => None,
        }
    }
}

struct StringFactProducer;

impl TrustFactProducer for StringFactProducer {
    fn name(&self) -> &'static str {
        "string_fact"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<StringFact>()]).as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() != FactKey::of::<StringFact>() {
            return Ok(());
        }

        ctx.observe(StringFact {
            value: "hello-world".to_string(),
        })?;
        ctx.mark_produced(FactKey::of::<StringFact>());
        Ok(())
    }
}

#[test]
fn where_string_predicates_build_and_evaluate() {
    let root = TrustSubject::root("Message", b"seed");
    let engine = TrustFactEngine::new(vec![Arc::new(StringFactProducer)]);

    let plan = TrustPlanBuilder::default()
        .for_message(|m| {
            m.require::<StringFact>(|w| {
                w.str_non_empty(Field::new("value"))
                    .str_contains(Field::new("value"), "world")
                    .str_matches_regex(Field::new("value"), "hello.*world")
            })
        })
        .compile();

    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}
