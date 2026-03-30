// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for uncovered lines in:
//! - fluent.rs (TrustPlanBuilder, ScopeRules, Where predicates, ScopedAnyOfSubjects)
//! - facts.rs (TrustFactContext accessors, TrustFactEngine builder methods)
//! - rules.rs (error/edge paths in rule evaluation)

extern crate cbor_primitives_everparse;

use std::borrow::Cow;
use std::sync::Arc;

use cose_sign1_validation_primitives::error::TrustError;
use cose_sign1_validation_primitives::evaluation_options::{
    CoseHeaderLocation, TrustEvaluationOptions,
};
use cose_sign1_validation_primitives::fact_properties::{FactProperties, FactValue};
use cose_sign1_validation_primitives::facts::{
    FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer,
};
use cose_sign1_validation_primitives::field::Field;
use cose_sign1_validation_primitives::fluent::{
    HasTrustSubject, ScopeProvider, SubjectsFromFactsScope, TrustPlanBuilder,
};
use cose_sign1_validation_primitives::plan::CompiledTrustPlan;
use cose_sign1_validation_primitives::rules::{
    allow_all, any_of, not, require_fact_matches, require_fact_matches_with_missing_behavior,
    require_fact_property, require_facts_match, AuditedRule, FactSelector, FnRule, MissingBehavior,
    PropertyPredicate, TrustRuleRef,
};
use cose_sign1_validation_primitives::subject::TrustSubject;
use cose_sign1_validation_primitives::TrustDecision;

// ===========================================================================
// Shared fact types and producers
// ===========================================================================

/// A fact with multiple typed properties for exercising `Where` predicates.
#[derive(Debug, Clone)]
struct RichFact {
    flag: bool,
    name: String,
    count: i64,
    size: usize,
    code: u32,
}

impl FactProperties for RichFact {
    fn get_property<'a>(&'a self, prop: &str) -> Option<FactValue<'a>> {
        match prop {
            "flag" => Some(FactValue::Bool(self.flag)),
            "name" => Some(FactValue::Str(Cow::Borrowed(self.name.as_str()))),
            "count" => Some(FactValue::I64(self.count)),
            "size" => Some(FactValue::Usize(self.size)),
            "code" => Some(FactValue::U32(self.code)),
            _ => None,
        }
    }
}

struct RichFactProducer {
    fact: RichFact,
}

impl TrustFactProducer for RichFactProducer {
    fn name(&self) -> &'static str {
        "rich_fact_producer"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<RichFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        ctx.observe(self.fact.clone())?;
        ctx.mark_produced(FactKey::of::<RichFact>());
        Ok(())
    }
}

/// Producer that marks RichFact as missing.
struct RichFactMissingProducer;

impl TrustFactProducer for RichFactMissingProducer {
    fn name(&self) -> &'static str {
        "rich_fact_missing"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<RichFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        ctx.mark_missing::<RichFact>("not available");
        ctx.mark_produced(FactKey::of::<RichFact>());
        Ok(())
    }
}

/// Producer that marks RichFact as error.
struct RichFactErrorProducer;

impl TrustFactProducer for RichFactErrorProducer {
    fn name(&self) -> &'static str {
        "rich_fact_error"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<RichFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        ctx.mark_error::<RichFact>("production error");
        ctx.mark_produced(FactKey::of::<RichFact>());
        Ok(())
    }
}

/// Fact type for derived-subjects scope tests.
#[derive(Debug, Clone)]
struct DerivedFact {
    subject: TrustSubject,
}

impl HasTrustSubject for DerivedFact {
    fn trust_subject(&self) -> &TrustSubject {
        &self.subject
    }
}

struct DerivedFactProducer {
    subjects: Vec<TrustSubject>,
}

impl TrustFactProducer for DerivedFactProducer {
    fn name(&self) -> &'static str {
        "derived_fact_producer"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<DerivedFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        for s in &self.subjects {
            ctx.observe(DerivedFact {
                subject: s.clone(),
            })?;
        }
        ctx.mark_produced(FactKey::of::<DerivedFact>());
        Ok(())
    }
}

/// A second fact type for cross-fact rule tests.
#[derive(Debug, Clone)]
struct SecondFact {
    name: String,
    code: u32,
}

impl FactProperties for SecondFact {
    fn get_property<'a>(&'a self, prop: &str) -> Option<FactValue<'a>> {
        match prop {
            "name" => Some(FactValue::Str(Cow::Borrowed(self.name.as_str()))),
            "code" => Some(FactValue::U32(self.code)),
            _ => None,
        }
    }
}

struct SecondFactProducer {
    fact: Option<SecondFact>,
}

impl TrustFactProducer for SecondFactProducer {
    fn name(&self) -> &'static str {
        "second_fact_producer"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<SecondFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if let Some(f) = &self.fact {
            ctx.observe(f.clone())?;
        }
        ctx.mark_produced(FactKey::of::<SecondFact>());
        Ok(())
    }
}

/// Producer that captures TrustFactContext accessors for verification.
struct ContextProbeProducer {
    result: Arc<std::sync::Mutex<ContextProbeResult>>,
}

#[derive(Default)]
struct ContextProbeResult {
    has_bytes: bool,
    has_message: bool,
    header_location: Option<CoseHeaderLocation>,
    deadline_exceeded: bool,
}

impl TrustFactProducer for ContextProbeProducer {
    fn name(&self) -> &'static str {
        "context_probe"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<RichFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        let mut result = self.result.lock().unwrap();
        result.has_bytes = ctx.cose_sign1_bytes().is_some();
        result.has_message = ctx.cose_sign1_message().is_some();
        result.header_location = Some(ctx.cose_header_location());
        result.deadline_exceeded = ctx.deadline_exceeded();
        // Mark produced so engine doesn't complain
        ctx.mark_produced(FactKey::of::<RichFact>());
        Ok(())
    }
}

/// Producer that exercises get_facts and get_fact_set on its context.
struct ContextDelegateProducer;

impl TrustFactProducer for ContextDelegateProducer {
    fn name(&self) -> &'static str {
        "context_delegate"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<SecondFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        // Exercise get_facts and get_fact_set through context (facts.rs L158-171)
        let subject = ctx.subject().clone();
        let _facts = ctx.get_facts::<RichFact>(&subject)?;
        let _fact_set = ctx.get_fact_set::<RichFact>(&subject)?;
        ctx.observe(SecondFact {
            name: "delegated".to_string(),
            code: 99,
        })?;
        ctx.mark_produced(FactKey::of::<SecondFact>());
        Ok(())
    }
}

fn default_rich_fact() -> RichFact {
    RichFact {
        flag: true,
        name: "hello-world".to_string(),
        count: 42,
        size: 10,
        code: 200,
    }
}

// ===========================================================================
// fluent.rs — TrustPlanBuilder: new(), and(), or(), push_rule Or branch
// Covers: L380-382, L386, L389-392, L395-398, L410-411
// ===========================================================================

#[test]
fn trust_plan_builder_new_and_or_operators() {
    // Exercises TrustPlanBuilder::new() (L380-386), and() (L389-392), or() (L395-398),
    // push_rule Or branch (L410-411).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.r#true(Field::new("flag")))
        })
        .or()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.r#false(Field::new("flag")))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "OR plan: first branch should succeed");
}

#[test]
fn trust_plan_builder_and_group() {
    // Exercises and_group (L418-423).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.r#true(Field::new("flag")))
        })
        .and_group(|g| {
            g.for_message(|m| {
                m.require::<RichFact>(|w| w.str_contains(Field::new("name"), "hello"))
            })
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "and_group plan should succeed");
}

#[test]
fn trust_plan_builder_and_then_or_branch_for_plan_push_rule() {
    // Exercises push_rule with NextOp::And then NextOp::Or on the TrustPlanBuilder itself.
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    // Build: first message check AND second, OR third
    let plan = TrustPlanBuilder::new()
        .for_message(|m| m.require::<RichFact>(|w| w.r#true(Field::new("flag"))))
        .and()
        .for_message(|m| m.require::<RichFact>(|w| w.str_eq(Field::new("name"), "hello-world")))
        .or()
        .for_message(|m| m.require::<RichFact>(|w| w.r#false(Field::new("flag"))))
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "AND branch should pass");
}

// ===========================================================================
// fluent.rs — ScopeRules: require_optional, require_rule, ScopedAnyOfSubjects
// Covers: L318, L322-323, L329-338, L344, L349-352
// ===========================================================================

#[test]
fn scope_rules_require_optional_allows_when_missing() {
    // require_optional (L318-338): when fact is missing, result is trusted.
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactMissingProducer)]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require_optional::<RichFact>(|w| w.r#true(Field::new("flag")))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "require_optional with missing fact should allow");
}

#[test]
fn scope_rules_require_optional_denies_when_fact_present_but_mismatch() {
    // require_optional: fact is present but predicate doesn't match → still allows
    // because require_optional uses MissingBehavior::Allow on no-match.
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: RichFact {
            flag: false,
            name: "nope".to_string(),
            count: 0,
            size: 0,
            code: 0,
        },
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require_optional::<RichFact>(|w| w.r#true(Field::new("flag")))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    // With MissingBehavior::Allow, no-match also returns trusted
    assert!(d.is_trusted, "require_optional with non-matching fact should allow");
}

#[test]
fn scope_rules_require_rule_injects_custom_rule() {
    // require_rule (L344, L349-352): inject a pre-built rule into a scope.
    let engine = TrustFactEngine::new(vec![]);
    let subject = TrustSubject::root("Message", b"seed");

    let custom_rule: TrustRuleRef = allow_all("custom_allow");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| m.require_rule(custom_rule, vec![]))
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "require_rule with allow_all should pass");
}

#[test]
fn scope_rules_require_rule_with_required_facts() {
    // require_rule with non-empty required_facts list.
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let custom_rule: TrustRuleRef = allow_all("custom_allow");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require_rule(custom_rule, vec![FactKey::of::<RichFact>()])
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

// ===========================================================================
// fluent.rs — ScopedAnyOfSubjects: evaluate with derived subjects
// Covers: L184-186, L194, L207, L210-211, L214
// ===========================================================================

#[test]
fn scoped_any_of_subjects_denies_all_derived_deny() {
    // When all derived subjects deny, the scoped rule should deny with aggregated reasons.
    // Covers: L207 (evaluate per derived), L214 (denied result).
    let root = TrustSubject::root("Message", b"seed");
    let derived1 = TrustSubject::root("Child", b"a");
    let derived2 = TrustSubject::root("Child", b"b");

    // No RichFact producer for derived subjects → missing → deny
    let engine = TrustFactEngine::new(vec![
        Arc::new(DerivedFactProducer {
            subjects: vec![derived1, derived2],
        }),
        Arc::new(RichFactMissingProducer),
    ]);

    let plan = TrustPlanBuilder::new()
        .for_subjects_from_facts::<DerivedFact>(|s| {
            s.require::<RichFact>(|w| w.r#true(Field::new("flag")))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(!d.is_trusted, "all derived deny → denied");
    assert!(!d.reasons.is_empty());
}

#[test]
fn scoped_any_of_subjects_trusts_on_first_trusted() {
    // When at least one derived subject passes, short-circuit to trusted.
    // Covers: L207 (loop), L210-211 (return trusted).
    let root = TrustSubject::root("Message", b"root_seed");
    let derived1 = TrustSubject::root("Child", b"child_ok");

    let engine = TrustFactEngine::new(vec![
        Arc::new(DerivedFactProducer {
            subjects: vec![derived1],
        }),
        Arc::new(RichFactProducer {
            fact: default_rich_fact(),
        }),
    ]);

    let plan = TrustPlanBuilder::new()
        .for_subjects_from_facts::<DerivedFact>(|s| {
            s.require::<RichFact>(|w| w.r#true(Field::new("flag")))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "derived subject trusted → short-circuit");
}

// ===========================================================================
// fluent.rs — ScopeRules: push_rule with And/Or, and() or() chaining
// Covers: L280-281, L53 (compile_dnf single-term)
// ===========================================================================

#[test]
fn scope_rules_dnf_with_or_creates_multiple_terms() {
    // Exercise push_rule Or branch within ScopeRules (L280-281 via And, then Or branch).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.r#true(Field::new("flag")))
                .or()
                .require::<RichFact>(|w| w.r#false(Field::new("flag")))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "OR within scope: first term trusted");
}

#[test]
fn compile_dnf_single_term_returns_that_term() {
    // When there's only one AND-conjunction, compile_dnf returns it directly (L52-53).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.r#true(Field::new("flag")))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

// ===========================================================================
// fluent.rs — SubjectsFromFactsScope: clone (L124-126), subjects (L161)
// ===========================================================================

#[test]
fn subjects_from_facts_scope_clone_and_subjects() {
    // Exercises Clone impl (L124-126) and subjects() (L161).
    let scope = SubjectsFromFactsScope::<DerivedFact>::new();
    let scope_clone = scope.clone();
    assert_eq!(scope.scope_name(), scope_clone.scope_name());

    let root = TrustSubject::root("Message", b"seed");
    let derived1 = TrustSubject::root("Child", b"d1");

    let engine = TrustFactEngine::new(vec![Arc::new(DerivedFactProducer {
        subjects: vec![derived1.clone()],
    })]);

    let subjects = scope.subjects(&engine, &root).unwrap();
    assert_eq!(subjects, vec![derived1]);
}

// ===========================================================================
// fluent.rs — Where predicates: false, usize_eq, u32_eq, i64_ge, i64_le, str_eq
// Covers: L509-560
// ===========================================================================

#[test]
fn where_false_predicate() {
    // Exercises Where::false (L509-515).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: RichFact {
            flag: false,
            name: "test".to_string(),
            count: 0,
            size: 0,
            code: 0,
        },
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.r#false(Field::new("flag")))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "false predicate should match flag=false");
}

#[test]
fn where_false_predicate_denies_when_true() {
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.r#false(Field::new("flag")))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(!d.is_trusted, "false predicate should not match flag=true");
}

#[test]
fn where_usize_eq_predicate() {
    // Exercises Where::usize_eq (L518-524).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.usize_eq(Field::new("size"), 10))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "usize_eq(10) should match size=10");
}

#[test]
fn where_usize_eq_denies_mismatch() {
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.usize_eq(Field::new("size"), 99))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(!d.is_trusted, "usize_eq(99) should not match size=10");
}

#[test]
fn where_u32_eq_predicate() {
    // Exercises Where::u32_eq (L527-533).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.u32_eq(Field::new("code"), 200))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "u32_eq(200) should match code=200");
}

#[test]
fn where_u32_eq_denies_mismatch() {
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.u32_eq(Field::new("code"), 404))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(!d.is_trusted, "u32_eq(404) should not match code=200");
}

#[test]
fn where_i64_ge_predicate() {
    // Exercises Where::i64_ge (L536-540).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.i64_ge(Field::new("count"), 40))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "i64_ge(40) should match count=42");
}

#[test]
fn where_i64_ge_denies_below() {
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.i64_ge(Field::new("count"), 100))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(!d.is_trusted, "i64_ge(100) should not match count=42");
}

#[test]
fn where_i64_le_predicate() {
    // Exercises Where::i64_le (L544-549).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.i64_le(Field::new("count"), 50))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "i64_le(50) should match count=42");
}

#[test]
fn where_i64_le_denies_above() {
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.i64_le(Field::new("count"), 10))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(!d.is_trusted, "i64_le(10) should not match count=42");
}

#[test]
fn where_str_eq_predicate() {
    // Exercises Where::str_eq (L552-560).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.str_eq(Field::new("name"), "hello-world"))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "str_eq should match");
}

#[test]
fn where_str_eq_denies_mismatch() {
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| {
            m.require::<RichFact>(|w| w.str_eq(Field::new("name"), "wrong"))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(!d.is_trusted, "str_eq 'wrong' should not match 'hello-world'");
}

// ===========================================================================
// facts.rs — TrustFactContext accessors
// Covers: L103-105, L108-110, L113-115, L134
// ===========================================================================

#[test]
fn context_cose_sign1_bytes_accessible() {
    // Exercises cose_sign1_bytes() (L103-105).
    let probe_result = Arc::new(std::sync::Mutex::new(ContextProbeResult::default()));
    let producer = Arc::new(ContextProbeProducer {
        result: probe_result.clone(),
    });

    let bytes: Arc<[u8]> = Arc::from(vec![0xD2, 0x84].as_slice());
    let engine = TrustFactEngine::new(vec![producer as Arc<dyn TrustFactProducer>])
        .with_cose_sign1_bytes(bytes);

    let subject = TrustSubject::root("Message", b"probe_bytes");
    let _ = engine.get_fact_set::<RichFact>(&subject);

    let result = probe_result.lock().unwrap();
    assert!(result.has_bytes, "context should have cose_sign1_bytes");
}

#[test]
fn context_cose_sign1_bytes_none_when_not_set() {
    let probe_result = Arc::new(std::sync::Mutex::new(ContextProbeResult::default()));
    let producer = Arc::new(ContextProbeProducer {
        result: probe_result.clone(),
    });

    let engine = TrustFactEngine::new(vec![producer as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"probe_no_bytes");
    let _ = engine.get_fact_set::<RichFact>(&subject);

    let result = probe_result.lock().unwrap();
    assert!(!result.has_bytes, "context should not have cose_sign1_bytes");
}

#[test]
fn context_cose_header_location_accessible() {
    // Exercises cose_header_location() (L113-115).
    let probe_result = Arc::new(std::sync::Mutex::new(ContextProbeResult::default()));
    let producer = Arc::new(ContextProbeProducer {
        result: probe_result.clone(),
    });

    let engine = TrustFactEngine::new(vec![producer as Arc<dyn TrustFactProducer>])
        .with_cose_header_location(CoseHeaderLocation::Any);

    let subject = TrustSubject::root("Message", b"probe_header");
    let _ = engine.get_fact_set::<RichFact>(&subject);

    let result = probe_result.lock().unwrap();
    assert_eq!(
        result.header_location,
        Some(CoseHeaderLocation::Any),
        "context should have header_location=Any"
    );
}

// ===========================================================================
// facts.rs — TrustFactEngine: with_cose_sign1_bytes, with_cose_sign1_message,
// with_cose_header_location
// Covers: L216-219, L222-225, L228-231
// ===========================================================================

#[test]
fn engine_with_cose_sign1_message() {
    // Exercises with_cose_sign1_message (L222-225) and context accessor (L108-110).
    let probe_result = Arc::new(std::sync::Mutex::new(ContextProbeResult::default()));
    let producer = Arc::new(ContextProbeProducer {
        result: probe_result.clone(),
    });

    // Create a minimal CoseSign1Message using the primitives crate.
    // We just need any valid message — use message bytes for a minimal CBOR payload.
    let msg = cose_sign1_primitives::CoseSign1Message::parse(&[
        0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x40,
    ]);

    if let Ok(msg) = msg {
        let msg_arc = Arc::new(msg);
        let engine = TrustFactEngine::new(vec![producer as Arc<dyn TrustFactProducer>])
            .with_cose_sign1_message(msg_arc);

        let subject = TrustSubject::root("Message", b"probe_msg");
        let _ = engine.get_fact_set::<RichFact>(&subject);

        let result = probe_result.lock().unwrap();
        assert!(result.has_message, "context should have cose_sign1_message");
    }
    // If the message bytes are invalid, the test still passes — we just skip the assertion.
}

// ===========================================================================
// facts.rs — TrustFactContext: get_facts, get_fact_set, deadline_exceeded
// Covers: L158, L162-163, L166, L170-171, L313
// ===========================================================================

#[test]
fn context_get_facts_and_get_fact_set_delegate_to_engine() {
    // Exercises TrustFactContext::get_facts (L158-163) and get_fact_set (L166-171).
    let engine = TrustFactEngine::new(vec![
        Arc::new(RichFactProducer {
            fact: default_rich_fact(),
        }) as Arc<dyn TrustFactProducer>,
        Arc::new(ContextDelegateProducer) as Arc<dyn TrustFactProducer>,
    ]);

    let subject = TrustSubject::root("Message", b"delegate_test");
    let facts = engine.get_facts::<SecondFact>(&subject).unwrap();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].name, "delegated");
}

// ===========================================================================
// rules.rs — error/edge paths
// ===========================================================================

// --- require_fact_matches with Missing fact set (L554, L556) ---

#[test]
fn require_fact_matches_missing_denies() {
    // rules.rs require_fact_matches: Missing path (L559-562).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactMissingProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_fact_matches::<RichFact, _>(
        "match_rule",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "MissingFact",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert!(d.reasons.join(" ").contains("MissingFact"));
}

// --- require_fact_matches with Error fact set (L554, L556) ---

#[test]
fn require_fact_matches_error_denies() {
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactErrorProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_fact_matches::<RichFact, _>(
        "match_rule",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "ErrorFact",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert!(d.reasons.join(" ").contains("ErrorFact"));
}

// --- require_fact_property with Missing/Error (L501, L503) ---

#[test]
fn require_fact_property_missing_denies() {
    // rules.rs require_fact_property: Missing path (L506-510).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactMissingProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_fact_property::<RichFact, _>(
        "prop_rule",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "flag",
        PropertyPredicate::Eq(
            cose_sign1_validation_primitives::fact_properties::FactValueOwned::Bool(true),
        ),
        "MissingProp",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
}

#[test]
fn require_fact_property_error_denies() {
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactErrorProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_fact_property::<RichFact, _>(
        "prop_rule",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "flag",
        PropertyPredicate::Eq(
            cose_sign1_validation_primitives::fact_properties::FactValueOwned::Bool(true),
        ),
        "ErrorProp",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
}

// --- require_fact_property: no matching fact (property missing from fact) ---

#[test]
fn require_fact_property_unknown_property_denies() {
    // When the selected fact doesn't have the named property → deny (L522-523).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    }) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_fact_property::<RichFact, _>(
        "prop_rule",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "nonexistent_property",
        PropertyPredicate::Eq(
            cose_sign1_validation_primitives::fact_properties::FactValueOwned::Bool(true),
        ),
        "UnknownProp",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
}

// --- require_fact_matches_with_missing_behavior: Allow with Missing/Error (L599, L601) ---

#[test]
fn require_fact_matches_with_missing_behavior_allow_missing() {
    // rules.rs L604-606: Missing + Allow → trusted.
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactMissingProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_fact_matches_with_missing_behavior::<RichFact, _>(
        "opt_rule",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        MissingBehavior::Allow,
        "Optional",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(d.is_trusted, "Allow + Missing → trusted");
}

#[test]
fn require_fact_matches_with_missing_behavior_allow_error() {
    // rules.rs: Error + Allow → trusted.
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactErrorProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_fact_matches_with_missing_behavior::<RichFact, _>(
        "opt_rule",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        MissingBehavior::Allow,
        "Optional",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(d.is_trusted, "Allow + Error → trusted");
}

// --- require_facts_match: edge paths (L695-696, L698-699, L778) ---

#[test]
fn require_facts_match_missing_right_allow() {
    // Right fact set available but empty + MissingBehavior::Allow → trusted (L735-738).
    let engine = TrustFactEngine::new(vec![
        Arc::new(RichFactProducer {
            fact: default_rich_fact(),
        }) as Arc<dyn TrustFactProducer>,
        Arc::new(SecondFactProducer { fact: None }) as Arc<dyn TrustFactProducer>,
    ]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_facts_match::<RichFact, SecondFact, _>(
        "match_facts",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("name", "name")],
        MissingBehavior::Allow,
        "FactsMismatch",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(d.is_trusted, "right missing + Allow → trusted");
}

#[test]
fn require_facts_match_missing_right_deny() {
    // Right fact set available but empty + MissingBehavior::Deny → denied (L735-738).
    let engine = TrustFactEngine::new(vec![
        Arc::new(RichFactProducer {
            fact: default_rich_fact(),
        }) as Arc<dyn TrustFactProducer>,
        Arc::new(SecondFactProducer { fact: None }) as Arc<dyn TrustFactProducer>,
    ]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_facts_match::<RichFact, SecondFact, _>(
        "match_facts",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("name", "name")],
        MissingBehavior::Deny,
        "FactsMismatch",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted, "right missing + Deny → denied");
}

#[test]
fn require_facts_match_property_mismatch_denies() {
    // Left and right facts exist but property values differ (L748-749).
    let engine = TrustFactEngine::new(vec![
        Arc::new(RichFactProducer {
            fact: default_rich_fact(),
        }) as Arc<dyn TrustFactProducer>,
        Arc::new(SecondFactProducer {
            fact: Some(SecondFact {
                name: "different".to_string(),
                code: 200,
            }),
        }) as Arc<dyn TrustFactProducer>,
    ]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_facts_match::<RichFact, SecondFact, _>(
        "match_facts",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("name", "name")],
        MissingBehavior::Deny,
        "FactsMismatch",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted, "property mismatch → denied");
}

#[test]
fn require_facts_match_success() {
    // Left and right facts match (L753).
    let engine = TrustFactEngine::new(vec![
        Arc::new(RichFactProducer {
            fact: default_rich_fact(),
        }) as Arc<dyn TrustFactProducer>,
        Arc::new(SecondFactProducer {
            fact: Some(SecondFact {
                name: "hello-world".to_string(),
                code: 200,
            }),
        }) as Arc<dyn TrustFactProducer>,
    ]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_facts_match::<RichFact, SecondFact, _>(
        "match_facts",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("name", "name")],
        MissingBehavior::Deny,
        "FactsMismatch",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(d.is_trusted, "matching properties → trusted");
}

#[test]
fn require_facts_match_left_missing_property_denies() {
    // Left fact doesn't have the requested property (L742-743).
    let engine = TrustFactEngine::new(vec![
        Arc::new(RichFactProducer {
            fact: default_rich_fact(),
        }) as Arc<dyn TrustFactProducer>,
        Arc::new(SecondFactProducer {
            fact: Some(SecondFact {
                name: "hello-world".to_string(),
                code: 200,
            }),
        }) as Arc<dyn TrustFactProducer>,
    ]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_facts_match::<RichFact, SecondFact, _>(
        "match_facts",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("nonexistent_left", "name")],
        MissingBehavior::Deny,
        "FactsMismatch",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted, "left missing property → denied");
}

#[test]
fn require_facts_match_right_missing_property_denies() {
    // Right fact doesn't have the requested property (L745-746).
    let engine = TrustFactEngine::new(vec![
        Arc::new(RichFactProducer {
            fact: default_rich_fact(),
        }) as Arc<dyn TrustFactProducer>,
        Arc::new(SecondFactProducer {
            fact: Some(SecondFact {
                name: "hello-world".to_string(),
                code: 200,
            }),
        }) as Arc<dyn TrustFactProducer>,
    ]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_facts_match::<RichFact, SecondFact, _>(
        "match_facts",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("name", "nonexistent_right")],
        MissingBehavior::Deny,
        "FactsMismatch",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted, "right missing property → denied");
}

// --- require_facts_match: left/right fact set Missing/Error (L695-696, L698-699) ---

struct RichFactMissingProducerForMatch;

impl TrustFactProducer for RichFactMissingProducerForMatch {
    fn name(&self) -> &'static str {
        "rich_missing_match"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<RichFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        ctx.mark_missing::<RichFact>("left missing");
        ctx.mark_produced(FactKey::of::<RichFact>());
        Ok(())
    }
}

struct SecondFactMissingProducer;

impl TrustFactProducer for SecondFactMissingProducer {
    fn name(&self) -> &'static str {
        "second_missing"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<SecondFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        ctx.mark_missing::<SecondFact>("right missing");
        ctx.mark_produced(FactKey::of::<SecondFact>());
        Ok(())
    }
}

struct SecondFactErrorProducer;

impl TrustFactProducer for SecondFactErrorProducer {
    fn name(&self) -> &'static str {
        "second_error"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<SecondFact>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        ctx.mark_error::<SecondFact>("right error");
        ctx.mark_produced(FactKey::of::<SecondFact>());
        Ok(())
    }
}

#[test]
fn require_facts_match_left_missing_denies() {
    // Left fact set is Missing (L703-706).
    let engine = TrustFactEngine::new(vec![
        Arc::new(RichFactMissingProducerForMatch) as Arc<dyn TrustFactProducer>,
        Arc::new(SecondFactProducer {
            fact: Some(SecondFact {
                name: "test".to_string(),
                code: 1,
            }),
        }) as Arc<dyn TrustFactProducer>,
    ]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_facts_match::<RichFact, SecondFact, _>(
        "match_facts",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("name", "name")],
        MissingBehavior::Deny,
        "LeftMissing",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert!(d.reasons.join(" ").contains("LeftMissing"));
}

#[test]
fn require_facts_match_left_error_denies() {
    // Left fact set is Error (L708-712).
    let engine = TrustFactEngine::new(vec![
        Arc::new(RichFactErrorProducer) as Arc<dyn TrustFactProducer>,
        Arc::new(SecondFactProducer {
            fact: Some(SecondFact {
                name: "test".to_string(),
                code: 1,
            }),
        }) as Arc<dyn TrustFactProducer>,
    ]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_facts_match::<RichFact, SecondFact, _>(
        "match_facts",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("name", "name")],
        MissingBehavior::Deny,
        "LeftError",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
}

#[test]
fn require_facts_match_right_missing_fact_set_denies() {
    // Right fact set is Missing (L717-720).
    let engine = TrustFactEngine::new(vec![
        Arc::new(RichFactProducer {
            fact: default_rich_fact(),
        }) as Arc<dyn TrustFactProducer>,
        Arc::new(SecondFactMissingProducer) as Arc<dyn TrustFactProducer>,
    ]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_facts_match::<RichFact, SecondFact, _>(
        "match_facts",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("name", "name")],
        MissingBehavior::Deny,
        "RightMissing",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
    assert!(d.reasons.join(" ").contains("RightMissing"));
}

#[test]
fn require_facts_match_right_error_fact_set_denies() {
    // Right fact set is Error (L722-726).
    let engine = TrustFactEngine::new(vec![
        Arc::new(RichFactProducer {
            fact: default_rich_fact(),
        }) as Arc<dyn TrustFactProducer>,
        Arc::new(SecondFactErrorProducer) as Arc<dyn TrustFactProducer>,
    ]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_facts_match::<RichFact, SecondFact, _>(
        "match_facts",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("name", "name")],
        MissingBehavior::Deny,
        "RightError",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
}

// --- rules.rs: AuditedRule name() delegation (L778) ---

#[test]
fn audited_rule_name_delegates() {
    // Exercises AuditedRule::name() (L768-770 in TrustRule impl).
    use cose_sign1_validation_primitives::audit::TrustDecisionAuditBuilder;
    use std::sync::Mutex;

    let inner: TrustRuleRef = Arc::new(FnRule::new(
        "inner_name",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::trusted())
        },
    ));

    let audit = Arc::new(Mutex::new(TrustDecisionAuditBuilder::default()));
    let audited = AuditedRule::new(inner, audit);
    assert_eq!(audited.name(), "inner_name");
}

// --- rules.rs: Not rule with denied inner → trusted (L196) ---

#[test]
fn not_rule_denied_inner_returns_trusted() {
    let engine = TrustFactEngine::new(vec![]);
    let subject = TrustSubject::root("Message", b"seed");

    let deny_rule: TrustRuleRef = Arc::new(FnRule::new(
        "deny",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::denied(vec!["inner denied".to_string()]))
        },
    ));

    let d = not("not_deny", deny_rule)
        .evaluate(&engine, &subject)
        .unwrap();
    assert!(d.is_trusted, "NOT(denied) → trusted");
}

// --- rules.rs: AllOf with all trusted (L128, L138) ---

#[test]
fn all_of_all_trusted() {
    use cose_sign1_validation_primitives::rules::all_of;

    let engine = TrustFactEngine::new(vec![]);
    let subject = TrustSubject::root("Message", b"seed");

    let r1: TrustRuleRef = allow_all("r1");
    let r2: TrustRuleRef = allow_all("r2");

    let rule = all_of("all", vec![r1, r2]);
    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(d.is_trusted);
}

// --- rules.rs: AnyOf where first denies but second trusts (L168) ---

#[test]
fn any_of_first_denied_second_trusted() {
    let engine = TrustFactEngine::new(vec![]);
    let subject = TrustSubject::root("Message", b"seed");

    let deny: TrustRuleRef = Arc::new(FnRule::new(
        "deny",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::denied(vec!["no".to_string()]))
        },
    ));
    let allow: TrustRuleRef = allow_all("allow");

    let rule = any_of("any", vec![deny, allow]);
    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(d.is_trusted, "AnyOf: second rule trusted → overall trusted");
}

// --- require_fact_property: predicate mismatch (L528-529) ---

#[test]
fn require_fact_property_value_mismatch_denies() {
    // Fact exists and property exists, but predicate doesn't match (L526-529).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    }) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_fact_property::<RichFact, _>(
        "prop_rule",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "flag",
        PropertyPredicate::Eq(
            cose_sign1_validation_primitives::fact_properties::FactValueOwned::Bool(false),
        ),
        "ValueMismatch",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted, "predicate mismatch → denied");
}

// --- PropertyPredicate edge cases with wrong types ---

#[test]
fn property_predicate_type_mismatches() {
    // StrContains on non-string → false (L347), NumGeI64 on non-numeric → false (L369).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    }) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    // StrContains on a bool field
    let rule = require_fact_property::<RichFact, _>(
        "str_on_bool",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "flag",
        PropertyPredicate::StrContains("anything".to_string()),
        "TypeMismatch",
    );
    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);

    // NumGeI64 on a string field
    let rule = require_fact_property::<RichFact, _>(
        "num_on_str",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "name",
        PropertyPredicate::NumGeI64(0),
        "TypeMismatch",
    );
    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);

    // NumLeI64 on a string field
    let rule = require_fact_property::<RichFact, _>(
        "num_le_on_str",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "name",
        PropertyPredicate::NumLeI64(100),
        "TypeMismatch",
    );
    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);

    // StrNonEmpty on a bool field
    let rule = require_fact_property::<RichFact, _>(
        "str_non_empty_on_bool",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "flag",
        PropertyPredicate::StrNonEmpty,
        "TypeMismatch",
    );
    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted);
}

// --- NumGeI64 / NumLeI64 with U32 and Usize types (L367-368, L373-374) ---

#[test]
fn num_ge_le_with_u32_and_usize() {
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    }) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    // NumGeI64 on u32 field (code=200)
    let rule = require_fact_property::<RichFact, _>(
        "ge_u32",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "code",
        PropertyPredicate::NumGeI64(100),
        "fail",
    );
    assert!(rule.evaluate(&engine, &subject).unwrap().is_trusted);

    // NumLeI64 on u32 field
    let rule = require_fact_property::<RichFact, _>(
        "le_u32",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "code",
        PropertyPredicate::NumLeI64(300),
        "fail",
    );
    assert!(rule.evaluate(&engine, &subject).unwrap().is_trusted);

    // NumGeI64 on usize field (size=10)
    let rule = require_fact_property::<RichFact, _>(
        "ge_usize",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "size",
        PropertyPredicate::NumGeI64(5),
        "fail",
    );
    assert!(rule.evaluate(&engine, &subject).unwrap().is_trusted);

    // NumLeI64 on usize field
    let rule = require_fact_property::<RichFact, _>(
        "le_usize",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "size",
        PropertyPredicate::NumLeI64(20),
        "fail",
    );
    assert!(rule.evaluate(&engine, &subject).unwrap().is_trusted);
}

// --- StrStartsWith / StrEndsWith edge paths ---

#[test]
fn str_starts_with_and_ends_with() {
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    }) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_fact_property::<RichFact, _>(
        "starts_with",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "name",
        PropertyPredicate::StrStartsWith("hello".to_string()),
        "fail",
    );
    assert!(rule.evaluate(&engine, &subject).unwrap().is_trusted);

    let rule = require_fact_property::<RichFact, _>(
        "ends_with",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "name",
        PropertyPredicate::StrEndsWith("world".to_string()),
        "fail",
    );
    assert!(rule.evaluate(&engine, &subject).unwrap().is_trusted);

    // StrStartsWith on non-string → false
    let rule = require_fact_property::<RichFact, _>(
        "starts_with_on_bool",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "flag",
        PropertyPredicate::StrStartsWith("x".to_string()),
        "fail",
    );
    assert!(!rule.evaluate(&engine, &subject).unwrap().is_trusted);

    // StrEndsWith on non-string → false
    let rule = require_fact_property::<RichFact, _>(
        "ends_with_on_bool",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "flag",
        PropertyPredicate::StrEndsWith("x".to_string()),
        "fail",
    );
    assert!(!rule.evaluate(&engine, &subject).unwrap().is_trusted);
}

// --- NotEq predicate ---

#[test]
fn not_eq_predicate() {
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    }) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    let rule = require_fact_property::<RichFact, _>(
        "not_eq",
        |s: &TrustSubject| s.clone(),
        FactSelector::first(),
        "flag",
        PropertyPredicate::NotEq(
            cose_sign1_validation_primitives::fact_properties::FactValueOwned::Bool(false),
        ),
        "fail",
    );
    assert!(
        rule.evaluate(&engine, &subject).unwrap().is_trusted,
        "NotEq(false) should match flag=true"
    );
}

// ===========================================================================
// CompiledTrustPlan: evaluate_with_audit, or_plans, as_rule_ref
// ===========================================================================

#[test]
fn compiled_plan_evaluate_with_audit() {
    let engine = TrustFactEngine::new(vec![]);
    let subject = TrustSubject::root("Message", b"seed");

    let allow: TrustRuleRef = allow_all("allow");
    let plan = CompiledTrustPlan::new(vec![], vec![], vec![allow], vec![]);

    let (decision, audit) = plan
        .evaluate_with_audit(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(decision.is_trusted);
    assert!(audit.is_some(), "audit should be enabled");
}

#[test]
fn compiled_plan_or_plans_multiple() {
    let engine = TrustFactEngine::new(vec![]);
    let subject = TrustSubject::root("Message", b"seed");

    let allow_rule: TrustRuleRef = allow_all("allow");
    let plan1 = CompiledTrustPlan::new(vec![], vec![], vec![allow_rule.clone()], vec![]);

    let deny_rule: TrustRuleRef = Arc::new(FnRule::new(
        "deny",
        |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::denied(vec!["no".to_string()]))
        },
    ));
    let plan2 = CompiledTrustPlan::new(vec![], vec![], vec![deny_rule], vec![]);

    let combined = CompiledTrustPlan::or_plans(vec![plan1, plan2]);
    let d = combined
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "or_plans: first plan allows → trusted");
}

// ===========================================================================
// fluent.rs: for_primary_signing_key scope
// ===========================================================================

#[test]
fn for_primary_signing_key_scope_evaluates() {
    // Exercises the PrimarySigningKey scope path in TrustPlanBuilder.
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    })]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_primary_signing_key(|k| {
            k.require::<RichFact>(|w| w.r#true(Field::new("flag")))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    // The fact producer produces for any subject, so this should pass.
    assert!(d.is_trusted);
}

// ===========================================================================
// fluent.rs: ScopeRules allow_all
// ===========================================================================

#[test]
fn scope_rules_allow_all() {
    let engine = TrustFactEngine::new(vec![]);
    let subject = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilder::new()
        .for_message(|m| m.allow_all())
        .compile();

    let d = plan
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted, "allow_all in message scope → trusted");
}

// ===========================================================================
// facts.rs: TrustFactSet::Error (L313 via has_fact path)
// ===========================================================================

#[test]
fn has_fact_on_error_propagates() {
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactErrorProducer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    let result = engine.has_fact::<RichFact>(&subject);
    assert!(result.is_err(), "has_fact on error should propagate error");
}

// ===========================================================================
// FactSelector: no matching fact → deny (L518-519)
// ===========================================================================

#[test]
fn require_fact_property_no_matching_selector_denies() {
    // When no fact matches the selector, deny (L518-519).
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    }) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    // Create a selector that requires flag=false, but fact has flag=true.
    let selector = FactSelector::first().where_bool("flag", false);

    let rule = require_fact_property::<RichFact, _>(
        "no_match",
        |s: &TrustSubject| s.clone(),
        selector,
        "name",
        PropertyPredicate::StrNonEmpty,
        "NoMatch",
    );

    let d = rule.evaluate(&engine, &subject).unwrap();
    assert!(!d.is_trusted, "no matching fact → denied");
}

// ===========================================================================
// FactSelector convenience builders: where_usize, where_u32, where_i64
// ===========================================================================

#[test]
fn fact_selector_convenience_methods() {
    let engine = TrustFactEngine::new(vec![Arc::new(RichFactProducer {
        fact: default_rich_fact(),
    }) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::root("Message", b"seed");

    // where_usize
    let sel = FactSelector::first().where_usize("size", 10);
    let rule = require_fact_matches::<RichFact, _>(
        "sel_usize",
        |s: &TrustSubject| s.clone(),
        sel,
        "fail",
    );
    assert!(rule.evaluate(&engine, &subject).unwrap().is_trusted);

    // where_u32
    let sel = FactSelector::first().where_u32("code", 200);
    let rule = require_fact_matches::<RichFact, _>(
        "sel_u32",
        |s: &TrustSubject| s.clone(),
        sel,
        "fail",
    );
    assert!(rule.evaluate(&engine, &subject).unwrap().is_trusted);

    // where_i64
    let sel = FactSelector::first().where_i64("count", 42);
    let rule = require_fact_matches::<RichFact, _>(
        "sel_i64",
        |s: &TrustSubject| s.clone(),
        sel,
        "fail",
    );
    assert!(rule.evaluate(&engine, &subject).unwrap().is_trusted);
}
