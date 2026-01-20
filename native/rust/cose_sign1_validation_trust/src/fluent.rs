// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fluent trust plan DSL.
//!
//! This module provides a closure-friendly way to assemble trust plans using scoped rules
//! over a [`TrustSubject`](crate::subject::TrustSubject).
//!
//! Design notes:
//! - Plans are built as disjunctive normal form (DNF): OR-of-ANDs.
//! - Empty `any_of` denies by default, so an empty plan is “deny all”.
//! - Scopes let packs evaluate the same predicate across derived subjects (e.g. counter-signatures).

use crate::error::TrustError;
use crate::facts::FactKey;
use crate::facts::TrustFactEngine;
use crate::field::Field;
use crate::plan::CompiledTrustPlan;
use crate::rules::TrustRuleRef;
use crate::rules::{any_of, FactSelector, OnEmptyBehavior, PropertyPredicate};
use crate::subject::TrustSubject;
use std::any::Any;
use std::marker::PhantomData;
use std::sync::Arc;

// -------------------------------------------------------------------------------------------------
// Rich trust-plan builder (AND/OR + scoped closures)
// -------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NextOp {
    And,
    Or,
}

impl Default for NextOp {
    /// Default operator used when composing rules.
    fn default() -> Self {
        Self::And
    }
}

/// Compile a DNF (OR-of-ANDs) rule representation into a single rule.
///
/// Each inner vector represents an AND-conjunction; the outer vector is OR-ed together.
fn compile_dnf(name: &'static str, dnf: Vec<Vec<TrustRuleRef>>) -> TrustRuleRef {
    let mut and_terms: Vec<TrustRuleRef> = Vec::new();
    for conj in dnf.into_iter() {
        and_terms.push(crate::rules::all_of(name, conj));
    }

    match and_terms.len() {
        1 => and_terms.into_iter().next().unwrap_or_else(|| any_of(name, Vec::new())),
        _ => any_of(name, and_terms),
    }
}

/// A fact type that carries a derived `TrustSubject`.
///
/// This enables scoped rules like "for each counter signature subject" without the trust crate
/// needing to know about counter-signature types.
pub trait HasTrustSubject: Send + Sync {
    /// Returns the derived subject represented by this fact.
    fn trust_subject(&self) -> &TrustSubject;
}

/// Provides derived subjects for a scope.
pub trait ScopeProvider: Clone + Send + Sync + 'static {
    /// A stable name for the scope (used for diagnostics and audit logs).
    fn scope_name(&self) -> &'static str;

    /// Enumerate all subjects in this scope for a given parent subject.
    fn subjects(
        &self,
        engine: &TrustFactEngine,
        subject: &TrustSubject,
    ) -> Result<Vec<TrustSubject>, TrustError>;
}

#[derive(Clone, Copy)]
pub struct MessageScope;

impl ScopeProvider for MessageScope {
    /// Scope name used in diagnostics.
    fn scope_name(&self) -> &'static str {
        "Message"
    }

    /// The message scope contains exactly the current subject.
    fn subjects(
        &self,
        _engine: &TrustFactEngine,
        subject: &TrustSubject,
    ) -> Result<Vec<TrustSubject>, TrustError> {
        Ok(vec![subject.clone()])
    }
}

#[derive(Clone, Copy)]
pub struct PrimarySigningKeyScope;

impl ScopeProvider for PrimarySigningKeyScope {
    /// Scope name used in diagnostics.
    fn scope_name(&self) -> &'static str {
        "PrimarySigningKey"
    }

    /// The primary signing key scope contains the derived key subject for the message.
    fn subjects(
        &self,
        _engine: &TrustFactEngine,
        subject: &TrustSubject,
    ) -> Result<Vec<TrustSubject>, TrustError> {
        Ok(vec![TrustSubject::primary_signing_key(subject)])
    }
}

pub struct SubjectsFromFactsScope<TFact> {
    _phantom: PhantomData<fn() -> TFact>,
}

impl<TFact> Clone for SubjectsFromFactsScope<TFact> {
    /// Copy-clone for this zero-sized scope provider.
    fn clone(&self) -> Self {
        *self
    }
}

impl<TFact> Copy for SubjectsFromFactsScope<TFact> {}

impl<TFact> SubjectsFromFactsScope<TFact> {
    /// Creates a scope provider that derives subjects from facts on the current subject.
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<TFact> Default for SubjectsFromFactsScope<TFact> {
    fn default() -> Self {
        Self::new()
    }
}

impl<TFact> ScopeProvider for SubjectsFromFactsScope<TFact>
where
    TFact: Any + Send + Sync + HasTrustSubject + 'static,
{
    /// Scope name used in diagnostics.
    fn scope_name(&self) -> &'static str {
        std::any::type_name::<TFact>()
    }

    /// Enumerates derived subjects by reading `TFact` facts and extracting each fact's subject.
    fn subjects(
        &self,
        engine: &TrustFactEngine,
        subject: &TrustSubject,
    ) -> Result<Vec<TrustSubject>, TrustError> {
        let facts = engine.get_facts::<TFact>(subject)?;
        Ok(facts
            .into_iter()
            .map(|f| f.trust_subject().clone())
            .collect())
    }
}

struct ScopedAnyOfSubjects<S>
where
    S: ScopeProvider,
{
    name: &'static str,
    scope: S,
    on_empty: OnEmptyBehavior,
    inner_rule: TrustRuleRef,
}

impl<S> crate::rules::TrustRule for ScopedAnyOfSubjects<S>
where
    S: ScopeProvider,
{
    /// Rule name used for diagnostics.
    fn name(&self) -> &'static str {
        self.name
    }

    /// Evaluates the inner rule against each derived subject and ORs the results.
    fn evaluate(
        &self,
        engine: &TrustFactEngine,
        subject: &TrustSubject,
    ) -> Result<crate::decision::TrustDecision, TrustError> {
        let derived = self.scope.subjects(engine, subject)?;
        if derived.is_empty() {
            return Ok(match self.on_empty {
                OnEmptyBehavior::Allow => crate::decision::TrustDecision::trusted(),
                OnEmptyBehavior::Deny => crate::decision::TrustDecision::denied(vec![format!(
                    "No subjects in scope {}",
                    self.scope.scope_name()
                )]),
            });
        }

        let mut reasons = Vec::new();
        for ds in derived {
            let d = self.inner_rule.evaluate(engine, &ds)?;
            if d.is_trusted {
                return Ok(crate::decision::TrustDecision::trusted());
            }
            reasons.extend(d.reasons);
        }

        Ok(crate::decision::TrustDecision::denied(reasons))
    }
}

/// Scoped builder used inside `for_*` closures.
#[derive(Clone)]
pub struct ScopeRules<S>
where
    S: ScopeProvider,
{
    scope: S,
    on_empty: OnEmptyBehavior,
    dnf: Vec<Vec<TrustRuleRef>>,
    next_op: NextOp,
    required_facts: Vec<FactKey>,
}

impl<S> ScopeRules<S>
where
    S: ScopeProvider,
{
    /// Create a new scoped rule builder.
    fn new(scope: S) -> Self {
        Self {
            scope,
            on_empty: OnEmptyBehavior::Deny,
            dnf: vec![Vec::new()],
            next_op: NextOp::default(),
            required_facts: Vec::new(),
        }
    }

    /// Controls what happens when the scope has no subjects.
    ///
    /// This is useful for optional scopes like counter-signatures.
    pub fn on_empty(mut self, behavior: OnEmptyBehavior) -> Self {
        self.on_empty = behavior;
        self
    }

    /// Set the next composition operator to AND.
    pub fn and(mut self) -> Self {
        self.next_op = NextOp::And;
        self
    }

    /// Set the next composition operator to OR.
    pub fn or(mut self) -> Self {
        self.next_op = NextOp::Or;
        self
    }

    /// Trust unconditionally within this scope.
    ///
    /// Useful for tests and for plans that want to bypass trust evaluation.
    pub fn allow_all(mut self) -> Self {
        self.push_rule(crate::rules::allow_all("AllowAll"));
        self
    }

    /// Add a rule to the current DNF expression using the current next-op.
    fn push_rule(&mut self, rule: TrustRuleRef) {
        match self.next_op {
            NextOp::And => {
                if let Some(last) = self.dnf.last_mut() {
                    last.push(rule);
                } else {
                    self.dnf.push(vec![rule]);
                }
            }
            NextOp::Or => {
                self.dnf.push(vec![rule]);
                self.next_op = NextOp::And;
            }
        }
    }

    /// Require that at least one fact of type `TFact` exists and matches the selector.
    pub fn require<TFact>(mut self, f: impl FnOnce(Where<TFact>) -> Where<TFact>) -> Self
    where
        TFact: crate::fact_properties::FactProperties + Send + Sync + 'static,
    {
        self.required_facts.push(FactKey::of::<TFact>());
        let selector = f(Where {
            selector: FactSelector::first(),
            _phantom: PhantomData,
        })
        .selector;

        let rule = crate::rules::require_fact_matches_with_missing_behavior::<TFact, _>(
            std::any::type_name::<TFact>(),
            |s: &TrustSubject| s.clone(),
            selector,
            crate::rules::MissingBehavior::Deny,
            "RequirementNotSatisfied",
        );
        self.push_rule(rule);
        self
    }

    /// Like `require`, but allows the requirement to be optional.
    ///
    /// If the fact type is missing/error, or if no facts match the selector, this requirement
    /// is treated as trusted.
    pub fn require_optional<TFact>(mut self, f: impl FnOnce(Where<TFact>) -> Where<TFact>) -> Self
    where
        TFact: crate::fact_properties::FactProperties + Send + Sync + 'static,
    {
        self.required_facts.push(FactKey::of::<TFact>());
        let selector = f(Where {
            selector: FactSelector::first(),
            _phantom: PhantomData,
        })
        .selector;

        let rule = crate::rules::require_fact_matches_with_missing_behavior::<TFact, _>(
            std::any::type_name::<TFact>(),
            |s: &TrustSubject| s.clone(),
            selector,
            crate::rules::MissingBehavior::Allow,
            "RequirementNotSatisfied",
        );
        self.push_rule(rule);
        self
    }

    /// Advanced: inject a pre-built rule into this scope.
    ///
    /// This is primarily intended for higher-level extension traits that need richer semantics
    /// than `require::<TFact>(...)` can express (e.g., cross-fact comparisons).
    pub fn require_rule(
        mut self,
        rule: TrustRuleRef,
        required_facts: impl IntoIterator<Item = FactKey>,
    ) -> Self {
        self.push_rule(rule);
        self.required_facts.extend(required_facts);
        self
    }

    /// Convert this scoped builder into a single scoped rule plus required facts.
    fn into_scoped_parts(self) -> (TrustRuleRef, Vec<FactKey>) {
        let inner_rule = compile_dnf("scope", self.dnf);
        (
            Arc::new(ScopedAnyOfSubjects {
                name: "scope",
                scope: self.scope,
                on_empty: self.on_empty,
                inner_rule,
            }),
            self.required_facts,
        )
    }
}

/// Trust plan builder supporting rich AND/OR composition across optional scopes.
#[must_use]
#[derive(Clone, Default)]
pub struct TrustPlanBuilder {
    dnf: Vec<Vec<TrustRuleRef>>,
    next_op: NextOp,
    required_facts: Vec<FactKey>,
}

impl TrustPlanBuilder {
    /// Create a new empty plan builder.
    pub fn new() -> Self {
        Self {
            dnf: vec![Vec::new()],
            next_op: NextOp::And,
            required_facts: Vec::new(),
        }
    }

    /// Set the next composition operator to AND.
    pub fn and(mut self) -> Self {
        self.next_op = NextOp::And;
        self
    }

    /// Set the next composition operator to OR.
    pub fn or(mut self) -> Self {
        self.next_op = NextOp::Or;
        self
    }

    /// Add a rule to the current DNF expression using the current next-op.
    fn push_rule(&mut self, rule: TrustRuleRef) {
        match self.next_op {
            NextOp::And => {
                if let Some(last) = self.dnf.last_mut() {
                    last.push(rule);
                } else {
                    self.dnf.push(vec![rule]);
                }
            }
            NextOp::Or => {
                self.dnf.push(vec![rule]);
                self.next_op = NextOp::And;
            }
        }
    }

    /// AND a nested group built by `f` into the current plan.
    pub fn and_group(mut self, f: impl FnOnce(TrustPlanBuilder) -> TrustPlanBuilder) -> Self {
        let (group_rule, group_required) = f(TrustPlanBuilder::new()).into_compiled_parts();
        self.push_rule(group_rule);
        self.required_facts.extend(group_required);
        self
    }

    /// Add rules scoped to the message subject.
    pub fn for_message(
        mut self,
        f: impl FnOnce(ScopeRules<MessageScope>) -> ScopeRules<MessageScope>,
    ) -> Self {
        let (rule, required) = f(ScopeRules::new(MessageScope)).into_scoped_parts();
        self.push_rule(rule);
        self.required_facts.extend(required);
        self
    }

    /// Add rules scoped to the primary signing key subject derived from the message.
    pub fn for_primary_signing_key(
        mut self,
        f: impl FnOnce(ScopeRules<PrimarySigningKeyScope>) -> ScopeRules<PrimarySigningKeyScope>,
    ) -> Self {
        let (rule, required) = f(ScopeRules::new(PrimarySigningKeyScope)).into_scoped_parts();
        self.push_rule(rule);
        self.required_facts.extend(required);
        self
    }

    /// Scope over subjects discovered from facts on the current subject.
    ///
    /// Example: a crate can produce "CounterSignatureSubjectFact" facts on the message subject;
    /// this method can then build a policy that evaluates against each derived counter-signature.
    pub fn for_subjects_from_facts<TFact>(
        mut self,
        f: impl FnOnce(
            ScopeRules<SubjectsFromFactsScope<TFact>>,
        ) -> ScopeRules<SubjectsFromFactsScope<TFact>>,
    ) -> Self
    where
        TFact: Any + Send + Sync + HasTrustSubject + 'static,
    {
        // Discovering subjects requires the carrier fact type.
        self.required_facts.push(FactKey::of::<TFact>());

        let (rule, required) =
            f(ScopeRules::new(SubjectsFromFactsScope::<TFact>::new())).into_scoped_parts();
        self.push_rule(rule);
        self.required_facts.extend(required);
        self
    }

    /// Convert the builder into a single rule reference plus required facts.
    fn into_compiled_parts(self) -> (TrustRuleRef, Vec<FactKey>) {
        let TrustPlanBuilder {
            dnf,
            required_facts,
            ..
        } = self;
        (compile_dnf("plan", dnf), required_facts)
    }

    /// Compile the builder into an immutable, engine-ready plan.
    pub fn compile(self) -> CompiledTrustPlan {
        let (rule, required_facts) = self.into_compiled_parts();
        CompiledTrustPlan::new(required_facts, Vec::new(), vec![rule], Vec::new())
    }
}

/// A closure-friendly builder for expressing fact predicates without writing custom rules.
///
/// This is intentionally *not* reflection based. You still use typed fields (compile-time checked).
pub struct Where<TFact> {
    selector: FactSelector,
    _phantom: PhantomData<TFact>,
}

impl<TFact> Where<TFact>
where
    TFact: crate::fact_properties::FactProperties + Send + Sync + 'static,
{
    /// Boolean field must be `true`.
    pub fn r#true(mut self, field: Field<TFact, bool>) -> Self {
        self.selector = self.selector.where_pred(
            field.name(),
            PropertyPredicate::Eq(crate::fact_properties::FactValueOwned::Bool(true)),
        );
        self
    }

    /// Boolean field must be `false`.
    pub fn r#false(mut self, field: Field<TFact, bool>) -> Self {
        self.selector = self.selector.where_pred(
            field.name(),
            PropertyPredicate::Eq(crate::fact_properties::FactValueOwned::Bool(false)),
        );
        self
    }

    /// Unsigned size field must equal `expected`.
    pub fn usize_eq(mut self, field: Field<TFact, usize>, expected: usize) -> Self {
        self.selector = self.selector.where_pred(
            field.name(),
            PropertyPredicate::Eq(crate::fact_properties::FactValueOwned::Usize(expected)),
        );
        self
    }

    /// `u32` field must equal `expected`.
    pub fn u32_eq(mut self, field: Field<TFact, u32>, expected: u32) -> Self {
        self.selector = self.selector.where_pred(
            field.name(),
            PropertyPredicate::Eq(crate::fact_properties::FactValueOwned::U32(expected)),
        );
        self
    }

    /// Numeric field must be greater-than-or-equal to `min`.
    pub fn i64_ge(mut self, field: Field<TFact, i64>, min: i64) -> Self {
        self.selector = self
            .selector
            .where_pred(field.name(), PropertyPredicate::NumGeI64(min));
        self
    }

    /// Numeric field must be less-than-or-equal to `max`.
    pub fn i64_le(mut self, field: Field<TFact, i64>, max: i64) -> Self {
        self.selector = self
            .selector
            .where_pred(field.name(), PropertyPredicate::NumLeI64(max));
        self
    }

    /// String field must equal `expected`.
    pub fn str_eq(mut self, field: Field<TFact, String>, expected: impl Into<String>) -> Self {
        self.selector = self.selector.where_pred(
            field.name(),
            PropertyPredicate::Eq(crate::fact_properties::FactValueOwned::String(
                expected.into(),
            )),
        );
        self
    }


    /// String field must be non-empty after trimming.
    pub fn str_non_empty(mut self, field: Field<TFact, String>) -> Self {
        self.selector = self
            .selector
            .where_pred(field.name(), PropertyPredicate::StrNonEmpty);
        self
    }

    /// String field must contain `needle`.
    pub fn str_contains(mut self, field: Field<TFact, String>, needle: impl Into<String>) -> Self {
        self.selector = self
            .selector
            .where_pred(field.name(), PropertyPredicate::StrContains(needle.into()));
        self
    }

    /// String field must match a regular expression pattern.
    pub fn str_matches_regex(
        mut self,
        field: Field<TFact, String>,
        pattern: impl Into<String>,
    ) -> Self {
        self.selector = self.selector.where_pred(
            field.name(),
            PropertyPredicate::StrMatchesRegex(pattern.into()),
        );
        self
    }
}
