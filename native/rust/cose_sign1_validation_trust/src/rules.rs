// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trust rule primitives and combinators.
//!
//! This module is the “boolean algebra” layer of the trust engine.
//! Rules evaluate against facts produced by a [`TrustFactEngine`](crate::facts::TrustFactEngine)
//! for a given [`TrustSubject`](crate::subject::TrustSubject), and return a [`TrustDecision`].
//!
//! Most callers should prefer the fluent builders in [`crate::fluent`], which assemble these
//! combinators into a [`crate::plan::CompiledTrustPlan`].

use crate::audit::{AuditEvent, TrustDecisionAuditBuilder};
use crate::decision::TrustDecision;
use crate::error::TrustError;
use crate::fact_properties::{FactProperties, FactValue, FactValueOwned};
use crate::facts::{FactKey, TrustFactEngine, TrustFactSet};
use crate::subject::TrustSubject;
use parking_lot::Mutex;
use regex::Regex;
use std::any::Any;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnEmptyBehavior {
    /// Treat an empty subject set as success (the scoped rule is effectively optional).
    Allow,
    /// Treat an empty subject set as failure.
    Deny,
}

/// A single trust predicate.
///
/// Rules should be deterministic and side-effect free.
pub trait TrustRule: Send + Sync {
    /// Stable rule name for diagnostics and audit logs.
    fn name(&self) -> &'static str;

    /// Evaluate this rule for `subject`, using `engine` to access facts.
    fn evaluate(
        &self,
        engine: &TrustFactEngine,
        subject: &TrustSubject,
    ) -> Result<TrustDecision, TrustError>;
}

pub type TrustRuleRef = Arc<dyn TrustRule>;

struct AllowAllRule {
    name: &'static str,
}

impl TrustRule for AllowAllRule {
    /// Rule name used for diagnostics.
    fn name(&self) -> &'static str {
        self.name
    }

    /// Always returns trusted.
    fn evaluate(
        &self,
        _engine: &TrustFactEngine,
        _subject: &TrustSubject,
    ) -> Result<TrustDecision, TrustError> {
        Ok(TrustDecision::trusted())
    }
}

/// A rule that always returns trusted.
///
/// Useful for experiments and tests; avoid using this in production trust plans.
pub fn allow_all(name: &'static str) -> TrustRuleRef {
    Arc::new(AllowAllRule { name })
}

/// Returns trusted only if **all** rules are trusted.
pub fn all_of(name: &'static str, rules: Vec<TrustRuleRef>) -> TrustRuleRef {
    Arc::new(AllOf { name, rules })
}

/// Returns trusted if **any** rule is trusted.
///
/// If `rules` is empty, the rule denies by default.
pub fn any_of(name: &'static str, rules: Vec<TrustRuleRef>) -> TrustRuleRef {
    Arc::new(AnyOf { name, rules })
}

/// Logical negation.
pub fn not(name: &'static str, rule: TrustRuleRef) -> TrustRuleRef {
    Arc::new(Not {
        name,
        rule,
        reason: "Negated rule was satisfied",
    })
}

/// Logical negation with a custom deny reason.
pub fn not_with_reason(
    name: &'static str,
    rule: TrustRuleRef,
    reason: &'static str,
) -> TrustRuleRef {
    Arc::new(Not { name, rule, reason })
}

struct AllOf {
    name: &'static str,
    rules: Vec<TrustRuleRef>,
}

impl TrustRule for AllOf {
    /// Rule name used for diagnostics.
    fn name(&self) -> &'static str {
        self.name
    }

    /// Evaluate all inner rules and AND their results.
    fn evaluate(
        &self,
        engine: &TrustFactEngine,
        subject: &TrustSubject,
    ) -> Result<TrustDecision, TrustError> {
        let mut reasons = Vec::new();
        let mut any_denied = false;

        for r in &self.rules {
            let d = r.evaluate(engine, subject)?;
            if !d.is_trusted {
                any_denied = true;
                reasons.extend(d.reasons);
            }
        }

        Ok(if any_denied {
            TrustDecision::denied(reasons)
        } else {
            TrustDecision::trusted()
        })
    }
}

struct AnyOf {
    name: &'static str,
    rules: Vec<TrustRuleRef>,
}

impl TrustRule for AnyOf {
    /// Rule name used for diagnostics.
    fn name(&self) -> &'static str {
        self.name
    }

    /// Evaluate inner rules and OR their results.
    fn evaluate(
        &self,
        engine: &TrustFactEngine,
        subject: &TrustSubject,
    ) -> Result<TrustDecision, TrustError> {
        if self.rules.is_empty() {
            return Ok(TrustDecision::denied(vec![
                "No trust sources were satisfied".to_string(),
            ]));
        }

        let mut reasons = Vec::new();
        for r in &self.rules {
            let d = r.evaluate(engine, subject)?;
            if d.is_trusted {
                return Ok(TrustDecision::trusted());
            }
            reasons.extend(d.reasons);
        }
        Ok(TrustDecision::denied(reasons))
    }
}

struct Not {
    name: &'static str,
    rule: TrustRuleRef,
    reason: &'static str,
}

impl TrustRule for Not {
    /// Rule name used for diagnostics.
    fn name(&self) -> &'static str {
        self.name
    }

    /// Invert the decision of the inner rule.
    fn evaluate(
        &self,
        engine: &TrustFactEngine,
        subject: &TrustSubject,
    ) -> Result<TrustDecision, TrustError> {
        let d = self.rule.evaluate(engine, subject)?;
        Ok(if d.is_trusted {
            TrustDecision::denied(vec![self.reason.to_string()])
        } else {
            TrustDecision::trusted()
        })
    }
}

pub struct FnRule<F> {
    name: &'static str,
    f: F,
}

impl<F> FnRule<F> {
    /// Create a named rule from a closure.
    pub fn new(name: &'static str, f: F) -> Self {
        Self { name, f }
    }
}

impl<F> TrustRule for FnRule<F>
where
    F: for<'a, 'b> Fn(&'a TrustFactEngine, &'b TrustSubject) -> Result<TrustDecision, TrustError>
        + Send
        + Sync
        + 'static,
{
    /// Rule name used for diagnostics.
    fn name(&self) -> &'static str {
        self.name
    }

    /// Evaluate the rule by invoking the stored closure.
    fn evaluate(
        &self,
        engine: &TrustFactEngine,
        subject: &TrustSubject,
    ) -> Result<TrustDecision, TrustError> {
        (self.f)(engine, subject)
    }
}

pub struct AuditedRule {
    inner: TrustRuleRef,
    audit: Arc<Mutex<TrustDecisionAuditBuilder>>,
}

/// Returns a rule that trusts when at least one fact of type `T` exists and matches `predicate`.
///
/// This is a convenience helper to avoid repeating `ensure_fact + get_fact_set` boilerplate.
pub fn require_any<T, SubjectSelector, Predicate>(
    name: &'static str,
    subject_selector: SubjectSelector,
    predicate: Predicate,
    deny_reason: &'static str,
) -> TrustRuleRef
where
    T: Any + Send + Sync,
    SubjectSelector: Fn(&TrustSubject) -> TrustSubject + Send + Sync + 'static,
    Predicate: Fn(&T) -> bool + Send + Sync + 'static,
{
    Arc::new(FnRule::new(
        name,
        move |engine: &TrustFactEngine,
              subject: &TrustSubject|
              -> Result<TrustDecision, TrustError> {
            let target = subject_selector(subject);
            engine.ensure_fact(&target, FactKey::of::<T>())?;

            let set = engine.get_fact_set::<T>(&target)?;
            match set {
                TrustFactSet::Available(values) => {
                    if values.iter().any(|v| predicate(v.as_ref())) {
                        Ok(TrustDecision::trusted())
                    } else {
                        Ok(TrustDecision::denied(vec![deny_reason.to_string()]))
                    }
                }
                TrustFactSet::Missing { reason } => Ok(TrustDecision::denied(vec![format!(
                    "{deny_reason}: {reason}"
                )])),
                TrustFactSet::Error { message } => Ok(TrustDecision::denied(vec![format!(
                    "{deny_reason}: {message}"
                )])),
            }
        },
    ))
}

/// Returns a rule that trusts when at least one fact of type `T` exists.
pub fn require_present<T, SubjectSelector>(
    name: &'static str,
    subject_selector: SubjectSelector,
    deny_reason: &'static str,
) -> TrustRuleRef
where
    T: Any + Send + Sync,
    SubjectSelector: Fn(&TrustSubject) -> TrustSubject + Send + Sync + 'static,
{
    require_any::<T, _, _>(name, subject_selector, |_| true, deny_reason)
}

/// Returns a rule that trusts when the first available fact of type `T` has `accessor(fact) == expected`.
///
/// Use this for typical boolean facts (e.g., `MstReceiptTrustedFact { trusted: bool }`).
pub fn require_bool<T, SubjectSelector, Accessor>(
    name: &'static str,
    subject_selector: SubjectSelector,
    accessor: Accessor,
    expected: bool,
    deny_reason: &'static str,
) -> TrustRuleRef
where
    T: Any + Send + Sync,
    SubjectSelector: Fn(&TrustSubject) -> TrustSubject + Send + Sync + 'static,
    Accessor: Fn(&T) -> bool + Send + Sync + 'static,
{
    require_any::<T, _, _>(
        name,
        subject_selector,
        move |f| accessor(f) == expected,
        deny_reason,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyPredicate {
    Eq(FactValueOwned),
    NotEq(FactValueOwned),
    StrNonEmpty,
    StrContains(String),
    StrStartsWith(String),
    StrEndsWith(String),
    StrMatchesRegex(String),
    NumGeI64(i64),
    NumLeI64(i64),
}

impl PropertyPredicate {
    /// Returns `true` if this predicate matches the given fact value.
    fn matches(&self, actual: FactValue<'_>) -> bool {
        match self {
            PropertyPredicate::Eq(expected) => actual == expected.as_borrowed(),
            PropertyPredicate::NotEq(expected) => actual != expected.as_borrowed(),
            PropertyPredicate::StrNonEmpty => match actual {
                FactValue::Str(s) => !s.trim().is_empty(),
                _ => false,
            },
            PropertyPredicate::StrContains(needle) => match actual {
                FactValue::Str(s) => s.contains(needle),
                _ => false,
            },
            PropertyPredicate::StrStartsWith(prefix) => match actual {
                FactValue::Str(s) => s.starts_with(prefix),
                _ => false,
            },
            PropertyPredicate::StrEndsWith(suffix) => match actual {
                FactValue::Str(s) => s.ends_with(suffix),
                _ => false,
            },
            PropertyPredicate::StrMatchesRegex(pattern) => match actual {
                FactValue::Str(s) => Regex::new(pattern)
                    .map(|re| re.is_match(s.as_ref()))
                    .unwrap_or(false),
                _ => false,
            },
            PropertyPredicate::NumGeI64(min) => match actual {
                FactValue::I64(v) => v >= *min,
                FactValue::U32(v) => (v as i64) >= *min,
                FactValue::Usize(v) => (v as i64) >= *min,
                _ => false,
            },
            PropertyPredicate::NumLeI64(max) => match actual {
                FactValue::I64(v) => v <= *max,
                FactValue::U32(v) => (v as i64) <= *max,
                FactValue::Usize(v) => (v as i64) <= *max,
                _ => false,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactSelector {
    filters: Vec<(&'static str, PropertyPredicate)>,
}

impl FactSelector {
    /// Create a selector that targets the first available fact.
    pub fn first() -> Self {
        Self { filters: vec![] }
    }

    /// Add an equality predicate against a named property.
    pub fn where_eq(mut self, property: &'static str, expected: FactValueOwned) -> Self {
        self.filters
            .push((property, PropertyPredicate::Eq(expected)));
        self
    }

    /// Add a custom predicate against a named property.
    pub fn where_pred(mut self, property: &'static str, predicate: PropertyPredicate) -> Self {
        self.filters.push((property, predicate));
        self
    }

    /// Convenience for a boolean equality predicate.
    pub fn where_bool(self, property: &'static str, expected: bool) -> Self {
        self.where_eq(property, FactValueOwned::Bool(expected))
    }

    /// Convenience for a `usize` equality predicate.
    pub fn where_usize(self, property: &'static str, expected: usize) -> Self {
        self.where_eq(property, FactValueOwned::Usize(expected))
    }

    /// Convenience for a `u32` equality predicate.
    pub fn where_u32(self, property: &'static str, expected: u32) -> Self {
        self.where_eq(property, FactValueOwned::U32(expected))
    }

    /// Convenience for an `i64` equality predicate.
    pub fn where_i64(self, property: &'static str, expected: i64) -> Self {
        self.where_eq(property, FactValueOwned::I64(expected))
    }

    /// Returns `true` if all selector predicates match the given fact.
    fn matches<T: FactProperties>(&self, fact: &T) -> bool {
        for (property, predicate) in &self.filters {
            let Some(actual) = fact.get_property(property) else {
                return false;
            };
            if !predicate.matches(actual) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingBehavior {
    Deny,
    Allow,
}

/// Select the first fact that matches the selector.
fn select_fact<'a, T: FactProperties>(
    values: &'a [Arc<T>],
    selector: &FactSelector,
) -> Option<&'a T> {
    values
        .iter()
        .map(|v| v.as_ref())
        .find(|v| selector.matches(*v))
}

/// Returns a rule that trusts when a selected fact of type `T` has `property == expected`.
///

/// Returns a rule that trusts when a selected fact of type `T` has a boolean property equal to `expected`.
/// This is fully declarative: callers name the fact type + the property.
pub fn require_fact_property_eq<T, SubjectSelector>(
    name: &'static str,
    subject_selector: SubjectSelector,
    selector: FactSelector,
    property: &'static str,
    expected: FactValueOwned,
    deny_reason: &'static str,
) -> TrustRuleRef
where
    T: Any + Send + Sync + FactProperties,
    SubjectSelector: Fn(&TrustSubject) -> TrustSubject + Send + Sync + 'static,
{
    require_fact_property::<T, _>(
        name,
        subject_selector,
        selector,
        property,
        PropertyPredicate::Eq(expected),
        deny_reason,
    )
}

/// Returns a rule that trusts when a selected fact of type `T` has a property matching `predicate`.
pub fn require_fact_property<T, SubjectSelector>(
    name: &'static str,
    subject_selector: SubjectSelector,
    selector: FactSelector,
    property: &'static str,
    predicate: PropertyPredicate,
    deny_reason: &'static str,
) -> TrustRuleRef
where
    T: Any + Send + Sync + FactProperties,
    SubjectSelector: Fn(&TrustSubject) -> TrustSubject + Send + Sync + 'static,
{
    Arc::new(FnRule::new(
        name,
        move |engine: &TrustFactEngine,
              subject: &TrustSubject|
              -> Result<TrustDecision, TrustError> {
            let target = subject_selector(subject);
            engine.ensure_fact(&target, FactKey::of::<T>())?;

            let set = engine.get_fact_set::<T>(&target)?;
            let values = match set {
                TrustFactSet::Available(values) => values,
                TrustFactSet::Missing { reason } => {
                    return Ok(TrustDecision::denied(vec![format!(
                        "{deny_reason}: {reason}"
                    )]))
                }
                TrustFactSet::Error { message } => {
                    return Ok(TrustDecision::denied(vec![format!(
                        "{deny_reason}: {message}"
                    )]))
                }
            };

            let Some(selected) = select_fact(&values, &selector) else {
                return Ok(TrustDecision::denied(vec![deny_reason.to_string()]));
            };

            let Some(actual) = selected.get_property(property) else {
                return Ok(TrustDecision::denied(vec![deny_reason.to_string()]));
            };

            Ok(if predicate.matches(actual) {
                TrustDecision::trusted()
            } else {
                TrustDecision::denied(vec![deny_reason.to_string()])
            })
        },
    ))
}

/// Returns a rule that trusts when at least one fact of type `T` exists that matches `selector`.
///
/// This is the core primitive for fluent "Require<T>().Where(...).Where(...)" style policies.
pub fn require_fact_matches<T, SubjectSelector>(
    name: &'static str,
    subject_selector: SubjectSelector,
    selector: FactSelector,
    deny_reason: &'static str,
) -> TrustRuleRef
where
    T: Any + Send + Sync + FactProperties,
    SubjectSelector: Fn(&TrustSubject) -> TrustSubject + Send + Sync + 'static,
{
    Arc::new(FnRule::new(
        name,
        move |engine: &TrustFactEngine,
              subject: &TrustSubject|
              -> Result<TrustDecision, TrustError> {
            let target = subject_selector(subject);
            engine.ensure_fact(&target, FactKey::of::<T>())?;

            let set = engine.get_fact_set::<T>(&target)?;
            let values = match set {
                TrustFactSet::Available(values) => values,
                TrustFactSet::Missing { reason } => {
                    return Ok(TrustDecision::denied(vec![format!(
                        "{deny_reason}: {reason}"
                    )]))
                }
                TrustFactSet::Error { message } => {
                    return Ok(TrustDecision::denied(vec![format!(
                        "{deny_reason}: {message}"
                    )]))
                }
            };

            Ok(if select_fact(&values, &selector).is_some() {
                TrustDecision::trusted()
            } else {
                TrustDecision::denied(vec![deny_reason.to_string()])
            })
        },
    ))
}

/// Like `require_fact_matches`, but allows callers to control what happens when the fact set is
/// missing/error or when no facts match the selector.
pub fn require_fact_matches_with_missing_behavior<T, SubjectSelector>(
    name: &'static str,
    subject_selector: SubjectSelector,
    selector: FactSelector,
    missing: MissingBehavior,
    deny_reason: &'static str,
) -> TrustRuleRef
where
    T: Any + Send + Sync + FactProperties,
    SubjectSelector: Fn(&TrustSubject) -> TrustSubject + Send + Sync + 'static,
{
    Arc::new(FnRule::new(
        name,
        move |engine: &TrustFactEngine,
              subject: &TrustSubject|
              -> Result<TrustDecision, TrustError> {
            let target = subject_selector(subject);
            engine.ensure_fact(&target, FactKey::of::<T>())?;

            let set = engine.get_fact_set::<T>(&target)?;
            let values = match set {
                TrustFactSet::Available(values) => values,
                TrustFactSet::Missing { .. } | TrustFactSet::Error { .. } => {
                    return Ok(match missing {
                        MissingBehavior::Allow => TrustDecision::trusted(),
                        MissingBehavior::Deny => {
                            TrustDecision::denied(vec![deny_reason.to_string()])
                        }
                    })
                }
            };

            Ok(if select_fact(&values, &selector).is_some() {
                TrustDecision::trusted()
            } else {
                match missing {
                    MissingBehavior::Allow => TrustDecision::trusted(),
                    MissingBehavior::Deny => TrustDecision::denied(vec![deny_reason.to_string()]),
                }
            })
        },
    ))
}

pub fn require_fact_bool<T, SubjectSelector>(
    name: &'static str,
    subject_selector: SubjectSelector,
    selector: FactSelector,
    property: &'static str,
    expected: bool,
    deny_reason: &'static str,
) -> TrustRuleRef
where
    T: Any + Send + Sync + FactProperties,
    SubjectSelector: Fn(&TrustSubject) -> TrustSubject + Send + Sync + 'static,
{
    require_fact_property_eq::<T, _>(
        name,
        subject_selector,
        selector,
        property,
        FactValueOwned::Bool(expected),
        deny_reason,
    )
}

/// Returns a rule that trusts when a selected fact of type `T` has a non-empty string property.
pub fn require_fact_str_non_empty<T, SubjectSelector>(
    name: &'static str,
    subject_selector: SubjectSelector,
    selector: FactSelector,
    property: &'static str,
    deny_reason: &'static str,
) -> TrustRuleRef
where
    T: Any + Send + Sync + FactProperties,
    SubjectSelector: Fn(&TrustSubject) -> TrustSubject + Send + Sync + 'static,
{
    require_fact_property::<T, _>(
        name,
        subject_selector,
        selector,
        property,
        PropertyPredicate::StrNonEmpty,
        deny_reason,
    )
}

/// Compares properties across two fact types after selecting one fact from each set.
///
/// Example use-cases:
/// - ensure the signing cert identity matches the chain element 0 identity
/// - ensure issuer == next chain element subject (if present)
pub fn require_facts_match<L, R, SubjectSelector>(
    name: &'static str,
    subject_selector: SubjectSelector,
    left_selector: FactSelector,
    right_selector: FactSelector,
    property_pairs: Vec<(&'static str, &'static str)>,
    missing_right: MissingBehavior,
    deny_reason: &'static str,
) -> TrustRuleRef
where
    L: Any + Send + Sync + FactProperties,
    R: Any + Send + Sync + FactProperties,
    SubjectSelector: Fn(&TrustSubject) -> TrustSubject + Send + Sync + 'static,
{
    Arc::new(FnRule::new(
        name,
        move |engine: &TrustFactEngine,
              subject: &TrustSubject|
              -> Result<TrustDecision, TrustError> {
            let target = subject_selector(subject);
            engine.ensure_fact(&target, FactKey::of::<L>())?;
            engine.ensure_fact(&target, FactKey::of::<R>())?;

            let left_set = engine.get_fact_set::<L>(&target)?;
            let right_set = engine.get_fact_set::<R>(&target)?;

            let left_values = match left_set {
                TrustFactSet::Available(values) => values,
                TrustFactSet::Missing { reason } => {
                    return Ok(TrustDecision::denied(vec![format!(
                        "{deny_reason}: {reason}"
                    )]))
                }
                TrustFactSet::Error { message } => {
                    return Ok(TrustDecision::denied(vec![format!(
                        "{deny_reason}: {message}"
                    )]))
                }
            };

            let right_values = match right_set {
                TrustFactSet::Available(values) => values,
                TrustFactSet::Missing { reason } => {
                    return Ok(TrustDecision::denied(vec![format!(
                        "{deny_reason}: {reason}"
                    )]))
                }
                TrustFactSet::Error { message } => {
                    return Ok(TrustDecision::denied(vec![format!(
                        "{deny_reason}: {message}"
                    )]))
                }
            };

            let Some(left) = select_fact(&left_values, &left_selector) else {
                return Ok(TrustDecision::denied(vec![deny_reason.to_string()]));
            };

            let right = select_fact(&right_values, &right_selector);
            let Some(right) = right else {
                return Ok(match missing_right {
                    MissingBehavior::Allow => TrustDecision::trusted(),
                    MissingBehavior::Deny => TrustDecision::denied(vec![deny_reason.to_string()]),
                });
            };

            for (left_prop, right_prop) in &property_pairs {
                let Some(left_val) = left.get_property(left_prop) else {
                    return Ok(TrustDecision::denied(vec![deny_reason.to_string()]));
                };
                let Some(right_val) = right.get_property(right_prop) else {
                    return Ok(TrustDecision::denied(vec![deny_reason.to_string()]));
                };
                if left_val != right_val {
                    return Ok(TrustDecision::denied(vec![deny_reason.to_string()]));
                }
            }

            Ok(TrustDecision::trusted())
        },
    ))
}

impl AuditedRule {
    #[allow(clippy::new_ret_no_self)]
    /// Wrap a rule and emit an audit event each time it is evaluated.
    pub fn new(inner: TrustRuleRef, audit: Arc<Mutex<TrustDecisionAuditBuilder>>) -> TrustRuleRef {
        Arc::new(Self { inner, audit })
    }
}

impl TrustRule for AuditedRule {
    /// Rule name used for diagnostics.
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    /// Evaluate the inner rule and record the result into the audit log.
    fn evaluate(
        &self,
        engine: &TrustFactEngine,
        subject: &TrustSubject,
    ) -> Result<TrustDecision, TrustError> {
        let decision = self.inner.evaluate(engine, subject)?;
        self.audit.lock().push(AuditEvent::RuleEvaluated {
            subject: subject.id,
            rule_name: self.inner.name(),
            decision: decision.clone(),
        });
        Ok(decision)
    }
}
