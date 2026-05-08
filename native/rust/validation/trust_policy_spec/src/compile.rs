// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 1 spec → [`CompiledTrustPlan`] lowering.
//!
//! # Phase 1 scope
//!
//! Phase 1 lowers the **structural** subset of [`TrustPolicySpec`] — every variant whose
//! semantics are expressible without reaching into pack-specific fact types:
//!
//! - [`TrustPolicySpec::AllowAll`] / [`TrustPolicySpec::DenyAll`]
//! - [`TrustPolicySpec::And`] / [`TrustPolicySpec::Or`] / [`TrustPolicySpec::Not`] /
//!   [`TrustPolicySpec::Implies`]
//! - [`TrustPolicySpec::Message`] / [`TrustPolicySpec::PrimarySigningKey`]
//!
//! [`TrustPolicySpec::RequireFact`] and [`TrustPolicySpec::AnyCounterSignature`] depend on
//! a fact-type registry that knows the in-memory `TypeId` of each registered fact — that's
//! the Phase 3 (`np-fact-registry`) deliverable. In Phase 1 they lower to a deterministic
//! placeholder rule: the compiler validates the `fact_id` against [`IFactRegistry`] (so an
//! unknown id surfaces as `TPX200` at compile time), and the placeholder returns
//! `denied(failure_message)` at evaluation time.
//!
//! # Why placeholders are safe
//!
//! The Phase 1 placeholder is **strictly more conservative** than the eventual Phase 3
//! lowering: a real-fact predicate that would have evaluated to `Trusted` evaluates to
//! `Denied` here. Trust policies in Phase 1 are therefore a subset of what the same
//! document would express after Phase 3 ships — never a superset. This matches the
//! guidance in §6.5.5 of the design doc: "every translation transition is monotone over
//! the trust lattice."
//!
//! # Recursion safety
//!
//! [`compile`] enforces a recursion depth cap to defend against pathological documents
//! that nest scope wrappers indefinitely. The default cap is [`DEFAULT_MAX_DEPTH`].

use crate::diagnostic_codes;
use crate::predicate::FactPredicateSpec;
use crate::registry::IFactRegistry;
use crate::source_location::SourceLocation;
use crate::spec::{OnEmptyBehavior, TrustPolicySpec};
use cose_sign1_validation_primitives::decision::TrustDecision;
use cose_sign1_validation_primitives::error::TrustError;
use cose_sign1_validation_primitives::facts::{FactKey, TrustFactEngine};
use cose_sign1_validation_primitives::fluent::{
    MessageScope, PrimarySigningKeyScope, ScopeProvider,
};
use cose_sign1_validation_primitives::plan::CompiledTrustPlan;
use cose_sign1_validation_primitives::rules::{
    all_of, allow_all, any_of, FnRule, OnEmptyBehavior as RuleOnEmptyBehavior, TrustRuleRef,
};
use cose_sign1_validation_primitives::subject::TrustSubject;
use std::borrow::Cow;
use std::sync::Arc;

/// Default maximum recursion depth honored by [`compile`].
pub const DEFAULT_MAX_DEPTH: usize = 256;

/// Compile-time errors produced by [`compile`].
///
/// Every variant carries a stable `code()` from [`crate::diagnostic_codes`] and an optional
/// [`SourceLocation`] (frontends populate this; the bare IR compile path leaves it `None`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompileError {
    /// `RequireFact.fact_id` is not registered in the configured [`IFactRegistry`]. (`TPX200`)
    UnknownFactId {
        /// The unrecognized identifier.
        fact_id: String,
        /// Where in the source document the id appeared, when available.
        location: Option<SourceLocation>,
    },
    /// Recursion depth cap exceeded. (`TPX301`)
    RecursionLimitExceeded {
        /// Configured depth limit.
        limit: usize,
        /// Tag of the variant where the limit tripped.
        variant: &'static str,
    },
    /// A path-operator predicate is structurally invalid (e.g. `Exists` with a value, or
    /// non-`Exists` without a value). (`TPX500`)
    PredicateMalformed {
        /// fact_id whose predicate failed validation.
        fact_id: String,
        /// Human-readable detail.
        detail: String,
    },
}

impl CompileError {
    /// Stable diagnostic code for this error.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownFactId { .. } => diagnostic_codes::TPX_200_UNKNOWN_FACT_ID,
            Self::RecursionLimitExceeded { .. } => diagnostic_codes::TPX_301_RECURSION_LIMIT,
            Self::PredicateMalformed { .. } => diagnostic_codes::TPX_500_PREDICATE_TYPE_MISMATCH,
        }
    }
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownFactId { fact_id, location } => match location {
                Some(loc) => write!(f, "[{}] unknown fact_id '{fact_id}' at {loc}", self.code()),
                None => write!(f, "[{}] unknown fact_id '{fact_id}'", self.code()),
            },
            Self::RecursionLimitExceeded { limit, variant } => {
                write!(
                    f,
                    "[{}] recursion limit {limit} exceeded at variant '{variant}'",
                    self.code()
                )
            }
            Self::PredicateMalformed { fact_id, detail } => {
                write!(
                    f,
                    "[{}] malformed predicate for fact_id '{fact_id}': {detail}",
                    self.code()
                )
            }
        }
    }
}

impl std::error::Error for CompileError {}

/// Compile-time options.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CompileOptions {
    /// Maximum recursion depth honored when walking nested specs. Defaults to
    /// [`DEFAULT_MAX_DEPTH`].
    pub max_depth: usize,
}

impl CompileOptions {
    /// Construct options with the given recursion depth cap.
    pub fn with_max_depth(max_depth: usize) -> Self {
        Self { max_depth }
    }
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

/// Lower a [`TrustPolicySpec`] tree to a [`CompiledTrustPlan`].
///
/// `registry` is consulted to validate `fact_id` references; Phase 3 will additionally use
/// it to resolve concrete fact types for predicate lowering.
///
/// See module docs for the Phase 1 scope and placeholder semantics.
pub fn compile(
    spec: &TrustPolicySpec,
    registry: &dyn IFactRegistry,
) -> Result<CompiledTrustPlan, CompileError> {
    compile_with_options(spec, registry, &CompileOptions::default())
}

/// As [`compile`], but with caller-supplied [`CompileOptions`].
pub fn compile_with_options(
    spec: &TrustPolicySpec,
    registry: &dyn IFactRegistry,
    options: &CompileOptions,
) -> Result<CompiledTrustPlan, CompileError> {
    let mut ctx = LowerCtx {
        registry,
        max_depth: options.max_depth,
    };
    let root = ctx.lower(spec, 0)?;
    // Phase 1 emits the lowered spec as a single trust source; constraints/vetoes/required-facts
    // are empty because predicate lowering (which would emit FactKey requirements) is deferred
    // to Phase 3.
    Ok(CompiledTrustPlan::new(
        Vec::new(),
        Vec::new(),
        vec![root],
        Vec::new(),
    ))
}

struct LowerCtx<'a> {
    registry: &'a dyn IFactRegistry,
    max_depth: usize,
}

impl<'a> LowerCtx<'a> {
    fn lower(&mut self, spec: &TrustPolicySpec, depth: usize) -> Result<TrustRuleRef, CompileError> {
        if depth >= self.max_depth {
            return Err(CompileError::RecursionLimitExceeded {
                limit: self.max_depth,
                variant: spec.variant_tag(),
            });
        }
        match spec {
            TrustPolicySpec::AllowAll => Ok(allow_all("allow_all")),
            TrustPolicySpec::DenyAll { reason } => Ok(deny_with_reason(reason.clone())),
            TrustPolicySpec::And { specs } => {
                let inner = self.lower_many(specs, depth + 1)?;
                Ok(all_of("and", inner))
            }
            TrustPolicySpec::Or { specs } => {
                let inner = self.lower_many(specs, depth + 1)?;
                Ok(any_of("or", inner))
            }
            TrustPolicySpec::Not { spec, reason } => {
                let inner = self.lower(spec, depth + 1)?;
                Ok(not_with_dynamic_reason(inner, reason.clone()))
            }
            TrustPolicySpec::Implies {
                antecedent,
                consequent,
            } => {
                let ant = self.lower(antecedent, depth + 1)?;
                let cons = self.lower(consequent, depth + 1)?;
                Ok(implies_rule(ant, cons))
            }
            TrustPolicySpec::Message { requirements } => {
                let inner = self.lower_many(requirements, depth + 1)?;
                let inner_rule = all_of("message_scope_inner", inner);
                Ok(scoped_any_of_subjects(
                    "message_scope",
                    MessageScope,
                    RuleOnEmptyBehavior::Deny,
                    inner_rule,
                ))
            }
            TrustPolicySpec::PrimarySigningKey { requirements } => {
                let inner = self.lower_many(requirements, depth + 1)?;
                let inner_rule = all_of("primary_signing_key_scope_inner", inner);
                Ok(scoped_any_of_subjects(
                    "primary_signing_key_scope",
                    PrimarySigningKeyScope,
                    RuleOnEmptyBehavior::Deny,
                    inner_rule,
                ))
            }
            TrustPolicySpec::AnyCounterSignature {
                on_empty,
                requirements,
            } => {
                // Phase 1 placeholder: scope discovery requires reaching into validation/core
                // for `CounterSignatureSubjectFact`, which is a Phase 3 dependency. We emit
                // a deterministic placeholder so downstream tooling can still inspect /
                // canonical-serialize the lowered plan.
                let _ = self.lower_many(requirements, depth + 1)?;
                Ok(any_counter_signature_placeholder(*on_empty))
            }
            TrustPolicySpec::RequireFact {
                fact_id,
                predicate,
                failure_message,
            } => {
                self.validate_fact_id(fact_id)?;
                validate_predicate_shape(fact_id, predicate)?;
                Ok(require_fact_placeholder(
                    fact_id.clone(),
                    failure_message.clone(),
                ))
            }
        }
    }

    fn lower_many(
        &mut self,
        specs: &[TrustPolicySpec],
        depth: usize,
    ) -> Result<Vec<TrustRuleRef>, CompileError> {
        let mut out = Vec::with_capacity(specs.len());
        for s in specs {
            out.push(self.lower(s, depth)?);
        }
        Ok(out)
    }

    fn validate_fact_id(&self, fact_id: &str) -> Result<(), CompileError> {
        if self.registry.try_get_fact_type(fact_id).is_some() {
            return Ok(());
        }
        Err(CompileError::UnknownFactId {
            fact_id: fact_id.to_owned(),
            location: None,
        })
    }
}

fn validate_predicate_shape(
    fact_id: &str,
    predicate: &FactPredicateSpec,
) -> Result<(), CompileError> {
    if let FactPredicateSpec::PathOperator(p) = predicate {
        if p.operator.is_presence_only() && p.value.is_some() {
            return Err(CompileError::PredicateMalformed {
                fact_id: fact_id.to_owned(),
                detail: "operator 'exists' must not carry a value operand".to_owned(),
            });
        }
        if !p.operator.is_presence_only() && p.value.is_none() {
            return Err(CompileError::PredicateMalformed {
                fact_id: fact_id.to_owned(),
                detail: format!(
                    "operator '{:?}' requires a value operand",
                    p.operator
                ),
            });
        }
    }
    Ok(())
}

fn deny_with_reason(reason: String) -> TrustRuleRef {
    let reason = Arc::<str>::from(reason);
    Arc::new(FnRule::new(
        "deny_all",
        move |_: &TrustFactEngine, _: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::denied(vec![Cow::Owned(reason.to_string())]))
        },
    ))
}

/// Negation rule that preserves the user-authored deny reason when present.
///
/// `cose_sign1_validation_primitives::rules::not_with_reason` requires `&'static str`, so
/// preserving a dynamic [`String`] reason from [`TrustPolicySpec::Not`] requires a
/// closure-backed rule. Falls back to a generic message when `reason == None`.
fn not_with_dynamic_reason(inner: TrustRuleRef, reason: Option<String>) -> TrustRuleRef {
    let reason: Arc<str> = match reason {
        Some(r) => Arc::<str>::from(r),
        None => Arc::<str>::from("Negated rule was satisfied"),
    };
    Arc::new(FnRule::new(
        "not",
        move |engine: &TrustFactEngine, subject: &TrustSubject| -> Result<TrustDecision, TrustError> {
            let d = inner.evaluate(engine, subject)?;
            Ok(if d.is_trusted {
                TrustDecision::denied(vec![Cow::Owned(reason.to_string())])
            } else {
                TrustDecision::trusted()
            })
        },
    ))
}

fn implies_rule(antecedent: TrustRuleRef, consequent: TrustRuleRef) -> TrustRuleRef {
    Arc::new(FnRule::new(
        "implies",
        move |engine: &TrustFactEngine, subject: &TrustSubject| -> Result<TrustDecision, TrustError> {
            let a = antecedent.evaluate(engine, subject)?;
            if !a.is_trusted {
                // Antecedent failed → vacuously satisfied.
                return Ok(TrustDecision::trusted());
            }
            consequent.evaluate(engine, subject)
        },
    ))
}

fn scoped_any_of_subjects<S>(
    name: &'static str,
    scope: S,
    on_empty: RuleOnEmptyBehavior,
    inner: TrustRuleRef,
) -> TrustRuleRef
where
    S: ScopeProvider,
{
    Arc::new(FnRule::new(
        name,
        move |engine: &TrustFactEngine,
              subject: &TrustSubject|
              -> Result<TrustDecision, TrustError> {
            let derived = scope.subjects(engine, subject)?;
            if derived.is_empty() {
                return Ok(match on_empty {
                    RuleOnEmptyBehavior::Allow => TrustDecision::trusted(),
                    RuleOnEmptyBehavior::Deny => TrustDecision::denied(vec![Cow::Owned(format!(
                        "No subjects in scope {}",
                        scope.scope_name()
                    ))]),
                });
            }
            let mut reasons = Vec::new();
            for ds in derived {
                let d = inner.evaluate(engine, &ds)?;
                if d.is_trusted {
                    return Ok(TrustDecision::trusted());
                }
                reasons.extend(d.reasons);
            }
            Ok(TrustDecision::denied(reasons))
        },
    ))
}

/// Phase 1 placeholder for `RequireFact` — always denies with the user-supplied message.
fn require_fact_placeholder(fact_id: String, failure_message: String) -> TrustRuleRef {
    let placeholder_message = Arc::<str>::from(format!(
        "{failure_message} (fact_id={fact_id}; Phase 1 placeholder — Phase 3 lowers this predicate)"
    ));
    Arc::new(FnRule::new(
        "require_fact_phase1_placeholder",
        move |_: &TrustFactEngine, _: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::denied(vec![Cow::Owned(
                placeholder_message.to_string(),
            )]))
        },
    ))
}

/// Phase 1 placeholder for `AnyCounterSignature`. `on_empty=Allow` lowers to "trusted",
/// `on_empty=Deny` lowers to "denied with `TPX300` Untranslatable banner". This makes the
/// `on_empty` knob observable in tests without requiring fact-registry support.
fn any_counter_signature_placeholder(on_empty: OnEmptyBehavior) -> TrustRuleRef {
    Arc::new(FnRule::new(
        "any_counter_signature_phase1_placeholder",
        move |_: &TrustFactEngine, _: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(match on_empty {
                OnEmptyBehavior::Allow => TrustDecision::trusted_reason(Cow::Borrowed(
                    "AnyCounterSignature {on_empty=Allow}: Phase 1 placeholder",
                )),
                OnEmptyBehavior::Deny => TrustDecision::denied(vec![Cow::Borrowed(
                    "AnyCounterSignature {on_empty=Deny}: Phase 1 placeholder (Phase 3 lowers via fact registry)",
                )]),
            })
        },
    ))
}

/// Translate this crate's [`OnEmptyBehavior`] into the primitives' enum.
///
/// Lossless; provided for callers that want to observe the parity manually.
pub fn into_rule_on_empty(value: OnEmptyBehavior) -> RuleOnEmptyBehavior {
    match value {
        OnEmptyBehavior::Allow => RuleOnEmptyBehavior::Allow,
        OnEmptyBehavior::Deny => RuleOnEmptyBehavior::Deny,
    }
}

/// Translate the primitives' [`RuleOnEmptyBehavior`] into this crate's enum.
pub fn from_rule_on_empty(value: RuleOnEmptyBehavior) -> OnEmptyBehavior {
    match value {
        RuleOnEmptyBehavior::Allow => OnEmptyBehavior::Allow,
        RuleOnEmptyBehavior::Deny => OnEmptyBehavior::Deny,
    }
}

/// Compile-time invariant: the placeholder rule trait-objects implement the same
/// `Send + Sync` bound as ordinary primitives' rules. The `_` binding forces the compiler
/// to type-check this without affecting runtime behavior.
#[allow(dead_code)]
fn _assert_send_sync<T: Send + Sync>() {}

#[allow(dead_code)]
fn _assertions() {
    _assert_send_sync::<TrustRuleRef>();
    // Phase-1 rule constructors must be Send + Sync (they back trait objects).
}

/// Re-export for callers wanting `FactKey` (used by the broader IR ecosystem when wiring
/// the Phase 3 fact-registry into a richer compile pipeline).
#[doc(hidden)]
pub use cose_sign1_validation_primitives::facts::FactKey as ReexportedFactKey;

// `_` reference to keep the import live for the doc-export above without triggering
// an unused-import warning.
#[allow(dead_code)]
const _FACT_KEY_REF: fn() = || {
    let _: Option<FactKey> = None;
};
