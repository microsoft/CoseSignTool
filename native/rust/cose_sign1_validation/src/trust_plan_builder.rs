// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::message_facts::{
    CounterSignatureSigningKeySubjectFact, CounterSignatureSubjectFact,
    PrimarySigningKeySubjectFact,
};
use crate::trust_packs::CoseSign1TrustPack;
use cose_sign1_validation_trust::facts::{FactKey, TrustFactProducer};
use cose_sign1_validation_trust::fluent as trust_fluent;
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use std::collections::HashSet;
use std::sync::Arc;

impl trust_fluent::HasTrustSubject for CounterSignatureSubjectFact {
    /// Returns the derived counter-signature subject carried by this fact.
    fn trust_subject(&self) -> &cose_sign1_validation_trust::subject::TrustSubject {
        &self.subject
    }
}

impl trust_fluent::HasTrustSubject for CounterSignatureSigningKeySubjectFact {
    /// Returns the derived counter-signature signing key subject carried by this fact.
    fn trust_subject(&self) -> &cose_sign1_validation_trust::subject::TrustSubject {
        &self.subject
    }
}

impl trust_fluent::HasTrustSubject for PrimarySigningKeySubjectFact {
    /// Returns the derived primary signing key subject carried by this fact.
    fn trust_subject(&self) -> &cose_sign1_validation_trust::subject::TrustSubject {
        &self.subject
    }
}

/// C#-style fluent trust-plan builder with explicit scopes and plan-level AND/OR.
///
/// This wraps the lower-level trust DSL and adds convenience scope names for this crate,
/// including counter-signature discovery.
///
/// Note: message facts (e.g., content-type, detached-payload presence) are always available at
/// runtime and during plan compilation checks. Callers should not need to provide a special
/// "message trust pack".
#[must_use]
#[derive(Clone)]
pub struct TrustPlanBuilder {
    inner: trust_fluent::TrustPlanBuilder,
    trust_packs: Vec<Arc<dyn CoseSign1TrustPack>>,
}

impl TrustPlanBuilder {
    /// Create a new builder bound to a specific set of trust packs.
    ///
    /// The pack list is used during `compile()` to validate that all required facts can be
    /// produced at runtime.
    pub fn new(trust_packs: Vec<Arc<dyn CoseSign1TrustPack>>) -> Self {
        Self {
            inner: trust_fluent::TrustPlanBuilder::new(),
            trust_packs,
        }
    }

    /// Set the next composition operator to AND.
    pub fn and(mut self) -> Self {
        self.inner = self.inner.and();
        self
    }

    /// Set the next composition operator to OR.
    pub fn or(mut self) -> Self {
        self.inner = self.inner.or();
        self
    }

    /// Adds a parenthesized sub-expression to the plan (AND semantics).
    pub fn and_group(mut self, f: impl FnOnce(TrustPlanBuilder) -> TrustPlanBuilder) -> Self {
        let group = f(TrustPlanBuilder::new(self.trust_packs.clone()));
        self.inner = self.inner.and_group(|_| group.inner);
        self
    }

    /// Add rules scoped to the message subject.
    pub fn for_message(
        mut self,
        f: impl FnOnce(
            trust_fluent::ScopeRules<trust_fluent::MessageScope>,
        ) -> trust_fluent::ScopeRules<trust_fluent::MessageScope>,
    ) -> Self {
        self.inner = self.inner.for_message(f);
        self
    }

    /// Add rules scoped to the derived primary signing key subject.
    pub fn for_primary_signing_key(
        mut self,
        f: impl FnOnce(
            trust_fluent::ScopeRules<trust_fluent::PrimarySigningKeyScope>,
        ) -> trust_fluent::ScopeRules<trust_fluent::PrimarySigningKeyScope>,
    ) -> Self {
        self.inner = self.inner.for_primary_signing_key(f);
        self
    }

    /// Scopes to each discovered counter signature subject.
    ///
    /// Default is `OnEmptyBehavior::Deny`; use `scope.on_empty(OnEmptyBehavior::Allow)` to make this optional.
    pub fn for_counter_signature(
        mut self,
        f: impl FnOnce(
            trust_fluent::ScopeRules<
                trust_fluent::SubjectsFromFactsScope<CounterSignatureSubjectFact>,
            >,
        ) -> trust_fluent::ScopeRules<
            trust_fluent::SubjectsFromFactsScope<CounterSignatureSubjectFact>,
        >,
    ) -> Self {
        self.inner = self
            .inner
            .for_subjects_from_facts::<CounterSignatureSubjectFact>(f);
        self
    }

    /// Scopes to each discovered counter signature *signing key* subject.
    pub fn for_counter_signature_signing_key(
        mut self,
        f: impl FnOnce(
            trust_fluent::ScopeRules<
                trust_fluent::SubjectsFromFactsScope<CounterSignatureSigningKeySubjectFact>,
            >,
        ) -> trust_fluent::ScopeRules<
            trust_fluent::SubjectsFromFactsScope<CounterSignatureSigningKeySubjectFact>,
        >,
    ) -> Self {
        self.inner = self
            .inner
            .for_subjects_from_facts::<CounterSignatureSigningKeySubjectFact>(f);
        self
    }

    /// Compile the plan and validate pack coverage.
    ///
    /// This ensures all required facts referenced by the plan are provided by the configured
    /// trust packs (message facts are always available).
    pub fn compile(self) -> Result<CoseSign1CompiledTrustPlan, TrustPlanCompileError> {
        let plan = self.inner.compile();
        validate_plan_requires_only_available_fact_types(&plan, &self.trust_packs)?;
        Ok(CoseSign1CompiledTrustPlan {
            plan,
            trust_packs: self.trust_packs,
        })
    }
}

/// A compiled trust plan bundled with the trust packs required to evaluate it.
///
/// The validator uses this to derive:
/// - fact producers (message facts + pack producers)
/// - signing-key resolvers
/// - post-signature validators
#[derive(Clone)]
pub struct CoseSign1CompiledTrustPlan {
    plan: CompiledTrustPlan,
    trust_packs: Vec<Arc<dyn CoseSign1TrustPack>>,
}

impl CoseSign1CompiledTrustPlan {
    /// Access the compiled plan.
    pub fn plan(&self) -> &CompiledTrustPlan {
        &self.plan
    }

    /// Access the trust packs required to evaluate the plan.
    pub fn trust_packs(&self) -> &[Arc<dyn CoseSign1TrustPack>] {
        self.trust_packs.as_slice()
    }

    /// Split into the underlying compiled plan plus the packs needed to evaluate it.
    pub fn into_parts(self) -> (CompiledTrustPlan, Vec<Arc<dyn CoseSign1TrustPack>>) {
        (self.plan, self.trust_packs)
    }

    /// Rehydrate a bundle from a plan and packs, validating that required fact types are provided.
    pub fn from_parts(
        plan: CompiledTrustPlan,
        trust_packs: Vec<Arc<dyn CoseSign1TrustPack>>,
    ) -> Result<Self, TrustPlanCompileError> {
        validate_plan_requires_only_available_fact_types(&plan, &trust_packs)?;
        Ok(Self { plan, trust_packs })
    }
}

/// Errors produced when compiling a plan against a specific set of trust packs.
#[derive(Debug, thiserror::Error)]
pub enum TrustPlanCompileError {
    #[error("trust plan requires fact types not provided by configured trust packs: {missing}")]
    MissingRequiredTrustPacks { missing: String },
}

/// Ensure all fact types required by `plan` can be produced by message facts or configured packs.
fn validate_plan_requires_only_available_fact_types(
    plan: &CompiledTrustPlan,
    trust_packs: &[Arc<dyn CoseSign1TrustPack>],
) -> Result<(), TrustPlanCompileError> {
    let mut provided_type_ids = HashSet::new();

    // Message facts are always available at runtime.
    for k in crate::message_fact_producer::CoseSign1MessageFactProducer::new().provides() {
        provided_type_ids.insert(k.type_id);
    }

    for pack in trust_packs {
        let producer: Arc<dyn TrustFactProducer> = pack.fact_producer();
        for k in producer.provides() {
            provided_type_ids.insert(k.type_id);
        }
    }

    let mut missing: Vec<&'static str> = Vec::new();
    for FactKey { type_id, name } in plan.required_facts() {
        if !provided_type_ids.contains(type_id) {
            missing.push(*name);
        }
    }

    if missing.is_empty() {
        return Ok(());
    }

    missing.sort();
    missing.dedup();
    Err(TrustPlanCompileError::MissingRequiredTrustPacks {
        missing: missing.join(", "),
    })
}

/// Convenience re-export for callers.
pub use cose_sign1_validation_trust::rules::OnEmptyBehavior;
