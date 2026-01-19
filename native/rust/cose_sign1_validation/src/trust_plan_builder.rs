// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::message_facts::{
    CounterSignatureSigningKeySubjectFact, CounterSignatureSubjectFact, PrimarySigningKeySubjectFact,
};
use crate::trust_packs::CoseSign1TrustPack;
use cose_sign1_validation_trust::fluent as trust_fluent;
use cose_sign1_validation_trust::facts::{FactKey, TrustFactProducer};
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use std::collections::HashSet;
use std::sync::Arc;

impl trust_fluent::HasTrustSubject for CounterSignatureSubjectFact {
    fn trust_subject(&self) -> &cose_sign1_validation_trust::subject::TrustSubject {
        &self.subject
    }
}

impl trust_fluent::HasTrustSubject for CounterSignatureSigningKeySubjectFact {
    fn trust_subject(&self) -> &cose_sign1_validation_trust::subject::TrustSubject {
        &self.subject
    }
}

impl trust_fluent::HasTrustSubject for PrimarySigningKeySubjectFact {
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
#[derive(Clone)]
pub struct TrustPlanBuilder {
    inner: trust_fluent::TrustPlanBuilder,
    trust_packs: Vec<Arc<dyn CoseSign1TrustPack>>,
}

impl TrustPlanBuilder {
    pub fn new(trust_packs: Vec<Arc<dyn CoseSign1TrustPack>>) -> Self {
        Self {
            inner: trust_fluent::TrustPlanBuilder::new(),
            trust_packs,
        }
    }

    pub fn and(mut self) -> Self {
        self.inner = self.inner.and();
        self
    }

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

    pub fn for_message(
        mut self,
        f: impl FnOnce(trust_fluent::ScopeRules<trust_fluent::MessageScope>)
            -> trust_fluent::ScopeRules<trust_fluent::MessageScope>,
    ) -> Self {
        self.inner = self.inner.for_message(f);
        self
    }

    pub fn for_primary_signing_key(
        mut self,
        f: impl FnOnce(trust_fluent::ScopeRules<trust_fluent::PrimarySigningKeyScope>)
            -> trust_fluent::ScopeRules<trust_fluent::PrimarySigningKeyScope>,
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
            trust_fluent::ScopeRules<trust_fluent::SubjectsFromFactsScope<CounterSignatureSubjectFact>>,
        ) -> trust_fluent::ScopeRules<trust_fluent::SubjectsFromFactsScope<CounterSignatureSubjectFact>>,
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

    /// Compile the plan.
    ///
    /// This validates that the configured trust packs can satisfy all required fact types.
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
    pub fn plan(&self) -> &CompiledTrustPlan {
        &self.plan
    }

    pub fn trust_packs(&self) -> &[Arc<dyn CoseSign1TrustPack>] {
        self.trust_packs.as_slice()
    }

    pub fn into_parts(self) -> (CompiledTrustPlan, Vec<Arc<dyn CoseSign1TrustPack>>) {
        (self.plan, self.trust_packs)
    }

    pub(crate) fn from_parts(
        plan: CompiledTrustPlan,
        trust_packs: Vec<Arc<dyn CoseSign1TrustPack>>,
    ) -> Result<Self, TrustPlanCompileError> {
        validate_plan_requires_only_available_fact_types(&plan, &trust_packs)?;
        Ok(Self { plan, trust_packs })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TrustPlanCompileError {
    #[error("trust plan requires fact types not provided by configured trust packs: {missing}")]
    MissingRequiredTrustPacks { missing: String },
}

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
