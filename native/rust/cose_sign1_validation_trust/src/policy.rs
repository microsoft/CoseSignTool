// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::facts::FactKey;
use crate::plan::CompiledTrustPlan;
use crate::rules::TrustRuleRef;

#[derive(Default, Clone)]
pub struct TrustPolicy {
    pub required_facts: Vec<FactKey>,
    pub constraints: Vec<TrustRuleRef>,
    pub trust_sources: Vec<TrustRuleRef>,
    pub vetoes: Vec<TrustRuleRef>,
}

impl TrustPolicy {
    /// Compile this policy into a [`CompiledTrustPlan`].
    ///
    /// Compilation freezes the current required facts and rules into the representation used by
    /// the evaluation engine.
    pub fn compile(&self) -> CompiledTrustPlan {
        CompiledTrustPlan::new(
            self.required_facts.clone(),
            self.constraints.clone(),
            self.trust_sources.clone(),
            self.vetoes.clone(),
        )
    }
}

#[derive(Default)]
pub struct TrustPolicyBuilder {
    policy: TrustPolicy,
}

impl TrustPolicyBuilder {
    /// Create a new empty policy builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Require that a fact key is produced during evaluation.
    ///
    /// This ensures the fact exists in the engine (even if its value is missing/error), which is
    /// useful for downstream rules and for auditability.
    pub fn require_fact(mut self, fact: FactKey) -> Self {
        if !self.policy.required_facts.contains(&fact) {
            self.policy.required_facts.push(fact);
        }
        self
    }

    /// Add a constraint rule.
    ///
    /// Constraints must be satisfied for the overall decision to be trusted.
    pub fn add_constraint(mut self, rule: TrustRuleRef) -> Self {
        self.policy.constraints.push(rule);
        self
    }

    /// Add a trust-source rule.
    ///
    /// Trust sources are combined according to the compiled plan semantics to determine whether
    /// the subject is trusted.
    pub fn add_trust_source(mut self, rule: TrustRuleRef) -> Self {
        self.policy.trust_sources.push(rule);
        self
    }

    /// Add a veto rule.
    ///
    /// Vetoes can deny trust even if trust sources would otherwise allow it.
    pub fn add_veto(mut self, rule: TrustRuleRef) -> Self {
        self.policy.vetoes.push(rule);
        self
    }

    /// Finish building and return the immutable [`TrustPolicy`].
    pub fn build(self) -> TrustPolicy {
        self.policy
    }
}
