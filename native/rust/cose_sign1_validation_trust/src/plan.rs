// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::audit::TrustDecisionAudit;
use crate::decision::TrustDecision;
use crate::error::TrustError;
use crate::evaluation_options::TrustEvaluationOptions;
use crate::facts::{FactKey, TrustFactEngine};
use crate::rules::{all_of, any_of, not, TrustRuleRef};
use crate::subject::TrustSubject;
use std::collections::HashSet;

/// A pre-validated trust plan.
///
/// A compiled plan is a rule graph plus an explicit list of required fact types.
/// Evaluation semantics are:
/// - Ensure all required facts are produced (or reported missing)
/// - If `bypass_trust` is enabled, return trusted with a diagnostic reason
/// - Otherwise: `constraints AND (OR trust_sources) AND NOT(OR vetoes)`
///
/// Important default: if `trust_sources` is empty, the plan denies by default.
#[derive(Clone)]
pub struct CompiledTrustPlan {
    required_facts: Vec<FactKey>,
    constraints: Vec<TrustRuleRef>,
    trust_sources: Vec<TrustRuleRef>,
    vetoes: Vec<TrustRuleRef>,
}

impl CompiledTrustPlan {
    /// Fact types that must be available for evaluation.
    pub fn required_facts(&self) -> &[FactKey] {
        self.required_facts.as_slice()
    }

    /// Creates a new plan from its component rule sets.
    pub fn new(
        required_facts: Vec<FactKey>,
        constraints: Vec<TrustRuleRef>,
        trust_sources: Vec<TrustRuleRef>,
        vetoes: Vec<TrustRuleRef>,
    ) -> Self {
        Self {
            required_facts,
            constraints,
            trust_sources,
            vetoes,
        }
    }

    /// Evaluate the plan for a given subject.
    pub fn evaluate(
        &self,
        engine: &TrustFactEngine,
        subject: &TrustSubject,
        options: &TrustEvaluationOptions,
    ) -> Result<TrustDecision, TrustError> {
        for key in &self.required_facts {
            engine.ensure_fact(subject, *key)?;
        }

        if options.bypass_trust {
            return Ok(TrustDecision::trusted_reason("BypassTrust"));
        }

        // Mirrors .NET semantics: constraints AND (OR trust_sources) AND NOT(OR vetoes)
        // Crucial behavior: if no trust sources are configured, evaluation denies by default.
        let constraints_rule = all_of("constraints", self.constraints.clone());

        // V2 semantics: OR over trust sources. Empty OR => denied with default reason.
        let trust_sources_rule = any_of("trust_sources", self.trust_sources.clone());

        // V2 semantics: OR over vetoes. Empty OR => denied with default OR-empty reason,
        // then NOT(internal) will invert to Trusted.
        let vetoes_rule = any_of("vetoes", self.vetoes.clone());

        let final_rule = all_of(
            "compiled_plan",
            vec![
                constraints_rule,
                trust_sources_rule,
                not("not_vetoed", vetoes_rule),
            ],
        );
        final_rule.evaluate(engine, subject)
    }

    /// Convert this plan into a `TrustRuleRef` that preserves this plan's evaluation semantics.
    ///
    /// This is useful for composing plans (e.g., OR-ing multiple pack plans together) while still
    /// leveraging the existing compiled-plan rule graph semantics.
    pub fn as_rule_ref(&self) -> TrustRuleRef {
        let constraints_rule = all_of("constraints", self.constraints.clone());
        let trust_sources_rule = any_of("trust_sources", self.trust_sources.clone());
        let vetoes_rule = any_of("vetoes", self.vetoes.clone());

        all_of(
            "compiled_plan",
            vec![
                constraints_rule,
                trust_sources_rule,
                not("not_vetoed", vetoes_rule),
            ],
        )
    }

    /// OR-compose multiple plans as independent trust sources.
    ///
    /// The resulting plan has:
    /// - `trust_sources` = each input plan represented as a rule (OR-ed by compiled-plan semantics)
    /// - `required_facts` = union of all required facts across plans
    /// - no top-level constraints/vetoes (each plan carries its own inside its rule)
    pub fn or_plans(plans: Vec<CompiledTrustPlan>) -> Self {
        let mut required = HashSet::<FactKey>::new();
        let mut trust_sources = Vec::new();

        for plan in plans {
            let rule = plan.as_rule_ref();
            for k in &plan.required_facts {
                required.insert(*k);
            }
            trust_sources.push(rule);
        }

        Self::new(
            required.into_iter().collect(),
            Vec::new(),
            trust_sources,
            Vec::new(),
        )
    }

    /// Evaluate the plan while collecting an audit trail from the engine.
    pub fn evaluate_with_audit(
        &self,
        engine: &TrustFactEngine,
        subject: &TrustSubject,
        options: &TrustEvaluationOptions,
    ) -> Result<(TrustDecision, Option<TrustDecisionAudit>), TrustError> {
        engine.enable_audit();
        let decision = self.evaluate(engine, subject, options)?;
        let audit = engine.take_audit();
        Ok((decision, audit))
    }
}
