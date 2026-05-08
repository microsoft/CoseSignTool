// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public spec-walking helpers used internally by the conformance harness
//! and exposed for downstream consumers that need the same checks.
//!
//! These helpers are intentionally minimal — they do NOT replace the IR
//! analysis in [`cose_sign1_trust_policy_spec`]; they are the small subset
//! the conformance harness needs (referenced fact ids, parameter literal
//! detection) and that downstream test crates often reach for as well.

use cose_sign1_trust_policy_spec::{FactPredicateSpec, ParameterRef, TrustPolicySpec};
use serde_json::Value;
use std::collections::BTreeSet;

/// Collect every distinct `fact_id` referenced by `RequireFact` nodes in
/// `spec`. Useful for asserting that a translation produced the expected
/// fact references.
pub fn collect_fact_ids(spec: &TrustPolicySpec) -> BTreeSet<&str> {
    let mut ids = BTreeSet::new();
    walk_collect(spec, &mut ids);
    ids
}

/// Returns `true` iff `spec` contains any `$param` literal anywhere in its
/// tree (including nested predicates and array values). Used by §6.5.10 #6 to
/// distinguish pre-bind specs from post-bind specs.
pub fn contains_param_literal(spec: &TrustPolicySpec) -> bool {
    match spec {
        TrustPolicySpec::AllowAll | TrustPolicySpec::DenyAll { .. } => false,
        TrustPolicySpec::And { specs } | TrustPolicySpec::Or { specs } => {
            specs.iter().any(contains_param_literal)
        }
        TrustPolicySpec::Not { spec, .. } => contains_param_literal(spec),
        TrustPolicySpec::Implies {
            antecedent,
            consequent,
        } => contains_param_literal(antecedent) || contains_param_literal(consequent),
        TrustPolicySpec::Message { requirements }
        | TrustPolicySpec::PrimarySigningKey { requirements }
        | TrustPolicySpec::AnyCounterSignature { requirements, .. } => {
            requirements.iter().any(contains_param_literal)
        }
        TrustPolicySpec::RequireFact { predicate, .. } => predicate_has_param(predicate),
        // Forward-compat: future variants are conservatively reported as
        // "no params present" so this helper never panics on a non-exhaustive
        // enum. Production-correct since a brand-new variant carrying $param
        // literals would by construction trip its own analysis pass.
        _ => false,
    }
}

fn walk_collect<'a>(spec: &'a TrustPolicySpec, ids: &mut BTreeSet<&'a str>) {
    match spec {
        TrustPolicySpec::AllowAll | TrustPolicySpec::DenyAll { .. } => {}
        TrustPolicySpec::And { specs } | TrustPolicySpec::Or { specs } => {
            for s in specs {
                walk_collect(s, ids);
            }
        }
        TrustPolicySpec::Not { spec, .. } => walk_collect(spec, ids),
        TrustPolicySpec::Implies {
            antecedent,
            consequent,
        } => {
            walk_collect(antecedent, ids);
            walk_collect(consequent, ids);
        }
        TrustPolicySpec::Message { requirements }
        | TrustPolicySpec::PrimarySigningKey { requirements }
        | TrustPolicySpec::AnyCounterSignature { requirements, .. } => {
            for s in requirements {
                walk_collect(s, ids);
            }
        }
        TrustPolicySpec::RequireFact { fact_id, .. } => {
            ids.insert(fact_id.as_str());
        }
        // Forward-compat: a brand-new TrustPolicySpec variant lands as a
        // silent gap rather than a panic. The conformance suite's #2
        // (attribute fidelity) property already enforces "every fact id
        // round-trips" — adding a new variant carrying RequireFact-children
        // would surface there before any harness consumer relied on this
        // helper.
        _ => {}
    }
}

fn predicate_has_param(predicate: &FactPredicateSpec) -> bool {
    match predicate {
        FactPredicateSpec::Property(p) => p.assertions.values().any(value_has_param),
        FactPredicateSpec::PathOperator(po) => po.value.as_ref().is_some_and(value_has_param),
        // Forward-compat (mirrors `contains_param_literal`).
        _ => false,
    }
}

fn value_has_param(value: &Value) -> bool {
    match value {
        Value::Object(_) => ParameterRef::try_recognize(value)
            .map(|opt| opt.is_some())
            .unwrap_or(false),
        Value::Array(items) => items.iter().any(value_has_param),
        _ => false,
    }
}
