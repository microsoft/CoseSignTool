// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`TrustPolicySpec`] — the serializable, deterministic IR for trust policies.
//!
//! This is the canonical translation target for every frontend (Phase 2 JSON, Phase 5a Rego)
//! and the lowering input for [`crate::compile`]. Round-trip stability and determinism are
//! contractual: see [`crate::canonical_json`] for the canonical-JSON guarantee that backs
//! the cache-key story (D9).

use crate::predicate::FactPredicateSpec;
use serde::{Deserialize, Serialize};

/// Behavior when a scope produces zero subjects.
///
/// Mirrors `cose_sign1_validation_primitives::rules::OnEmptyBehavior` but is owned by this
/// crate so it can carry `Serialize`/`Deserialize` without forcing serde into the trust-evaluation
/// runtime. Conversion is lossless: see [`crate::compile`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnEmptyBehavior {
    /// Treat an empty subject set as success — the scope is effectively optional.
    Allow,
    /// Treat an empty subject set as failure.
    Deny,
}

impl Default for OnEmptyBehavior {
    fn default() -> Self {
        Self::Deny
    }
}

/// Discriminated union describing a trust policy.
///
/// The IR is intentionally minimal: every higher-level construct (e.g. counter-signature
/// scope, primary-signing-key scope) is expressed in terms of these primitives. Frontends
/// (JSON, Rego) translate to this shape; the lowering pipeline ([`crate::compile`]) translates
/// from this shape into a [`cose_sign1_validation_primitives::plan::CompiledTrustPlan`].
///
/// # Determinism
///
/// All collection slots use `Vec` (order-preserving) — order is semantically meaningful for
/// short-circuit evaluation in `And`/`Or`. Property-assertion maps inside [`FactPredicateSpec`]
/// use `BTreeMap` so that canonical JSON serialization is byte-stable across builds.
///
/// # Schema discipline
///
/// Every variant carries `#[serde(deny_unknown_fields)]` (via the `tag`/`rename_all`
/// configuration on the enum and the inner field shape) — frontends are required to reject
/// typos in user documents at parse time so they surface as `TPX100` rather than as silent
/// behavioral drift.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustPolicySpec {
    /// Always trust. Useful for tests; never appropriate in production policies.
    AllowAll,

    /// Always deny with `reason`.
    DenyAll {
        /// Human-readable diagnostic reason.
        reason: String,
    },

    /// AND of zero or more inner specs. Empty `specs` is vacuously `true`.
    And {
        /// Inner specs, AND-combined left-to-right.
        specs: Vec<TrustPolicySpec>,
    },

    /// OR of zero or more inner specs. Empty `specs` denies by default
    /// (mirrors the primitives `any_of` semantics).
    Or {
        /// Inner specs, OR-combined left-to-right.
        specs: Vec<TrustPolicySpec>,
    },

    /// Logical negation of `spec`. `reason` is the deny message used when `spec` is trusted.
    Not {
        /// Inner spec to negate.
        spec: Box<TrustPolicySpec>,
        /// Diagnostic reason for the negation. Defaults to a generic message when `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

    /// Material implication: `antecedent → consequent`.
    ///
    /// Equivalent to `Or(Not(antecedent), And(antecedent, consequent))`. When the antecedent
    /// fails to evaluate to trusted, the implication is vacuously satisfied.
    Implies {
        /// The "if" side of the implication.
        antecedent: Box<TrustPolicySpec>,
        /// The "then" side, evaluated when `antecedent` is trusted.
        consequent: Box<TrustPolicySpec>,
    },

    /// Scope inner requirements to the message subject.
    Message {
        /// Inner specs, AND-combined within the message scope.
        requirements: Vec<TrustPolicySpec>,
    },

    /// Scope inner requirements to the derived primary-signing-key subject.
    PrimarySigningKey {
        /// Inner specs, AND-combined within the primary-signing-key scope.
        requirements: Vec<TrustPolicySpec>,
    },

    /// Scope inner requirements over each discovered counter-signature subject. Trusted when
    /// any counter-signature satisfies the inner specs; otherwise denied. `on_empty` controls
    /// the behavior when there are no counter-signatures at all.
    AnyCounterSignature {
        /// Behavior when zero counter-signatures are present.
        #[serde(default)]
        on_empty: OnEmptyBehavior,
        /// Inner specs, AND-combined per counter-signature.
        requirements: Vec<TrustPolicySpec>,
    },

    /// Require a fact identified by `fact_id` to satisfy `predicate`.
    ///
    /// `failure_message` is surfaced verbatim to the trust-decision diagnostics if the
    /// predicate fails. `fact_id` MUST be advertised by the configured fact registry; an
    /// unknown id is rejected at compile time as `TPX200`.
    RequireFact {
        /// Stable, semver-versioned fact identifier (`^[a-z][a-z0-9-]*/v[0-9]+$`).
        fact_id: String,
        /// Predicate to evaluate against the fact.
        predicate: FactPredicateSpec,
        /// Human-readable diagnostic reason used when the predicate fails.
        failure_message: String,
    },
}

impl TrustPolicySpec {
    /// Convenience constructor for [`TrustPolicySpec::And`].
    pub fn and(specs: impl IntoIterator<Item = TrustPolicySpec>) -> Self {
        Self::And {
            specs: specs.into_iter().collect(),
        }
    }

    /// Convenience constructor for [`TrustPolicySpec::Or`].
    pub fn or(specs: impl IntoIterator<Item = TrustPolicySpec>) -> Self {
        Self::Or {
            specs: specs.into_iter().collect(),
        }
    }

    /// Convenience constructor for [`TrustPolicySpec::Not`].
    pub fn not(spec: TrustPolicySpec, reason: Option<String>) -> Self {
        Self::Not {
            spec: Box::new(spec),
            reason,
        }
    }

    /// Convenience constructor for [`TrustPolicySpec::Implies`].
    pub fn implies(antecedent: TrustPolicySpec, consequent: TrustPolicySpec) -> Self {
        Self::Implies {
            antecedent: Box::new(antecedent),
            consequent: Box::new(consequent),
        }
    }

    /// Convenience constructor for [`TrustPolicySpec::Message`].
    pub fn message(requirements: impl IntoIterator<Item = TrustPolicySpec>) -> Self {
        Self::Message {
            requirements: requirements.into_iter().collect(),
        }
    }

    /// Convenience constructor for [`TrustPolicySpec::PrimarySigningKey`].
    pub fn primary_signing_key(requirements: impl IntoIterator<Item = TrustPolicySpec>) -> Self {
        Self::PrimarySigningKey {
            requirements: requirements.into_iter().collect(),
        }
    }

    /// Convenience constructor for [`TrustPolicySpec::AnyCounterSignature`].
    pub fn any_counter_signature(
        on_empty: OnEmptyBehavior,
        requirements: impl IntoIterator<Item = TrustPolicySpec>,
    ) -> Self {
        Self::AnyCounterSignature {
            on_empty,
            requirements: requirements.into_iter().collect(),
        }
    }

    /// Convenience constructor for [`TrustPolicySpec::RequireFact`].
    pub fn require_fact(
        fact_id: impl Into<String>,
        predicate: FactPredicateSpec,
        failure_message: impl Into<String>,
    ) -> Self {
        Self::RequireFact {
            fact_id: fact_id.into(),
            predicate,
            failure_message: failure_message.into(),
        }
    }

    /// Returns the stable variant tag string emitted by serde for this spec.
    ///
    /// Mirrors the `#[serde(tag = "type", rename_all = "snake_case")]` configuration —
    /// useful for diagnostic messages that want to identify the variant without rendering
    /// the full document.
    pub fn variant_tag(&self) -> &'static str {
        match self {
            Self::AllowAll => "allow_all",
            Self::DenyAll { .. } => "deny_all",
            Self::And { .. } => "and",
            Self::Or { .. } => "or",
            Self::Not { .. } => "not",
            Self::Implies { .. } => "implies",
            Self::Message { .. } => "message",
            Self::PrimarySigningKey { .. } => "primary_signing_key",
            Self::AnyCounterSignature { .. } => "any_counter_signature",
            Self::RequireFact { .. } => "require_fact",
        }
    }
}
