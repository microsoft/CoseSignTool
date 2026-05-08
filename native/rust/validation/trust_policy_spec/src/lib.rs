// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![deny(missing_docs)]

//! `cose_sign1_trust_policy_spec` — Phase 1 of the native Rust trust-policy port.
//!
//! This crate ships the **canonical, serializable IR** ([`TrustPolicySpec`]) used by every
//! frontend (Phase 2 JSON, Phase 5a Rego) and the lowering pipeline that produces a
//! `cose_sign1_validation_primitives::plan::CompiledTrustPlan`. Mirrors the .NET
//! `tp-spec` deliverable and obeys the D1–D11 + R1–R7 decisions captured in
//! `eval-trust-policy-translation-contract-rust.md`.
//!
//! # Quickstart
//!
//! ```
//! use cose_sign1_trust_policy_spec::{
//!     compile, FactPredicateSpec, IFactRegistry, PredicateOperator, StaticFactRegistry,
//!     TrustPolicySpec,
//! };
//!
//! let spec = TrustPolicySpec::and([
//!     TrustPolicySpec::message([TrustPolicySpec::AllowAll]),
//!     TrustPolicySpec::require_fact(
//!         "x509-chain-trusted/v1",
//!         FactPredicateSpec::path_operator(
//!             "is_trusted",
//!             PredicateOperator::Equals,
//!             Some(serde_json::Value::Bool(true)),
//!         ),
//!         "X.509 chain failed to validate",
//!     ),
//! ]);
//!
//! // Round-trips deterministically:
//! let json = cose_sign1_trust_policy_spec::to_canonical_json(&spec).unwrap();
//! let parsed: TrustPolicySpec = serde_json::from_str(&json).unwrap();
//! assert_eq!(spec, parsed);
//!
//! // Lowers against a fact registry to a CompiledTrustPlan:
//! let registry = StaticFactRegistry::default_mappings();
//! let _plan = compile(&spec, &registry).expect("structural compile");
//! ```
//!
//! # Phase boundary
//!
//! Phase 1 lowers the structural variants ([`AllowAll`](TrustPolicySpec::AllowAll),
//! [`DenyAll`](TrustPolicySpec::DenyAll), [`And`](TrustPolicySpec::And),
//! [`Or`](TrustPolicySpec::Or), [`Not`](TrustPolicySpec::Not),
//! [`Implies`](TrustPolicySpec::Implies), [`Message`](TrustPolicySpec::Message),
//! [`PrimarySigningKey`](TrustPolicySpec::PrimarySigningKey)) end-to-end. The
//! fact-dependent variants ([`RequireFact`](TrustPolicySpec::RequireFact),
//! [`AnyCounterSignature`](TrustPolicySpec::AnyCounterSignature)) lower to deterministic
//! placeholders whose semantics are strictly more conservative than the eventual Phase 3
//! lowering — see [`compile`] module docs for the contract.

pub mod canonical_json;
pub mod compile;
pub mod diagnostic_codes;
pub mod parameter;
pub mod predicate;
pub mod registry;
pub mod source_location;
pub mod spec;

pub use canonical_json::{to_canonical_json, to_canonical_pretty};
pub use compile::{
    compile, compile_with_options, from_rule_on_empty, into_rule_on_empty, CompileError,
    CompileOptions, DEFAULT_MAX_DEPTH,
};
pub use parameter::{bind, BindError, ParameterRef, PARAM_KEY};
pub use predicate::{
    FactPredicateSpec, PathOperatorPredicateSpec, PredicateOperator, PropertyAssertionPredicateSpec,
};
pub use registry::{IFactRegistry, StaticFactRegistry};
pub use source_location::SourceLocation;
pub use spec::{OnEmptyBehavior, TrustPolicySpec};
