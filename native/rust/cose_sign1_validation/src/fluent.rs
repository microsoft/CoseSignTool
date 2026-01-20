// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fluent-first API surface.
//!
//! This module is the intended "customer" entrypoint for policy authoring and validation.
//! It re-exports the handful of types needed to:
//! - build a trust policy (`TrustPlanBuilder`)
//! - compile/bundle it (`CoseSign1CompiledTrustPlan`)
//! - run validation (`CoseSign1Validator`)
//!
//! Pack-specific fluent extensions live in their respective crates, for example:
//! - `cose_sign1_validation_transparent_mst::fluent_ext::*`
//! - `cose_sign1_validation_certificates::fluent_ext::*`
//! - `cose_sign1_validation_azure_key_vault::fluent_ext::*`

use std::sync::Arc;

// Core validation entrypoints
pub use crate::validator::{
    CoseSign1ValidationError, CoseSign1ValidationOptions, CoseSign1ValidationResult,
    CoseSign1Validator, CounterSignature, CounterSignatureResolutionResult,
    CounterSignatureResolver, DetachedPayload, DetachedPayloadFnProvider, DetachedPayloadProvider,
    PostSignatureValidationContext, PostSignatureValidator, SigningKey, SigningKeyResolutionResult,
    SigningKeyResolver, ValidationFailure, ValidationResult, ValidationResultKind,
};

// Message representation
pub use crate::cose::{CoseDecodeError, CoseSign1};

// Message fact producer (useful for tests and custom pack authors)
pub use crate::message_fact_producer::CoseSign1MessageFactProducer;

// Trust-pack plumbing
pub use crate::trust_packs::CoseSign1TrustPack;

// Trust-plan authoring (CoseSign1 wrapper)
pub use crate::trust_plan_builder::{
    CoseSign1CompiledTrustPlan, OnEmptyBehavior, TrustPlanBuilder, TrustPlanCompileError,
};

// Trust DSL building blocks (needed for extension traits and advanced policies)
pub use cose_sign1_validation_trust::fluent::{
    MessageScope, PrimarySigningKeyScope, ScopeRules, SubjectsFromFactsScope, Where,
};

// Built-in message-scope fluent extensions
pub use crate::message_facts::fluent_ext::*;

// Common fact types used for scoping and advanced inspection.
pub use crate::message_facts::{
    CborValueReader, ContentTypeFact, CoseSign1MessageBytesFact, CoseSign1MessagePartsFact,
    CounterSignatureEnvelopeIntegrityFact, CounterSignatureSigningKeySubjectFact,
    CounterSignatureSubjectFact, CwtClaimsFact, CwtClaimsPresentFact, DetachedPayloadPresentFact,
    PrimarySigningKeySubjectFact, UnknownCounterSignatureBytesFact,
    CwtClaimScalar,
};

/// Build a [`CoseSign1Validator`] from trust packs and a fluent policy closure.
///
/// This is the most compact "customer path": you provide the packs and express policy in the
/// closure; we compile and bundle the plan and return a ready-to-use validator.
pub fn build_validator_with_policy(
    trust_packs: Vec<Arc<dyn CoseSign1TrustPack>>,
    policy: impl FnOnce(TrustPlanBuilder) -> TrustPlanBuilder,
) -> Result<CoseSign1Validator, TrustPlanCompileError> {
    let plan = policy(TrustPlanBuilder::new(trust_packs)).compile()?;
    Ok(CoseSign1Validator::new(plan))
}
