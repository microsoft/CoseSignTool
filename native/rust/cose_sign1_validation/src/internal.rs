// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Legacy/advanced API surface.
//!
//! This module is intentionally hidden from generated docs.
//!
//! Most consumers should use `cose_sign1_validation::fluent`.

// Keep the internal module paths available under `internal::*` for:
// - tests
// - deep debugging
// - advanced integrations

pub mod cose {
    pub use crate::cose::*;
}

pub use crate::cose::CoseSign1;

pub use crate::message_fact_producer::CoseSign1MessageFactProducer;

pub use crate::message_facts::{
    CborValueReader, ContentTypeFact, CoseSign1MessageBytesFact, CoseSign1MessagePartsFact,
    CounterSignatureEnvelopeIntegrityFact, CounterSignatureSigningKeySubjectFact,
    CounterSignatureSubjectFact, CwtClaimScalar, CwtClaimsFact, CwtClaimsPresentFact,
    DetachedPayloadPresentFact, PrimarySigningKeySubjectFact, UnknownCounterSignatureBytesFact,
};

pub use crate::trust_plan_builder::{
    CoseSign1CompiledTrustPlan, OnEmptyBehavior, TrustPlanBuilder, TrustPlanCompileError,
};

pub use crate::trust_packs::CoseSign1TrustPack;

pub use crate::validator::{
    CoseSign1MessageValidator, CoseSign1ValidationError, CoseSign1ValidationOptions,
    CoseSign1ValidationResult, CoseSign1Validator, CoseSign1ValidatorInit, CounterSignature,
    CounterSignatureResolutionResult, CounterSignatureResolver, DetachedPayload,
    DetachedPayloadFnProvider, DetachedPayloadProvider, PostSignatureValidationContext,
    PostSignatureValidator, SigningKey, SigningKeyResolutionResult, SigningKeyResolver,
    ValidationFailure, ValidationResult, ValidationResultKind,
};
