// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod cose;

pub mod message_fact_producer;
pub mod message_facts;
pub mod trust_plan_builder;
pub mod trust_packs;
pub mod validator;

pub use cose::CoseSign1;
pub use message_fact_producer::CoseSign1MessageFactProducer;
pub use message_facts::{
    CborValueReader, ContentTypeFact, CoseSign1MessageBytesFact, CoseSign1MessagePartsFact,
    CounterSignatureEnvelopeIntegrityFact, CounterSignatureSigningKeySubjectFact,
    CounterSignatureSubjectFact, CwtClaimScalar, CwtClaimsFact, CwtClaimsPresentFact,
    DetachedPayloadPresentFact, PrimarySigningKeySubjectFact, UnknownCounterSignatureBytesFact,
};
pub use trust_plan_builder::{
    CoseSign1CompiledTrustPlan, OnEmptyBehavior, TrustPlanBuilder, TrustPlanCompileError,
};
pub use trust_packs::CoseSign1TrustPack;
pub use trust_packs::{NoopTrustFactProducer, SimpleTrustPack};
pub use validator::{
    CoseSign1MessageValidator, CoseSign1ValidationError, CoseSign1ValidationOptions,
    CoseSign1ValidationResult, CoseSign1Validator, CoseSign1ValidatorInit, CounterSignature,
    CounterSignatureResolutionResult, CounterSignatureResolver, DetachedPayload,
    DetachedPayloadFnProvider, DetachedPayloadProvider, PostSignatureValidationContext,
    PostSignatureValidator, SigningKey, SigningKeyResolutionResult, SigningKeyResolver,
    ValidationFailure, ValidationResult, ValidationResultKind,
};
