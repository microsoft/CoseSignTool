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
    pub use cose_sign1_primitives::{CoseSign1Error, CoseSign1Message};
}

pub use crate::message_fact_producer::CoseSign1MessageFactProducer;

pub use crate::message_facts::{
    ContentTypeFact, CoseSign1MessageBytesFact, CoseSign1MessagePartsFact,
    CounterSignatureEnvelopeIntegrityFact, CounterSignatureSigningKeySubjectFact,
    CounterSignatureSubjectFact, CwtClaimScalar, CwtClaimsFact, CwtClaimsPresentFact,
    DetachedPayloadPresentFact, PrimarySigningKeySubjectFact, UnknownCounterSignatureBytesFact,
};
pub use cbor_primitives::RawCbor;

pub use crate::trust_plan_builder::{
    CoseSign1CompiledTrustPlan, OnEmptyBehavior, TrustPlanBuilder, TrustPlanCompileError,
};

pub use crate::trust_packs::CoseSign1TrustPack;

pub use crate::validator::{
    CoseSign1MessageValidator, CoseSign1ValidationError, CoseSign1ValidationOptions,
    CoseSign1ValidationResult, CoseSign1Validator, CoseSign1ValidatorInit, CounterSignature,
    CounterSignatureResolutionResult, CounterSignatureResolver,
    PostSignatureValidationContext,
    PostSignatureValidator, CoseKeyResolutionResult, CoseKeyResolver,
    ValidationFailure, ValidationResult, ValidationResultKind,
};

// CoseKey is exported from primitives
pub use crypto_primitives::{CryptoError, CryptoVerifier};
