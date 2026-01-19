// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test-only utilities for composing validation scenarios.
//!
//! This crate exists to keep the production `cose_sign1_validation` surface focused while still
//! supporting concise test composition in this repo.

use cose_sign1_validation::fluent::{
    CoseSign1TrustPack, PostSignatureValidator, SigningKeyResolver,
};
use cose_sign1_validation_trust::facts::{FactKey, TrustFactContext, TrustFactProducer};
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use std::sync::Arc;

static NO_FACT_KEYS: &[FactKey] = &[];

#[derive(Default)]
pub struct NoopTrustFactProducer;

impl TrustFactProducer for NoopTrustFactProducer {
    /// Stable producer name used for diagnostics.
    fn name(&self) -> &'static str {
        "noop"
    }

    /// Produce no facts.
    fn produce(
        &self,
        _ctx: &mut TrustFactContext<'_>,
    ) -> Result<(), cose_sign1_validation_trust::error::TrustError> {
        Ok(())
    }

    /// Returns an empty list of provided fact keys.
    fn provides(&self) -> &'static [FactKey] {
        NO_FACT_KEYS
    }
}

/// A convenience trust pack for composing producers/resolvers/validators without defining a new type.
#[derive(Clone)]
pub struct SimpleTrustPack {
    name: &'static str,
    fact_producer: Arc<dyn TrustFactProducer>,
    signing_key_resolvers: Vec<Arc<dyn SigningKeyResolver>>,
    post_signature_validators: Vec<Arc<dyn PostSignatureValidator>>,
    default_trust_plan: Option<CompiledTrustPlan>,
}

impl SimpleTrustPack {
    /// Create a pack with no fact production and no contributed resolvers/validators.
    pub fn no_facts(name: &'static str) -> Self {
        Self {
            name,
            fact_producer: Arc::new(NoopTrustFactProducer),
            signing_key_resolvers: Vec::new(),
            post_signature_validators: Vec::new(),
            default_trust_plan: None,
        }
    }

    /// Replace the pack's fact producer.
    pub fn with_fact_producer(mut self, producer: Arc<dyn TrustFactProducer>) -> Self {
        self.fact_producer = producer;
        self
    }

    /// Add a signing-key resolver contributed by this pack.
    pub fn with_signing_key_resolver(mut self, resolver: Arc<dyn SigningKeyResolver>) -> Self {
        self.signing_key_resolvers.push(resolver);
        self
    }

    /// Add a post-signature validator contributed by this pack.
    pub fn with_post_signature_validator(
        mut self,
        validator: Arc<dyn PostSignatureValidator>,
    ) -> Self {
        self.post_signature_validators.push(validator);
        self
    }

    /// Set the pack's default trust plan.
    pub fn with_default_trust_plan(mut self, plan: CompiledTrustPlan) -> Self {
        self.default_trust_plan = Some(plan);
        self
    }
}

impl CoseSign1TrustPack for SimpleTrustPack {
    /// Pack name used for diagnostics.
    fn name(&self) -> &'static str {
        self.name
    }

    /// Pack-provided fact producer.
    fn fact_producer(&self) -> Arc<dyn TrustFactProducer> {
        self.fact_producer.clone()
    }

    /// Pack-provided signing-key resolvers.
    fn signing_key_resolvers(&self) -> Vec<Arc<dyn SigningKeyResolver>> {
        self.signing_key_resolvers.clone()
    }

    /// Pack-provided post-signature validators.
    fn post_signature_validators(&self) -> Vec<Arc<dyn PostSignatureValidator>> {
        self.post_signature_validators.clone()
    }

    /// Pack's secure-by-default trust plan.
    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        self.default_trust_plan.clone()
    }
}
