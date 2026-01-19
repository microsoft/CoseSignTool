// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::{PostSignatureValidator, SigningKeyResolver};
use cose_sign1_validation_trust::facts::TrustFactProducer;
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use std::sync::Arc;

static NO_FACT_KEYS: &[cose_sign1_validation_trust::facts::FactKey] = &[];

#[derive(Default)]
pub struct NoopTrustFactProducer;

impl TrustFactProducer for NoopTrustFactProducer {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn produce(
        &self,
        _ctx: &mut cose_sign1_validation_trust::facts::TrustFactContext<'_>,
    ) -> Result<(), cose_sign1_validation_trust::error::TrustError> {
        Ok(())
    }

    fn provides(&self) -> &'static [cose_sign1_validation_trust::facts::FactKey] {
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
    pub fn no_facts(name: &'static str) -> Self {
        Self {
            name,
            fact_producer: Arc::new(NoopTrustFactProducer),
            signing_key_resolvers: Vec::new(),
            post_signature_validators: Vec::new(),
            default_trust_plan: None,
        }
    }

    pub fn with_fact_producer(mut self, producer: Arc<dyn TrustFactProducer>) -> Self {
        self.fact_producer = producer;
        self
    }

    pub fn with_signing_key_resolver(mut self, resolver: Arc<dyn SigningKeyResolver>) -> Self {
        self.signing_key_resolvers.push(resolver);
        self
    }

    pub fn with_post_signature_validator(
        mut self,
        validator: Arc<dyn PostSignatureValidator>,
    ) -> Self {
        self.post_signature_validators.push(validator);
        self
    }

    pub fn with_default_trust_plan(mut self, plan: CompiledTrustPlan) -> Self {
        self.default_trust_plan = Some(plan);
        self
    }
}

/// A bundle that makes validation "secure-by-default":
/// - provides facts
/// - provides the signing-key resolver(s) needed for signature verification
/// - provides a default trust plan used when the caller does not specify a policy
pub trait CoseSign1TrustPack: Send + Sync {
    fn name(&self) -> &'static str;

    fn fact_producer(&self) -> Arc<dyn TrustFactProducer>;

    fn signing_key_resolvers(&self) -> Vec<Arc<dyn SigningKeyResolver>> {
        Vec::new()
    }

    fn post_signature_validators(&self) -> Vec<Arc<dyn PostSignatureValidator>> {
        Vec::new()
    }

    /// Returns the pack's secure-by-default trust plan.
    ///
    /// When the caller does not provide an explicit plan, the validator OR-composes all pack plans.
    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        None
    }
}

impl CoseSign1TrustPack for SimpleTrustPack {
    fn name(&self) -> &'static str {
        self.name
    }

    fn fact_producer(&self) -> Arc<dyn TrustFactProducer> {
        self.fact_producer.clone()
    }

    fn signing_key_resolvers(&self) -> Vec<Arc<dyn SigningKeyResolver>> {
        self.signing_key_resolvers.clone()
    }

    fn post_signature_validators(&self) -> Vec<Arc<dyn PostSignatureValidator>> {
        self.post_signature_validators.clone()
    }

    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        self.default_trust_plan.clone()
    }
}
