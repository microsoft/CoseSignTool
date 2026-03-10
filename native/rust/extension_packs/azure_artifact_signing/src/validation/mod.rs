// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Validation support for Azure Artifact Signing.

use std::sync::Arc;

use cose_sign1_validation::fluent::CoseSign1TrustPack;
use cose_sign1_validation_primitives::{
    plan::CompiledTrustPlan, 
    facts::{TrustFactProducer, TrustFactContext, FactKey}, 
    error::TrustError,
};

use crate::validation::facts::{AasSigningServiceIdentifiedFact, AasComplianceFact};

pub mod facts;

/// Produces AAS-specific facts.
pub struct AasFactProducer;

impl TrustFactProducer for AasFactProducer {
    fn name(&self) -> &'static str {
        "azure_artifact_signing"
    }

    // produce() requires a TrustFactContext that cannot be constructed outside
    // the TrustFactEngine. The engine dispatches to produce() internally, and the
    // AasFactProducer::provides() returns &[] so the engine never routes to it.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        // TODO: Detect AAS-issued certificates by examining the x5chain issuer CN
        // and EKU OIDs (specific to Microsoft Artifact Signing).
        // For now, produce a default "not identified" fact.
        ctx.observe(AasSigningServiceIdentifiedFact {
            is_ats_issued: false,
            issuer_cn: None,
            eku_oids: Vec::new(),
        })?;
        
        ctx.observe(AasComplianceFact {
            fips_level: "unknown".to_string(),
            scitt_compliant: false,
        })?;
        
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        &[]  // TODO: Register fact keys for AasSigningServiceIdentifiedFact and AasComplianceFact
    }
}

/// Trust pack for Azure Artifact Signing.
///
/// Produces AAS-specific trust facts (whether the signing cert was issued by AAS,
/// compliance markers).
pub struct AzureArtifactSigningTrustPack {
    fact_producer: Arc<AasFactProducer>,
}

impl AzureArtifactSigningTrustPack {
    pub fn new() -> Self {
        Self {
            fact_producer: Arc::new(AasFactProducer),
        }
    }
}

impl CoseSign1TrustPack for AzureArtifactSigningTrustPack {
    fn name(&self) -> &'static str {
        "azure_artifact_signing"
    }

    fn fact_producer(&self) -> Arc<dyn TrustFactProducer> {
        self.fact_producer.clone()
    }

    fn cose_key_resolvers(&self) -> Vec<Arc<dyn cose_sign1_validation::fluent::CoseKeyResolver>> {
        // AAS uses X.509 certificates — delegate to certificates pack for key resolution
        Vec::new()
    }

    fn post_signature_validators(
        &self,
    ) -> Vec<Arc<dyn cose_sign1_validation::fluent::PostSignatureValidator>> {
        Vec::new()
    }

    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        None // Users compose their own plan using AAS + certificates pack
    }
}