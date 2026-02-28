// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Validation support for Azure Trusted Signing.

use std::sync::Arc;

use cose_sign1_validation::fluent::CoseSign1TrustPack;
use cose_sign1_validation_primitives::{
    plan::CompiledTrustPlan, 
    facts::{TrustFactProducer, TrustFactContext, FactKey}, 
    error::TrustError,
};

use crate::validation::facts::{AtsSigningServiceIdentifiedFact, AtsComplianceFact};

pub mod facts;

/// Produces ATS-specific facts.
pub struct AtsFactProducer;

impl TrustFactProducer for AtsFactProducer {
    fn name(&self) -> &'static str {
        "azure_trusted_signing"
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        // TODO: Detect ATS-issued certificates by examining the x5chain issuer CN
        // and EKU OIDs (specific to Microsoft Trusted Signing).
        // For now, produce a default "not identified" fact.
        ctx.observe(AtsSigningServiceIdentifiedFact {
            is_ats_issued: false,
            issuer_cn: None,
            eku_oids: Vec::new(),
        })?;
        
        ctx.observe(AtsComplianceFact {
            fips_level: "unknown".to_string(),
            scitt_compliant: false,
        })?;
        
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        &[]  // TODO: Register fact keys for AtsSigningServiceIdentifiedFact and AtsComplianceFact
    }
}

/// Trust pack for Azure Trusted Signing.
///
/// Produces ATS-specific trust facts (whether the signing cert was issued by ATS,
/// compliance markers).
pub struct AzureTrustedSigningTrustPack {
    fact_producer: Arc<AtsFactProducer>,
}

impl AzureTrustedSigningTrustPack {
    pub fn new() -> Self {
        Self {
            fact_producer: Arc::new(AtsFactProducer),
        }
    }
}

impl CoseSign1TrustPack for AzureTrustedSigningTrustPack {
    fn name(&self) -> &'static str {
        "azure_trusted_signing"
    }

    fn fact_producer(&self) -> Arc<dyn TrustFactProducer> {
        self.fact_producer.clone()
    }

    fn cose_key_resolvers(&self) -> Vec<Arc<dyn cose_sign1_validation::fluent::CoseKeyResolver>> {
        // ATS uses X.509 certificates — delegate to certificates pack for key resolution
        Vec::new()
    }

    fn post_signature_validators(
        &self,
    ) -> Vec<Arc<dyn cose_sign1_validation::fluent::PostSignatureValidator>> {
        Vec::new()
    }

    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        None // Users compose their own plan using ATS + certificates pack
    }
}