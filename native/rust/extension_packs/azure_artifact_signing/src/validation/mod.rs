// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Validation support for Azure Artifact Signing.

use std::sync::Arc;

use cose_sign1_validation::fluent::CoseSign1TrustPack;
use cose_sign1_validation_primitives::{
    error::TrustError,
    facts::{FactKey, TrustFactContext, TrustFactProducer},
    plan::CompiledTrustPlan,
};

use crate::validation::facts::{AasComplianceFact, AasSigningServiceIdentifiedFact};

pub mod facts;

/// Produces AAS-specific facts.
pub struct AasFactProducer;

impl TrustFactProducer for AasFactProducer {
    fn name(&self) -> &'static str {
        "azure_artifact_signing"
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        // Detect AAS-issued certificates by examining the signing certificate's
        // issuer CN and EKU OIDs.
        //
        // AAS-issued certificates have:
        // - Issuer CN containing "Microsoft" (e.g., "Microsoft ID Verified CS EOC CA 01")
        // - EKU OID matching the Microsoft Code Signing pattern: 1.3.6.1.4.1.311.*
        let mut is_ats_issued = false;
        let mut issuer_cn: Option<String> = None;
        let mut eku_oids: Vec<String> = Vec::new();

        // Try to get signing certificate identity facts from the certificates pack
        // (these are produced by X509CertificateTrustPack if an x5chain is present).
        if let Ok(cose_sign1_validation_primitives::facts::TrustFactSet::Available(identities)) = ctx.get_fact_set::<cose_sign1_certificates::validation::facts::X509SigningCertificateIdentityFact>(ctx.subject()) {
            if let Some(identity) = identities.first() {
                issuer_cn = Some(identity.issuer.to_string());
                if identity.issuer.contains("Microsoft") {
                    is_ats_issued = true;
                }
            }
        }

        // Check EKU facts for Microsoft-specific OIDs
        if let Ok(cose_sign1_validation_primitives::facts::TrustFactSet::Available(ekus)) = ctx.get_fact_set::<cose_sign1_certificates::validation::facts::X509SigningCertificateEkuFact>(ctx.subject()) {
            for eku in &ekus {
                eku_oids.push(eku.oid_value.to_string());
                if eku.oid_value.starts_with("1.3.6.1.4.1.311") {
                    is_ats_issued = true;
                }
            }
        }

        ctx.observe(AasSigningServiceIdentifiedFact {
            is_ats_issued,
            issuer_cn,
            eku_oids,
        })?;

        ctx.observe(AasComplianceFact {
            fips_level: if is_ats_issued {
                "FIPS 140-2 Level 3".to_string()
            } else {
                "unknown".to_string()
            },
            scitt_compliant: is_ats_issued,
        })?;

        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        static KEYS: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| {
            vec![
                FactKey::of::<AasSigningServiceIdentifiedFact>(),
                FactKey::of::<AasComplianceFact>(),
            ]
        })
    }
}

/// Trust pack for Azure Artifact Signing.
///
/// Produces AAS-specific trust facts (whether the signing cert was issued by AAS,
/// compliance markers).
pub struct AzureArtifactSigningTrustPack {
    fact_producer: Arc<AasFactProducer>,
}

impl Default for AzureArtifactSigningTrustPack {
    fn default() -> Self {
        Self {
            fact_producer: Arc::new(AasFactProducer),
        }
    }
}

impl AzureArtifactSigningTrustPack {
    pub fn new() -> Self {
        Self::default()
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
