// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Verification provider registry.

use super::{VerificationProvider, VerificationProviderArgs};
use std::sync::Arc;

/// X.509 certificate verification provider.
#[cfg(feature = "certificates")]
pub struct CertificateVerificationProvider;

#[cfg(feature = "certificates")]
impl VerificationProvider for CertificateVerificationProvider {
    fn name(&self) -> &str {
        "certificates"
    }

    fn description(&self) -> &str {
        "X.509 certificate chain validation"
    }

    fn create_trust_pack(
        &self,
        args: &VerificationProviderArgs,
    ) -> Result<Arc<dyn cose_sign1_validation::fluent::CoseSign1TrustPack>, anyhow::Error> {
        let options = cose_sign1_certificates::validation::pack::CertificateTrustOptions {
            trust_embedded_chain_as_trusted: args.allow_embedded,
            ..Default::default()
        };
        Ok(Arc::new(
            cose_sign1_certificates::validation::pack::X509CertificateTrustPack::new(options),
        ))
    }
}

/// Azure Key Vault verification provider.
///
/// Maps V2 `AzureKeyVaultVerificationProvider`.
/// Validates that the message's kid matches allowed AKV key patterns.
#[cfg(feature = "akv")]
pub struct AkvVerificationProvider;

#[cfg(feature = "akv")]
impl VerificationProvider for AkvVerificationProvider {
    fn name(&self) -> &str {
        "akv"
    }

    fn description(&self) -> &str {
        "Azure Key Vault KID pattern validation"
    }

    fn create_trust_pack(
        &self,
        args: &VerificationProviderArgs,
    ) -> Result<Arc<dyn cose_sign1_validation::fluent::CoseSign1TrustPack>, anyhow::Error> {
        let options = cose_sign1_azure_key_vault::validation::pack::AzureKeyVaultTrustOptions {
            require_azure_key_vault_kid: true,
            allowed_kid_patterns: if args.akv_kid_patterns.is_empty() {
                vec![
                    "https://*.vault.azure.net/keys/*".to_string(),
                    "https://*.managedhsm.azure.net/keys/*".to_string(),
                ]
            } else {
                args.akv_kid_patterns.clone()
            },
        };
        Ok(Arc::new(
            cose_sign1_azure_key_vault::validation::pack::AzureKeyVaultTrustPack::new(options),
        ))
    }
}

/// MST receipt verification provider.
#[cfg(feature = "mst")]
pub struct MstVerificationProvider;

#[cfg(feature = "mst")]
impl VerificationProvider for MstVerificationProvider {
    fn name(&self) -> &str {
        "mst"
    }

    fn description(&self) -> &str {
        "Microsoft Transparency receipt verification"
    }

    fn create_trust_pack(
        &self,
        args: &VerificationProviderArgs,
    ) -> Result<Arc<dyn cose_sign1_validation::fluent::CoseSign1TrustPack>, anyhow::Error> {
        // If offline JWKS provided, use offline mode
        // Otherwise use defaults (offline, no network)
        let pack = if let Some(jwks_json) = &args.mst_offline_jwks {
            cose_sign1_transparent_mst::validation::pack::MstTrustPack::offline_with_jwks(jwks_json.clone())
        } else {
            cose_sign1_transparent_mst::validation::pack::MstTrustPack::new(false, None, None)
        };

        Ok(Arc::new(pack))
    }
}

/// Collect all available verification providers.
pub fn available_providers() -> Vec<Box<dyn VerificationProvider>> {
    let mut providers: Vec<Box<dyn VerificationProvider>> = Vec::new();

    #[cfg(feature = "certificates")]
    providers.push(Box::new(CertificateVerificationProvider));

    #[cfg(feature = "akv")]
    providers.push(Box::new(AkvVerificationProvider));

    #[cfg(feature = "mst")]
    providers.push(Box::new(MstVerificationProvider));

    providers
}
