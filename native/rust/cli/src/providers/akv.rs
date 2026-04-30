// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Key Vault (AKV) signing provider.
//!
//! Supports two modes matching V2 .NET CLI:
//! - `akv-cert`: Certificate-based signing (cert + chain from AKV, signing via AKV REST)
//! - `akv`: Key-only signing (no certificate chain, COSE key in header)
//!
//! Behind the `akv` feature flag.

use anyhow::{Context, Result};
use cose_sign1_azure_key_vault::common::akv_key_client::AkvKeyClient;
use cose_sign1_azure_key_vault::signing::akv_signing_service::AzureKeyVaultSigningService;
use cose_sign1_signing::SigningService;
use std::sync::Arc;

/// Create an AKV key-only signing service (no certificate chain).
///
/// Uses `kid` header + COSE_Key for key identification.
pub fn create_akv_key_service(
    vault_url: &str,
    key_name: &str,
    key_version: Option<&str>,
) -> Result<impl SigningService> {
    let crypto_client = AkvKeyClient::new_dev(vault_url, key_name, key_version)
        .map_err(|e| anyhow::anyhow!("Failed to create AKV crypto client: {e}"))?;

    let mut service = AzureKeyVaultSigningService::new(Box::new(crypto_client))
        .map_err(|e| anyhow::anyhow!("Failed to create AKV signing service: {e}"))?;

    service
        .initialize()
        .map_err(|e| anyhow::anyhow!("Failed to initialize AKV signing service: {e}"))
        .context(
            "Ensure Azure credentials are configured (az login) and the key vault/key are accessible",
        )?;

    Ok(service)
}

/// Create an AKV certificate-based signing service (with cert chain).
///
/// Fetches the certificate from AKV, then uses the AKV key for signing.
/// The certificate chain is embedded in the COSE x5chain header.
pub fn create_akv_cert_service(
    vault_url: &str,
    cert_name: &str,
    cert_version: Option<&str>,
) -> Result<impl SigningService> {
    // For certificate-based signing, AKV stores the cert under the same name as the key.
    // We create the crypto client with the cert name (which is also the key name in AKV).
    let crypto_client = AkvKeyClient::new_dev(vault_url, cert_name, cert_version)
        .map_err(|e| anyhow::anyhow!("Failed to create AKV crypto client: {e}"))?;

    let mut service = AzureKeyVaultSigningService::new(Box::new(crypto_client))
        .map_err(|e| anyhow::anyhow!("Failed to create AKV signing service: {e}"))?;

    service
        .initialize()
        .map_err(|e| anyhow::anyhow!("Failed to initialize AKV signing service: {e}"))
        .context(
            "Ensure Azure credentials are configured (az login) and the key vault certificate is accessible",
        )?;

    Ok(service)
}
