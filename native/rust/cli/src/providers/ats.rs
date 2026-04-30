// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Artifact Signing (ATS) provider.
//!
//! Creates an `AzureArtifactSigningService` from CLI arguments.
//! Behind the `ats` feature flag.

use anyhow::{Context, Result};
use cose_sign1_azure_artifact_signing::options::AzureArtifactSigningOptions;
use cose_sign1_azure_artifact_signing::signing::signing_service::AzureArtifactSigningService;

/// Create an AAS signing service from CLI arguments.
pub fn create_ats_service(
    endpoint: &str,
    account_name: &str,
    cert_profile_name: &str,
) -> Result<AzureArtifactSigningService> {
    let options = AzureArtifactSigningOptions {
        endpoint: endpoint.to_string(),
        account_name: account_name.to_string(),
        certificate_profile_name: cert_profile_name.to_string(),
    };

    AzureArtifactSigningService::new(options)
        .map_err(|e| anyhow::anyhow!("Failed to create Azure Artifact Signing service: {e}"))
        .context("Ensure Azure credentials are configured (az login, managed identity, or environment variables)")
}
