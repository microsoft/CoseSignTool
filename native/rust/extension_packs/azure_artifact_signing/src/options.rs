// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Configuration options for Azure Artifact Signing.

/// Options for connecting to Azure Artifact Signing.
#[derive(Debug, Clone)]
pub struct AzureArtifactSigningOptions {
    /// AAS endpoint URL (e.g., "https://eus.codesigning.azure.net")
    pub endpoint: String,
    /// AAS account name
    pub account_name: String,
    /// Certificate profile name within the account
    pub certificate_profile_name: String,
}
