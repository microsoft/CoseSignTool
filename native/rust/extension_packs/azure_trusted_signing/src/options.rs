// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Configuration options for Azure Trusted Signing.

/// Options for connecting to Azure Trusted Signing.
#[derive(Debug, Clone)]
pub struct AzureTrustedSigningOptions {
    /// ATS endpoint URL (e.g., "https://eus.codesigning.azure.net")
    pub endpoint: String,
    /// ATS account name
    pub account_name: String,
    /// Certificate profile name within the account
    pub certificate_profile_name: String,
}