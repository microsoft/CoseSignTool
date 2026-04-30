// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Microsoft Signing Transparency (MST) provider.

use anyhow::{Context, Result};
use cose_sign1_signing::transparency::TransparencyProvider;
use cose_sign1_transparent_mst::{
    code_transparency_client::{CodeTransparencyClient, CodeTransparencyClientConfig},
    signing::MstTransparencyProvider,
};
use url::Url;

/// Create an MST transparency provider from CLI arguments.
pub fn create_mst_transparency_provider(endpoint: &str) -> Result<Box<dyn TransparencyProvider>> {
    let endpoint_url = Url::parse(endpoint)
        .with_context(|| format!("Failed to parse MST endpoint URL: {endpoint}"))?;
    let client = CodeTransparencyClient::new(endpoint_url, CodeTransparencyClientConfig::default());
    Ok(Box::new(MstTransparencyProvider::new(client)))
}
