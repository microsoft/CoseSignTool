// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signing options and configuration.

/// Options for signing operations.
///
/// Maps V2 `DirectSignatureOptions` and related options classes.
#[must_use = "builders do nothing unless consumed"]
#[derive(Debug, Clone)]
pub struct SigningOptions {
    /// Additional header contributors for this signing operation.
    pub additional_header_contributors: Vec<String>,
    /// Additional authenticated data (external AAD).
    pub additional_data: Option<Vec<u8>>,
    /// Disable transparency service integration.
    pub disable_transparency: bool,
    /// Fail if transparency service returns an error.
    pub fail_on_transparency_error: bool,
    /// Embed payload in the COSE_Sign1 message (true) or use detached payload (false).
    ///
    /// Maps V2 `DirectSignatureOptions.EmbedPayload`.
    pub embed_payload: bool,
}

impl Default for SigningOptions {
    fn default() -> Self {
        Self {
            additional_header_contributors: Vec::new(),
            additional_data: None,
            disable_transparency: false,
            fail_on_transparency_error: false,
            embed_payload: true,
        }
    }
}
