// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Options for direct signature factory.

use cose_sign1_signing::HeaderContributor;

/// Options for creating direct signatures.
///
/// Maps V2 `DirectSignatureOptions`.
#[must_use = "builders do nothing unless consumed"]
pub struct DirectSignatureOptions {
    /// Whether to embed the payload in the COSE_Sign1 message.
    ///
    /// When `true` (default), the payload is included in the message.
    /// When `false`, creates a detached signature where the payload is null.
    pub embed_payload: bool,

    /// Additional header contributors to apply during signing.
    pub additional_header_contributors: Vec<Box<dyn HeaderContributor>>,

    /// External additional authenticated data (AAD).
    ///
    /// This data is included in the signature but not in the message.
    pub additional_data: Vec<u8>,

    /// Whether to disable transparency providers.
    ///
    /// Default is `false` (transparency enabled).
    pub disable_transparency: bool,

    /// Whether to fail if transparency provider encounters an error.
    ///
    /// Default is `true` (fail on error).
    pub fail_on_transparency_error: bool,

    /// Maximum payload size for embedding.
    ///
    /// If `None`, uses the default MAX_EMBED_PAYLOAD_SIZE (100 MB).
    pub max_embed_size: Option<u64>,

    /// Whether to verify the signature after signing to ensure the COSE_Sign1
    /// message is valid for signature verification purposes.
    ///
    /// Default is `true`. This catches signing errors (wrong key, corrupted
    /// output, algorithm mismatch) before the message leaves the factory.
    ///
    /// Set to `false` only in performance-critical paths where you trust the
    /// signer and want to avoid the ~80μs verification overhead per operation.
    ///
    /// **Note:** This verifies cryptographic integrity only — it does NOT
    /// establish trust over the signing key or certificate chain.
    pub verify_after_sign: bool,
}

impl DirectSignatureOptions {
    /// Creates new options with defaults.
    pub fn new() -> Self {
        Self {
            embed_payload: true,
            additional_header_contributors: Vec::new(),
            additional_data: Vec::new(),
            disable_transparency: false,
            fail_on_transparency_error: true,
            max_embed_size: None,
            verify_after_sign: true,
        }
    }

    /// Sets whether to embed the payload.
    pub fn with_embed_payload(mut self, embed: bool) -> Self {
        self.embed_payload = embed;
        self
    }

    /// Adds a header contributor.
    pub fn add_header_contributor(mut self, contributor: Box<dyn HeaderContributor>) -> Self {
        self.additional_header_contributors.push(contributor);
        self
    }

    /// Sets the external AAD.
    pub fn with_additional_data(mut self, data: Vec<u8>) -> Self {
        self.additional_data = data;
        self
    }

    /// Sets the maximum payload size for embedding.
    pub fn with_max_embed_size(mut self, size: u64) -> Self {
        self.max_embed_size = Some(size);
        self
    }

    /// Sets whether to disable transparency providers.
    pub fn with_disable_transparency(mut self, disable: bool) -> Self {
        self.disable_transparency = disable;
        self
    }

    /// Sets whether to verify the signature after signing.
    ///
    /// Default is `true`. Set to `false` only when performance is critical
    /// and the signer is trusted.
    pub fn with_verify_after_sign(mut self, verify: bool) -> Self {
        self.verify_after_sign = verify;
        self
    }
}

impl Default for DirectSignatureOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DirectSignatureOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectSignatureOptions")
            .field("embed_payload", &self.embed_payload)
            .field(
                "additional_header_contributors",
                &format!(
                    "<{} contributors>",
                    self.additional_header_contributors.len()
                ),
            )
            .field(
                "additional_data",
                &format!("<{} bytes>", self.additional_data.len()),
            )
            .field("disable_transparency", &self.disable_transparency)
            .field(
                "fail_on_transparency_error",
                &self.fail_on_transparency_error,
            )
            .field("max_embed_size", &self.max_embed_size)
            .field("verify_after_sign", &self.verify_after_sign)
            .finish()
    }
}
