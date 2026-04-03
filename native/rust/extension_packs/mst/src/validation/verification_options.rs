// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Verification options for transparent statement validation.
//!
//! Port of C# `Azure.Security.CodeTransparency.CodeTransparencyVerificationOptions`.

use crate::validation::jwks_cache::JwksCache;
use code_transparency_client::{
    CodeTransparencyClient, CodeTransparencyClientOptions, JwksDocument,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Factory function type for creating `CodeTransparencyClient` instances.
pub type ClientFactory =
    dyn Fn(&str, &CodeTransparencyClientOptions) -> CodeTransparencyClient + Send + Sync;

/// Controls what happens when a receipt is from an authorized domain.
///
/// Maps C# `Azure.Security.CodeTransparency.AuthorizedReceiptBehavior`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthorizedReceiptBehavior {
    /// At least one receipt from any authorized domain must verify successfully.
    VerifyAnyMatching,
    /// All receipts from authorized domains must verify successfully.
    VerifyAllMatching,
    /// Every authorized domain must have at least one valid receipt.
    #[default]
    RequireAll,
}

/// Controls what happens when a receipt is from an unauthorized domain.
///
/// Maps C# `Azure.Security.CodeTransparency.UnauthorizedReceiptBehavior`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnauthorizedReceiptBehavior {
    /// Verify unauthorized receipts but don't fail if they're invalid.
    #[default]
    VerifyAll,
    /// Skip unauthorized receipts entirely.
    IgnoreAll,
    /// Fail immediately if any unauthorized receipt is present.
    FailIfPresent,
}

/// Options controlling transparent statement verification.
///
/// Maps C# `Azure.Security.CodeTransparency.CodeTransparencyVerificationOptions`.
///
/// ## JWKS key resolution
///
/// Keys are resolved via the [`jwks_cache`](Self::jwks_cache):
/// - **Pre-seeded (offline)**: Call [`with_offline_keys`](Self::with_offline_keys)
///   to populate the cache with known JWKS before verification.
/// - **Network fallback**: When `allow_network_fetch` is `true` (default) and a
///   key isn't in the cache, it's fetched from the service and cached.
/// - **Offline-only**: Set `allow_network_fetch = false` to use only pre-seeded keys.
pub struct CodeTransparencyVerificationOptions {
    /// List of authorized issuer domains. If empty, all issuers are treated as authorized.
    pub authorized_domains: Vec<String>,
    /// How to handle receipts from authorized domains.
    pub authorized_receipt_behavior: AuthorizedReceiptBehavior,
    /// How to handle receipts from unauthorized domains.
    pub unauthorized_receipt_behavior: UnauthorizedReceiptBehavior,
    /// Whether to allow network fetches for JWKS when the cache doesn't have the key.
    /// Default: `true`.
    pub allow_network_fetch: bool,
    /// JWKS cache for key resolution. Pre-seed with offline keys via
    /// [`with_offline_keys`](Self::with_offline_keys), or let verification
    /// auto-populate from network fetches.
    pub jwks_cache: Option<Arc<JwksCache>>,
    /// Optional factory for creating `CodeTransparencyClient` instances.
    ///
    /// When set, the verification code calls this factory instead of constructing
    /// clients from the issuer hostname. This allows tests to inject mock clients.
    ///
    /// The factory receives the issuer hostname and `CodeTransparencyClientOptions`,
    /// and returns a `CodeTransparencyClient`.
    pub client_factory: Option<Arc<ClientFactory>>,
}

impl std::fmt::Debug for CodeTransparencyVerificationOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeTransparencyVerificationOptions")
            .field("authorized_domains", &self.authorized_domains)
            .field(
                "authorized_receipt_behavior",
                &self.authorized_receipt_behavior,
            )
            .field(
                "unauthorized_receipt_behavior",
                &self.unauthorized_receipt_behavior,
            )
            .field("allow_network_fetch", &self.allow_network_fetch)
            .field("jwks_cache", &self.jwks_cache)
            .field(
                "client_factory",
                &self.client_factory.as_ref().map(|_| "Some(<factory>)"),
            )
            .finish()
    }
}

impl Clone for CodeTransparencyVerificationOptions {
    fn clone(&self) -> Self {
        Self {
            authorized_domains: self.authorized_domains.clone(),
            authorized_receipt_behavior: self.authorized_receipt_behavior,
            unauthorized_receipt_behavior: self.unauthorized_receipt_behavior,
            allow_network_fetch: self.allow_network_fetch,
            jwks_cache: self.jwks_cache.clone(),
            client_factory: self.client_factory.clone(),
        }
    }
}

impl Default for CodeTransparencyVerificationOptions {
    fn default() -> Self {
        Self {
            authorized_domains: Vec::new(),
            authorized_receipt_behavior: AuthorizedReceiptBehavior::default(),
            unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::default(),
            allow_network_fetch: true,
            jwks_cache: None,
            client_factory: None,
        }
    }
}

impl CodeTransparencyVerificationOptions {
    /// Pre-seed the cache with offline JWKS documents.
    ///
    /// Offline keys are inserted into the cache as if they were freshly fetched.
    /// If no cache exists yet, one is created with default settings.
    ///
    /// This replaces the old `offline_keys` field — offline keys ARE cache entries.
    pub fn with_offline_keys(mut self, keys: HashMap<String, JwksDocument>) -> Self {
        let cache = self
            .jwks_cache
            .get_or_insert_with(|| Arc::new(JwksCache::new()));
        for (issuer, jwks) in keys {
            cache.insert(&issuer, jwks);
        }
        self
    }
}
