// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! In-process LRU cache fronting [`crate::CoseTpJsonFrontend`] (D9).
//!
//! Cache key: `blake3(canonical_doc_bytes) || blake3(canonical_params_bytes) ||
//! blake3(canonical_capabilities_bytes)`. Mirrors the .NET implementation but uses
//! `blake3` (R5 decision: 2026-05-08) instead of SHA-256 — internal-only key, so the
//! hash-function difference does not break any cross-port contract.
//!
//! Backed by `moka::sync::Cache` (R4 decision: 2026-05-08), which provides true LRU
//! semantics, lock-free reads on hits, and bounded capacity. Default capacity is 32
//! per [`crate::CoseTpJsonOptions`].

use crate::frontend::CoseTpJsonFrontend;
use crate::options::CoseTpJsonOptions;
use cose_sign1_trust_policy_spec::{
    to_canonical_json, TrustPolicySpec, TrustPolicyTranslationContext,
    TrustPolicyTranslationResult,
};
use moka::sync::Cache;
use serde_json::{Map, Value};
use std::sync::Arc;

/// Errors returned when constructing a [`TranslatorCache`].
///
/// `#[non_exhaustive]` so future construction-time validations surface as new variants
/// without breaking source compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TranslatorCacheError {
    /// Capacity was zero — a zero-capacity cache evicts every insert and is useless.
    InvalidCapacity {
        /// The configured capacity.
        capacity: u64,
    },
}

impl std::fmt::Display for TranslatorCacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCapacity { capacity } => write!(
                f,
                "cache capacity must be greater than zero, was {capacity}",
            ),
        }
    }
}

impl std::error::Error for TranslatorCacheError {}

/// In-process LRU cache fronting a [`CoseTpJsonFrontend`].
///
/// The cache is `Send + Sync`; multiple translator threads can share a single instance.
/// Cached values are wrapped in `Arc` so concurrent readers obtain inexpensive
/// reference-shared copies — mirroring §6.5.9 anti-pattern #4: cached entries are
/// derived data, never the policy of record.
pub struct TranslatorCache {
    inner: Cache<CacheKey, Arc<TrustPolicyTranslationResult>>,
    capacity: u64,
}

impl TranslatorCache {
    /// Construct a cache with caller-supplied [`CoseTpJsonOptions`]. The cache reads
    /// only `cache_capacity` from the options bundle.
    pub fn with_options(options: CoseTpJsonOptions) -> Result<Self, TranslatorCacheError> {
        Self::with_capacity(options.cache_capacity)
    }

    /// Construct a cache with a specific capacity. Capacity must be > 0.
    pub fn with_capacity(capacity: u64) -> Result<Self, TranslatorCacheError> {
        if capacity == 0 {
            return Err(TranslatorCacheError::InvalidCapacity { capacity });
        }
        Ok(Self {
            inner: Cache::builder().max_capacity(capacity).build(),
            capacity,
        })
    }

    /// Returns the configured cache capacity (entries — not bytes).
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Approximate number of entries currently held by the cache. Moka's `entry_count`
    /// is eventually-consistent so callers should treat this as a hint, not a contract.
    pub fn entry_count(&self) -> u64 {
        self.inner.run_pending_tasks();
        self.inner.entry_count()
    }

    /// Translate `text` through `frontend`, caching the result by canonical content
    /// hash + parameter hash + capability fingerprint so equal inputs return identical
    /// references without re-parsing or re-validating.
    ///
    /// The returned `Arc` may alias prior callers' results — the result type is
    /// effectively immutable, so concurrent readers see a stable snapshot.
    pub fn translate_text(
        &self,
        frontend: &CoseTpJsonFrontend,
        text: &str,
        ctx: &TrustPolicyTranslationContext,
        document_source: Option<&str>,
    ) -> Arc<TrustPolicyTranslationResult> {
        let key = compute_key(text, ctx, document_source);
        if let Some(hit) = self.inner.get(&key) {
            return hit;
        }
        let fresh = Arc::new(frontend.translate_text(text, ctx, document_source));
        self.inner.insert(key, fresh.clone());
        fresh
    }
}

impl std::fmt::Debug for TranslatorCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranslatorCache")
            .field("capacity", &self.capacity)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    doc_hash: [u8; 32],
    params_hash: [u8; 32],
    caps_hash: [u8; 32],
    document_source: Option<String>,
}

fn compute_key(
    text: &str,
    ctx: &TrustPolicyTranslationContext,
    document_source: Option<&str>,
) -> CacheKey {
    let doc_hash = *blake3::hash(text.as_bytes()).as_bytes();
    let params_hash = *blake3::hash(canonical_params(&ctx.parameters).as_bytes()).as_bytes();
    let caps_hash = *blake3::hash(canonical_capabilities(ctx).as_bytes()).as_bytes();
    CacheKey {
        doc_hash,
        params_hash,
        caps_hash,
        document_source: document_source.map(str::to_owned),
    }
}

fn canonical_params(parameters: &std::collections::BTreeMap<String, Value>) -> String {
    if parameters.is_empty() {
        return String::from("{}");
    }
    // BTreeMap iteration is sorted — produce a deterministic JSON object literal.
    let mut canonical = Map::with_capacity(parameters.len());
    for (name, value) in parameters {
        canonical.insert(name.clone(), value.clone());
    }
    Value::Object(canonical).to_string()
}

fn canonical_capabilities(ctx: &TrustPolicyTranslationContext) -> String {
    let Some(caps) = ctx.available_facts.as_ref() else {
        return String::from(":");
    };
    let prefix = if ctx.allow_unknown_facts { "u:" } else { "k:" };
    let mut buf = String::with_capacity(64);
    buf.push_str(prefix);
    for id in &caps.available_fact_ids {
        buf.push_str(id);
        buf.push(';');
    }
    for (id, schema) in &caps.predicate_schemas {
        buf.push_str(id);
        buf.push('=');
        buf.push_str(&schema.to_string());
        buf.push(';');
    }
    buf
}

/// Convenience: serialize a [`TrustPolicySpec`] to its canonical JSON form. Re-exported
/// for hosts that want to assert byte-stability against the cache's hashed inputs.
pub fn spec_to_canonical_json(spec: &TrustPolicySpec) -> Result<String, serde_json::Error> {
    to_canonical_json(spec)
}
