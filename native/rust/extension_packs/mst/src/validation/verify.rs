// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Static verification of transparent statements.
//!
//! Port of C# `CodeTransparencyClient.VerifyTransparentStatement()`.

use crate::validation::jwks_cache::JwksCache;
use crate::validation::receipt_verify::{
    get_cwt_issuer_host, verify_mst_receipt, ReceiptVerifyInput,
    CWT_CLAIMS_LABEL, CWT_ISS_LABEL,
};
use crate::validation::verification_options::{
    AuthorizedReceiptBehavior, CodeTransparencyVerificationOptions, UnauthorizedReceiptBehavior,
};
use code_transparency_client::{
    CodeTransparencyClient, CodeTransparencyClientConfig, CodeTransparencyClientOptions,
};
use cose_sign1_crypto_openssl::jwk_verifier::OpenSslJwkVerifierFactory;
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_signing::transparency::extract_receipts;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Prefix for receipts with unknown/unrecognized issuers.
pub const UNKNOWN_ISSUER_PREFIX: &str = "__unknown-issuer::";

/// A receipt extracted from a transparent statement, already parsed.
pub struct ExtractedReceipt {
    pub issuer: String,
    pub raw_bytes: Vec<u8>,
    pub message: Option<CoseSign1Message>,
}

impl std::fmt::Debug for ExtractedReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtractedReceipt")
            .field("issuer", &self.issuer)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

/// Extract receipts from raw transparent statement bytes.
pub fn get_receipts_from_transparent_statement(
    bytes: &[u8],
) -> Result<Vec<ExtractedReceipt>, String> {
    let msg = CoseSign1Message::parse(bytes)
        .map_err(|e| format!("failed to parse transparent statement: {}", e))?;
    get_receipts_from_message(&msg)
}

/// Extract receipts from an already-parsed [`CoseSign1Message`].
pub fn get_receipts_from_message(
    msg: &CoseSign1Message,
) -> Result<Vec<ExtractedReceipt>, String> {
    let blobs = extract_receipts(msg);
    let mut result = Vec::new();
    for (idx, raw_bytes) in blobs.into_iter().enumerate() {
        let parsed = CoseSign1Message::parse(&raw_bytes);
        let issuer = match &parsed {
            Ok(m) => get_cwt_issuer_host(&m.protected, CWT_CLAIMS_LABEL, CWT_ISS_LABEL)
                .unwrap_or_else(|| format!("{}{}", UNKNOWN_ISSUER_PREFIX, idx)),
            Err(_) => format!("{}{}", UNKNOWN_ISSUER_PREFIX, idx),
        };
        result.push(ExtractedReceipt { issuer, raw_bytes, message: parsed.ok() });
    }
    Ok(result)
}

/// Extract the issuer host from a receipt's CWT claims.
pub fn get_receipt_issuer_host(receipt_bytes: &[u8]) -> Result<String, String> {
    let receipt = CoseSign1Message::parse(receipt_bytes)
        .map_err(|e| format!("failed to parse receipt: {}", e))?;
    get_cwt_issuer_host(&receipt.protected, CWT_CLAIMS_LABEL, CWT_ISS_LABEL)
        .ok_or_else(|| "issuer not found in receipt CWT claims".to_string())
}

/// Verify a transparent statement from raw bytes.
pub fn verify_transparent_statement(
    bytes: &[u8],
    options: Option<CodeTransparencyVerificationOptions>,
    client_options: Option<CodeTransparencyClientOptions>,
) -> Result<(), Vec<String>> {
    let msg = CoseSign1Message::parse(bytes)
        .map_err(|e| vec![format!("failed to parse: {}", e)])?;
    verify_transparent_statement_message(&msg, bytes, options, client_options)
}

/// Verify an already-parsed transparent statement.
///
/// `raw_bytes` must be the original serialized bytes (needed for digest computation).
pub fn verify_transparent_statement_message(
    msg: &CoseSign1Message,
    raw_bytes: &[u8],
    options: Option<CodeTransparencyVerificationOptions>,
    client_options: Option<CodeTransparencyClientOptions>,
) -> Result<(), Vec<String>> {
    let mut options = options.unwrap_or_default();
    let client_options = client_options.unwrap_or_default();

    // Ensure a cache is always present. If the caller didn't provide one,
    // create a file-backed cache in a temp directory scoped to the process.
    // This means even one-shot callers benefit from caching within a session.
    if options.jwks_cache.is_none() {
        options.jwks_cache = Some(Arc::new(create_default_cache()));
    }

    let receipt_list = get_receipts_from_message(msg).map_err(|e| vec![e])?;
    if receipt_list.is_empty() {
        return Err(vec!["No receipts found in the transparent statement.".into()]);
    }

    // Build authorized domain set
    let authorized_set: HashSet<String> = options.authorized_domains.iter()
        .filter(|d| !d.is_empty() && !d.starts_with(UNKNOWN_ISSUER_PREFIX))
        .map(|d| d.trim().to_lowercase())
        .collect();
    let user_provided = !authorized_set.is_empty();

    if authorized_set.is_empty()
        && options.unauthorized_receipt_behavior == UnauthorizedReceiptBehavior::IgnoreAll
    {
        return Err(vec!["No receipts would be verified: no authorized domains and unauthorized behavior is IgnoreAll.".into()]);
    }

    // Early fail on unauthorized if FailIfPresent
    if options.unauthorized_receipt_behavior == UnauthorizedReceiptBehavior::FailIfPresent && user_provided {
        for r in &receipt_list {
            if !authorized_set.contains(&r.issuer.to_lowercase()) {
                return Err(vec![format!("Receipt issuer '{}' is not in the authorized domain list.", r.issuer)]);
            }
        }
    }

    let mut authorized_failures = Vec::new();
    let mut unauthorized_failures = Vec::new();
    let mut valid_authorized: HashSet<String> = HashSet::new();
    let mut authorized_with_receipt: HashSet<String> = HashSet::new();
    let mut clients: HashMap<String, CodeTransparencyClient> = HashMap::new();

    for receipt in &receipt_list {
        let issuer = &receipt.issuer;
        let issuer_lower = issuer.to_lowercase();
        let is_authorized = !user_provided || authorized_set.contains(&issuer_lower);

        if is_authorized && user_provided {
            authorized_with_receipt.insert(issuer_lower.clone());
        }

        let should_verify = if is_authorized {
            true
        } else {
            matches!(options.unauthorized_receipt_behavior, UnauthorizedReceiptBehavior::VerifyAll)
        };

        if !should_verify { continue; }

        if issuer.starts_with(UNKNOWN_ISSUER_PREFIX) {
            unauthorized_failures.push(format!("Cannot verify receipt with unknown issuer '{}'.", issuer));
            continue;
        }

        // Get or create client — use factory if provided, else default construction.
        let client = clients.entry(issuer.clone()).or_insert_with(|| {
            if let Some(ref factory) = options.client_factory {
                factory(issuer, &client_options)
            } else {
                let endpoint = url::Url::parse(&format!("https://{}", issuer))
                    .unwrap_or_else(|_| url::Url::parse("https://invalid").unwrap());
                CodeTransparencyClient::with_options(
                    endpoint, CodeTransparencyClientConfig::default(), client_options.clone(),
                )
            }
        });

        // Resolve JWKS: cache → network → fail.
        // At most ONE network fetch per issuer — result goes into cache.
        let jwks_json = resolve_jwks_for_issuer(issuer, client, &options);
        let used_cache = jwks_json.is_some();

        let factory = OpenSslJwkVerifierFactory;
        let input = ReceiptVerifyInput {
            statement_bytes_with_receipts: raw_bytes,
            receipt_bytes: &receipt.raw_bytes,
            offline_jwks_json: jwks_json.as_deref(),
            allow_network_fetch: options.allow_network_fetch && !used_cache,
            jwks_api_version: None,
            client: Some(client),
            jwk_verifier_factory: &factory,
        };

        match verify_mst_receipt(input) {
            Ok(result) if result.trusted => {
                if is_authorized { valid_authorized.insert(issuer_lower); }
                if used_cache {
                    if let Some(ref cache) = options.jwks_cache { cache.record_verification_hit(); }
                }
            }
            Ok(_) | Err(_) => {
                if used_cache {
                    if let Some(ref cache) = options.jwks_cache {
                        cache.record_verification_miss();
                        if cache.record_miss(issuer) && options.allow_network_fetch {
                            // Cache evicted — retry with fresh keys
                            if let Some(fresh) = fetch_and_cache_jwks(issuer, client, &options) {
                                let retry = ReceiptVerifyInput {
                                    statement_bytes_with_receipts: raw_bytes,
                                    receipt_bytes: &receipt.raw_bytes,
                                    offline_jwks_json: Some(&fresh),
                                    allow_network_fetch: false,
                                    jwks_api_version: None,
                                    client: Some(client),
                                    jwk_verifier_factory: &factory,
                                };
                                if let Ok(r) = verify_mst_receipt(retry) {
                                    if r.trusted {
                                        if is_authorized { valid_authorized.insert(issuer_lower); }
                                        cache.record_verification_hit();
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
                let msg = format!("Receipt verification failed for '{}'.", issuer);
                if is_authorized { authorized_failures.push(msg); }
                else { unauthorized_failures.push(msg); }
            }
        }
    }

    // Cache-poisoning check
    if let Some(ref cache) = options.jwks_cache {
        if cache.check_poisoned() { cache.force_refresh(); }
    }

    // Apply authorized-domain policy
    if user_provided {
        match options.authorized_receipt_behavior {
            AuthorizedReceiptBehavior::VerifyAnyMatching => {
                if valid_authorized.is_empty() {
                    authorized_failures.push("No valid receipts found for any authorized issuer domain.".into());
                } else {
                    authorized_failures.clear();
                }
            }
            AuthorizedReceiptBehavior::VerifyAllMatching => {
                if authorized_with_receipt.is_empty() {
                    authorized_failures.push("No valid receipts found for any authorized issuer domain.".into());
                }
                for d in &authorized_with_receipt {
                    if !valid_authorized.contains(d) {
                        authorized_failures.push(format!("A receipt from the required domain '{}' failed verification.", d));
                    }
                }
            }
            AuthorizedReceiptBehavior::RequireAll => {
                for d in &authorized_set {
                    if !valid_authorized.contains(d) {
                        authorized_failures.push(format!("No valid receipt found for a required domain '{}'.", d));
                    }
                }
            }
        }
    }

    let mut all = authorized_failures;
    all.extend(unauthorized_failures);
    if all.is_empty() { Ok(()) } else { Err(all) }
}

/// Resolve JWKS for an issuer: cache hit → network fetch (populates cache) → None.
fn resolve_jwks_for_issuer(
    issuer: &str,
    client: &CodeTransparencyClient,
    options: &CodeTransparencyVerificationOptions,
) -> Option<String> {
    if let Some(ref cache) = options.jwks_cache {
        if let Some(doc) = cache.get(issuer) {
            return serde_json::to_string(&doc).ok();
        }
    }
    if options.allow_network_fetch {
        return fetch_and_cache_jwks(issuer, client, options);
    }
    None
}

/// Fetch JWKS from network and insert into cache. Returns the JSON string.
fn fetch_and_cache_jwks(
    issuer: &str,
    client: &CodeTransparencyClient,
    options: &CodeTransparencyVerificationOptions,
) -> Option<String> {
    let doc = client.get_public_keys_typed().ok()?;
    if let Some(ref cache) = options.jwks_cache {
        cache.insert(issuer, doc.clone());
    }
    serde_json::to_string(&doc).ok()
}

/// Create a default file-backed JWKS cache in a safe temp directory.
///
/// The cache file is placed at `{temp_dir}/mst-jwks-cache/default.json`.
/// Each issuer is a separate key inside the cache, so a single file handles
/// multiple MST instances.
///
/// If the caller provides their own `jwks_cache` on the options, this is not used.
#[cfg_attr(coverage_nightly, coverage(off))]
fn create_default_cache() -> JwksCache {
    use crate::validation::jwks_cache::{DEFAULT_MISS_THRESHOLD, DEFAULT_REFRESH_INTERVAL};

    let cache_dir = std::env::temp_dir().join("mst-jwks-cache");
    if std::fs::create_dir_all(&cache_dir).is_ok() {
        let cache_file = cache_dir.join("default.json");
        JwksCache::with_file(cache_file, DEFAULT_REFRESH_INTERVAL, DEFAULT_MISS_THRESHOLD)
    } else {
        // Fall back to in-memory only if we can't write to temp
        JwksCache::new()
    }
}
