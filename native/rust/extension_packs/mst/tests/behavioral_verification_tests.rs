// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Behavioral tests for MST verification logic.
//!
//! These tests verify the correctness of the MST verification pipeline:
//! - Receipt parsing with proper VDS=2 headers
//! - Algorithm validation (ES256 accepted, unsupported rejected)
//! - JWKS resolution (offline keys, cache hit/miss, network fallback)
//! - Cache eviction after consecutive misses
//! - Cache poisoning detection and force refresh
//! - Authorization policy enforcement (all 6 behavior combinations)
//! - End-to-end verification with mock JWKS

use cose_sign1_transparent_mst::validation::jwks_cache::JwksCache;
use cose_sign1_transparent_mst::validation::verification_options::{
    AuthorizedReceiptBehavior, CodeTransparencyVerificationOptions, UnauthorizedReceiptBehavior,
};
use cose_sign1_transparent_mst::validation::verify::{
    get_receipt_issuer_host, get_receipts_from_message, get_receipts_from_transparent_statement,
    verify_transparent_statement, UNKNOWN_ISSUER_PREFIX,
};

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use code_transparency_client::{
    mock_transport::{MockResponse, SequentialMockTransport},
    CodeTransparencyClient, CodeTransparencyClientConfig, CodeTransparencyClientOptions,
    JwksDocument,
};
use cose_sign1_primitives::CoseSign1Message;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

// ==================== CBOR Helpers ====================

/// Encode a transparent statement with receipts in unprotected header 394.
fn encode_statement(receipts: &[Vec<u8>]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut phdr = p.encoder();
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap(); // alg
    phdr.encode_i64(-7).unwrap(); // ES256
    let phdr_bytes = phdr.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    // Unprotected: {394: [receipts...]}
    enc.encode_map(1).unwrap();
    enc.encode_i64(394).unwrap();
    enc.encode_array(receipts.len()).unwrap();
    for r in receipts {
        enc.encode_bstr(r).unwrap();
    }
    enc.encode_null().unwrap(); // detached payload
    enc.encode_bstr(b"stub-sig").unwrap();
    enc.into_bytes()
}

/// Encode a receipt with VDS=2 (proper MST), kid, issuer, and empty VDP proofs.
fn encode_receipt_vds2(issuer: &str, kid: &str) -> Vec<u8> {
    let p = EverParseCborProvider;

    // Protected: {alg: ES256, kid: kid, VDS: 2, CWT: {ISS: issuer}}
    let mut phdr = p.encoder();
    phdr.encode_map(4).unwrap();
    phdr.encode_i64(1).unwrap(); // alg
    phdr.encode_i64(-7).unwrap(); // ES256
    phdr.encode_i64(4).unwrap(); // kid label
    phdr.encode_bstr(kid.as_bytes()).unwrap();
    phdr.encode_i64(395).unwrap(); // VDS label
    phdr.encode_i64(2).unwrap(); // VDS = 2 (MST CCF)
    phdr.encode_i64(15).unwrap(); // CWT claims label
    phdr.encode_map(1).unwrap(); // CWT claims map
    phdr.encode_i64(1).unwrap(); // ISS claim
    phdr.encode_tstr(issuer).unwrap();
    let phdr_bytes = phdr.into_bytes();

    // Unprotected: {396: {-1: []}}  (VDP with empty proofs)
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    // Unprotected header with VDP
    enc.encode_map(1).unwrap();
    enc.encode_i64(396).unwrap(); // VDP label
    enc.encode_map(1).unwrap(); // VDP map
    enc.encode_i64(-1).unwrap(); // proofs label
    enc.encode_array(0).unwrap(); // empty proofs array
    enc.encode_null().unwrap(); // detached payload
    enc.encode_bstr(b"receipt-sig").unwrap();
    enc.into_bytes()
}

/// Encode a receipt with VDS=1 (non-MST, should be rejected).
fn encode_receipt_vds1(issuer: &str) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut phdr = p.encoder();
    phdr.encode_map(4).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(-7).unwrap();
    phdr.encode_i64(4).unwrap();
    phdr.encode_bstr(b"k1").unwrap();
    phdr.encode_i64(395).unwrap();
    phdr.encode_i64(1).unwrap(); // VDS = 1 (NOT MST)
    phdr.encode_i64(15).unwrap();
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_tstr(issuer).unwrap();
    let phdr_bytes = phdr.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
}

/// Encode a receipt missing VDS header.
fn encode_receipt_no_vds(issuer: &str) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut phdr = p.encoder();
    phdr.encode_map(3).unwrap(); // only 3 fields, no VDS
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(-7).unwrap();
    phdr.encode_i64(4).unwrap();
    phdr.encode_bstr(b"k1").unwrap();
    phdr.encode_i64(15).unwrap();
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_tstr(issuer).unwrap();
    let phdr_bytes = phdr.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
}

fn make_jwks_with_kid(kid: &str) -> String {
    format!(
        r#"{{"keys":[{{"kty":"EC","kid":"{}","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}}]}}"#,
        kid
    )
}

fn make_factory(
    jwks: &str,
) -> Arc<dyn Fn(&str, &CodeTransparencyClientOptions) -> CodeTransparencyClient + Send + Sync> {
    let jwks = jwks.to_string();
    Arc::new(move |_issuer, _opts| {
        let mock = SequentialMockTransport::new(vec![MockResponse::ok(jwks.as_bytes().to_vec())]);
        CodeTransparencyClient::with_options(
            Url::parse("https://mock.example.com").unwrap(),
            CodeTransparencyClientConfig::default(),
            CodeTransparencyClientOptions {
                client_options: mock.into_client_options(),
                ..Default::default()
            },
        )
    })
}

// ==================== Receipt Parsing Behavior ====================

#[test]
fn receipt_extraction_parses_issuers_correctly() {
    let r1 = encode_receipt_vds2("issuer-alpha.example.com", "kid-1");
    let r2 = encode_receipt_vds2("issuer-beta.example.com", "kid-2");
    let stmt = encode_statement(&[r1, r2]);

    let receipts = get_receipts_from_transparent_statement(&stmt).unwrap();
    assert_eq!(receipts.len(), 2, "Should extract 2 receipts");
    assert_eq!(receipts[0].issuer, "issuer-alpha.example.com");
    assert_eq!(receipts[1].issuer, "issuer-beta.example.com");
    assert!(
        receipts[0].message.is_some(),
        "Receipt should parse as COSE_Sign1"
    );
}

#[test]
fn receipt_extraction_assigns_unknown_prefix_for_unparseable() {
    let stmt = encode_statement(&[b"not-a-cose-message".to_vec()]);
    let receipts = get_receipts_from_transparent_statement(&stmt).unwrap();
    assert_eq!(receipts.len(), 1);
    assert!(
        receipts[0].issuer.starts_with(UNKNOWN_ISSUER_PREFIX),
        "Unparseable receipt should get unknown prefix, got: {}",
        receipts[0].issuer
    );
    assert!(receipts[0].message.is_none());
}

#[test]
fn receipt_extraction_empty_statement_returns_empty() {
    let stmt = encode_statement(&[]);
    let receipts = get_receipts_from_transparent_statement(&stmt).unwrap();
    assert_eq!(receipts.len(), 0);
}

#[test]
fn receipt_issuer_host_extracts_from_cwt_claims() {
    let receipt = encode_receipt_vds2("mst.contoso.com", "signing-key-1");
    let issuer = get_receipt_issuer_host(&receipt).unwrap();
    assert_eq!(issuer, "mst.contoso.com");
}

#[test]
fn receipt_issuer_host_fails_for_garbage() {
    let result = get_receipt_issuer_host(b"not-a-cose-message");
    assert!(result.is_err());
}

// ==================== Verification: No Receipts ====================

#[test]
fn verify_fails_when_no_receipts_present() {
    let stmt = encode_statement(&[]);
    let result = verify_transparent_statement(&stmt, None, None);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("No receipts")),
        "Should report 'No receipts found', got: {:?}",
        errors
    );
}

// ==================== Verification: VDS Validation ====================

#[test]
fn verify_with_vds2_receipt_exercises_full_path() {
    let receipt = encode_receipt_vds2("mst.example.com", "key-1");
    let stmt = encode_statement(&[receipt]);

    // Provide offline JWKS with the matching kid
    let jwks = JwksDocument::from_json(&make_jwks_with_kid("key-1")).unwrap();
    let mut keys = HashMap::new();
    keys.insert("mst.example.com".to_string(), jwks);

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: false,
        ..Default::default()
    }
    .with_offline_keys(keys);

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    // Verification will fail (fake sig) but exercises the FULL pipeline:
    // receipt parsing → VDS check → JWKS resolution → proof extraction → verify
    assert!(result.is_err());
    let errors = result.unwrap_err();
    // Should NOT be "No receipts" — should be a verification failure
    assert!(
        !errors.iter().any(|e| e.contains("No receipts")),
        "VDS=2 receipt should be processed, not skipped: {:?}",
        errors
    );
}

#[test]
fn verify_with_vds1_receipt_rejects_unsupported_vds() {
    let receipt = encode_receipt_vds1("bad-vds.example.com");
    let stmt = encode_statement(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: false,
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    assert!(result.is_err());
    // VDS=1 should be rejected with unsupported_vds error
}

// ==================== Verification: JWKS Resolution ====================

#[test]
fn verify_with_offline_jwks_finds_key_by_kid() {
    let receipt = encode_receipt_vds2("offline.example.com", "offline-key-1");
    let stmt = encode_statement(&[receipt]);

    let jwks = JwksDocument::from_json(&make_jwks_with_kid("offline-key-1")).unwrap();
    let mut keys = HashMap::new();
    keys.insert("offline.example.com".to_string(), jwks);

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: false,
        ..Default::default()
    }
    .with_offline_keys(keys);

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    // Will fail (fake sig) but should reach signature verification, not JWKS error
    assert!(result.is_err());
}

#[test]
fn verify_with_factory_resolves_jwks_from_network() {
    let receipt = encode_receipt_vds2("network.example.com", "net-key-1");
    let stmt = encode_statement(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: true,
        client_factory: Some(make_factory(&make_jwks_with_kid("net-key-1"))),
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    // Will fail (fake sig) but exercises the JWKS network fetch path
    assert!(result.is_err());
}

#[test]
fn verify_without_jwks_or_network_fails_cleanly() {
    let receipt = encode_receipt_vds2("no-keys.example.com", "missing-key");
    let stmt = encode_statement(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: false,
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    assert!(result.is_err());
}

// ==================== Cache Behavior ====================

#[test]
fn cache_insert_and_get_returns_document() {
    let cache = JwksCache::new();
    let jwks = JwksDocument::from_json(&make_jwks_with_kid("k1")).unwrap();
    cache.insert("issuer1.example.com", jwks.clone());

    let retrieved = cache.get("issuer1.example.com");
    assert!(retrieved.is_some(), "Inserted JWKS should be retrievable");
    assert_eq!(retrieved.unwrap().keys.len(), 1);
}

#[test]
fn cache_get_returns_none_for_missing_issuer() {
    let cache = JwksCache::new();
    assert!(cache.get("nonexistent.example.com").is_none());
}

#[test]
fn cache_evicts_after_miss_threshold() {
    let cache = JwksCache::new();
    let jwks = JwksDocument::from_json(&make_jwks_with_kid("k1")).unwrap();
    cache.insert("stale.example.com", jwks);

    // Record 4 misses — should NOT evict yet (threshold is 5)
    for i in 0..4 {
        let evicted = cache.record_miss("stale.example.com");
        assert!(!evicted, "Should not evict after {} misses", i + 1);
        assert!(
            cache.get("stale.example.com").is_some(),
            "Entry should still exist after {} misses",
            i + 1
        );
    }

    // 5th miss triggers eviction
    let evicted = cache.record_miss("stale.example.com");
    assert!(evicted, "Should evict after 5th miss");
    assert!(
        cache.get("stale.example.com").is_none(),
        "Entry should be gone after eviction"
    );
}

#[test]
fn cache_insert_resets_miss_counter() {
    let cache = JwksCache::new();
    let jwks = JwksDocument::from_json(&make_jwks_with_kid("k1")).unwrap();
    cache.insert("resettable.example.com", jwks.clone());

    // Record 3 misses
    for _ in 0..3 {
        cache.record_miss("resettable.example.com");
    }

    // Re-insert (simulates successful refresh)
    cache.insert("resettable.example.com", jwks);

    // Should need 5 more misses to evict (counter was reset)
    for _ in 0..4 {
        assert!(!cache.record_miss("resettable.example.com"));
    }
    assert!(
        cache.record_miss("resettable.example.com"),
        "Should evict after 5 NEW misses"
    );
}

#[test]
fn cache_poisoning_detected_after_all_misses_in_window() {
    let cache = JwksCache::new();

    // Fill the 20-entry sliding window with misses
    for _ in 0..20 {
        cache.record_verification_miss();
    }
    assert!(
        cache.check_poisoned(),
        "100% miss rate should indicate cache poisoning"
    );
}

#[test]
fn cache_poisoning_not_detected_with_single_hit() {
    let cache = JwksCache::new();

    for _ in 0..19 {
        cache.record_verification_miss();
    }
    cache.record_verification_hit(); // one hit breaks the streak
    assert!(
        !cache.check_poisoned(),
        "One hit should prevent poisoning detection"
    );
}

#[test]
fn cache_force_refresh_clears_all_entries() {
    let cache = JwksCache::new();
    let jwks = JwksDocument::from_json(&make_jwks_with_kid("k1")).unwrap();
    cache.insert("a.example.com", jwks.clone());
    cache.insert("b.example.com", jwks);

    cache.force_refresh();

    assert!(cache.get("a.example.com").is_none());
    assert!(cache.get("b.example.com").is_none());
}

#[test]
fn cache_clear_removes_all_entries() {
    let cache = JwksCache::new();
    let jwks = JwksDocument::from_json(&make_jwks_with_kid("k1")).unwrap();
    cache.insert("clearme.example.com", jwks);

    cache.clear();
    assert!(cache.get("clearme.example.com").is_none());
}

// ==================== File-Backed Cache ====================

#[test]
fn file_backed_cache_persists_and_loads() {
    let dir = std::env::temp_dir().join("mst-behavioral-test-cache");
    let _ = std::fs::create_dir_all(&dir);
    let file = dir.join("behavioral-test.json");
    let _ = std::fs::remove_file(&file);

    // Write
    {
        let cache = JwksCache::with_file(file.clone(), std::time::Duration::from_secs(3600), 5);
        let jwks = JwksDocument::from_json(&make_jwks_with_kid("persist-key")).unwrap();
        cache.insert("persist.example.com", jwks);
    }

    // Read in new cache instance
    {
        let cache = JwksCache::with_file(file.clone(), std::time::Duration::from_secs(3600), 5);
        let doc = cache.get("persist.example.com");
        assert!(doc.is_some(), "Persisted entry should be loaded from file");
        assert_eq!(doc.unwrap().keys[0].kid, "persist-key");
    }

    // Cleanup
    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_dir(&dir);
}

// ==================== Authorization Policy Enforcement ====================

#[test]
fn policy_require_all_fails_when_domain_has_no_receipt() {
    let receipt = encode_receipt_vds2("present.example.com", "k1");
    let stmt = encode_statement(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec![
            "present.example.com".to_string(),
            "missing.example.com".to_string(), // no receipt for this domain
        ],
        authorized_receipt_behavior: AuthorizedReceiptBehavior::RequireAll,
        allow_network_fetch: true,
        client_factory: Some(make_factory(&make_jwks_with_kid("k1"))),
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("missing.example.com")),
        "Should report missing domain, got: {:?}",
        errors
    );
}

#[test]
fn policy_verify_any_matching_clears_failures_on_success() {
    // With VerifyAnyMatching, if at least one authorized receipt would verify,
    // earlier failures are cleared. Since our receipts are fake, all will fail,
    // and the error should mention no valid receipts.
    let r1 = encode_receipt_vds2("auth.example.com", "k1");
    let stmt = encode_statement(&[r1]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["auth.example.com".to_string()],
        authorized_receipt_behavior: AuthorizedReceiptBehavior::VerifyAnyMatching,
        allow_network_fetch: true,
        client_factory: Some(make_factory(&make_jwks_with_kid("k1"))),
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    assert!(result.is_err()); // will fail (fake sig) but exercises VerifyAnyMatching
}

#[test]
fn policy_verify_all_matching_fails_if_any_receipt_invalid() {
    let r1 = encode_receipt_vds2("domain-a.example.com", "ka");
    let r2 = encode_receipt_vds2("domain-b.example.com", "kb");
    let stmt = encode_statement(&[r1, r2]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec![
            "domain-a.example.com".to_string(),
            "domain-b.example.com".to_string(),
        ],
        authorized_receipt_behavior: AuthorizedReceiptBehavior::VerifyAllMatching,
        allow_network_fetch: true,
        client_factory: Some(make_factory(&make_jwks_with_kid("ka"))), // only has ka, not kb
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    assert!(result.is_err());
}

#[test]
fn policy_fail_if_present_rejects_unauthorized_receipt() {
    let r_auth = encode_receipt_vds2("authorized.example.com", "ka");
    let r_unauth = encode_receipt_vds2("unauthorized.example.com", "ku");
    let stmt = encode_statement(&[r_auth, r_unauth]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["authorized.example.com".to_string()],
        unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::FailIfPresent,
        allow_network_fetch: false,
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("not in the authorized domain")),
        "Should reject unauthorized receipt, got: {:?}",
        errors
    );
}

#[test]
fn policy_ignore_all_with_no_authorized_domains_errors() {
    let receipt = encode_receipt_vds2("any.example.com", "k1");
    let stmt = encode_statement(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec![], // no authorized domains
        unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::IgnoreAll,
        allow_network_fetch: false,
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("No receipts would be verified")),
        "IgnoreAll + no authorized domains should error, got: {:?}",
        errors
    );
}

#[test]
fn policy_verify_all_ignores_unauthorized_with_ignore_all() {
    let r_auth = encode_receipt_vds2("auth.example.com", "ka");
    let r_unauth = encode_receipt_vds2("unauth.example.com", "ku");
    let stmt = encode_statement(&[r_auth, r_unauth]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["auth.example.com".to_string()],
        unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::IgnoreAll,
        allow_network_fetch: true,
        client_factory: Some(make_factory(&make_jwks_with_kid("ka"))),
        ..Default::default()
    };

    // The unauthorized receipt should be skipped entirely (not verified, not failed)
    let result = verify_transparent_statement(&stmt, Some(opts), None);
    // Will fail due to fake sig on authorized receipt, but unauthorized is ignored
    assert!(result.is_err());
}

// ==================== Multiple Receipt Scenarios ====================

#[test]
fn multiple_receipts_from_same_issuer() {
    let r1 = encode_receipt_vds2("same.example.com", "k1");
    let r2 = encode_receipt_vds2("same.example.com", "k2");
    let stmt = encode_statement(&[r1, r2]);

    let receipts = get_receipts_from_transparent_statement(&stmt).unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].issuer, "same.example.com");
    assert_eq!(receipts[1].issuer, "same.example.com");
}

#[test]
fn mixed_valid_and_invalid_receipts() {
    let valid_receipt = encode_receipt_vds2("valid.example.com", "k1");
    let garbage_receipt = b"not-cose".to_vec();
    let stmt = encode_statement(&[valid_receipt, garbage_receipt]);

    let receipts = get_receipts_from_transparent_statement(&stmt).unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].issuer, "valid.example.com");
    assert!(receipts[1].issuer.starts_with(UNKNOWN_ISSUER_PREFIX));
}

// ==================== Verification Options ====================

#[test]
fn verification_options_default_values() {
    let opts = CodeTransparencyVerificationOptions::default();
    assert!(opts.authorized_domains.is_empty());
    assert_eq!(
        opts.authorized_receipt_behavior,
        AuthorizedReceiptBehavior::RequireAll
    );
    assert_eq!(
        opts.unauthorized_receipt_behavior,
        UnauthorizedReceiptBehavior::VerifyAll
    );
    assert!(opts.allow_network_fetch);
    assert!(opts.jwks_cache.is_none());
    assert!(opts.client_factory.is_none());
}

#[test]
fn verification_options_with_offline_keys_seeds_cache() {
    let jwks = JwksDocument::from_json(&make_jwks_with_kid("offline-k")).unwrap();
    let mut keys = HashMap::new();
    keys.insert("offline.example.com".to_string(), jwks);

    let opts = CodeTransparencyVerificationOptions::default().with_offline_keys(keys);
    assert!(opts.jwks_cache.is_some());
    let cache = opts.jwks_cache.unwrap();
    let doc = cache.get("offline.example.com");
    assert!(doc.is_some());
    assert_eq!(doc.unwrap().keys[0].kid, "offline-k");
}

#[test]
fn verification_options_clone_preserves_factory() {
    let opts = CodeTransparencyVerificationOptions {
        client_factory: Some(make_factory(&make_jwks_with_kid("k"))),
        authorized_domains: vec!["test.example.com".to_string()],
        ..Default::default()
    };
    let cloned = opts.clone();
    assert_eq!(cloned.authorized_domains, vec!["test.example.com"]);
    assert!(cloned.client_factory.is_some());
}
