// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Mock-based verification tests using the `client_factory` injection point.
//!
//! Exercises:
//! - JWKS network fetch success/failure paths
//! - Cache eviction + retry on miss threshold
//! - File-backed cache persistence
//! - Cache-poisoning detection + force_refresh
//! - Authorization policy enforcement (VerifyAnyMatching, VerifyAllMatching, RequireAll)
//! - Multiple receipt scenarios
//! - create_default_cache() file I/O

use cose_sign1_transparent_mst::validation::jwks_cache::JwksCache;
use cose_sign1_transparent_mst::validation::verification_options::{
    AuthorizedReceiptBehavior, CodeTransparencyVerificationOptions, UnauthorizedReceiptBehavior,
};
use cose_sign1_transparent_mst::validation::verify::{
    get_receipts_from_transparent_statement, verify_transparent_statement,
    verify_transparent_statement_message,
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

fn encode_statement_with_receipts(receipts: &[Vec<u8>]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    let mut phdr = p.encoder();
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(-7).unwrap();
    let phdr_bytes = phdr.into_bytes();

    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();

    enc.encode_map(1).unwrap();
    enc.encode_i64(394).unwrap();
    enc.encode_array(receipts.len()).unwrap();
    for r in receipts {
        enc.encode_bstr(r).unwrap();
    }

    enc.encode_null().unwrap();
    enc.encode_bstr(b"stub-sig").unwrap();

    enc.into_bytes()
}

fn encode_receipt_with_issuer(issuer: &str) -> Vec<u8> {
    let p = EverParseCborProvider;

    let mut phdr = p.encoder();
    phdr.encode_map(4).unwrap();
    phdr.encode_i64(1).unwrap(); // alg
    phdr.encode_i64(-7).unwrap(); // ES256
    phdr.encode_i64(4).unwrap(); // kid
    phdr.encode_bstr(b"k1").unwrap();
    phdr.encode_i64(395).unwrap(); // vds
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(15).unwrap(); // CWT claims
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap(); // iss
    phdr.encode_tstr(issuer).unwrap();
    let phdr_bytes = phdr.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(b"receipt-sig").unwrap();
    enc.into_bytes()
}

fn make_jwks_json() -> String {
    r#"{"keys":[{"kty":"EC","kid":"k1","crv":"P-256"}]}"#.to_string()
}

fn make_mock_client(jwks_response: &str) -> CodeTransparencyClient {
    let mock =
        SequentialMockTransport::new(vec![MockResponse::ok(jwks_response.as_bytes().to_vec())]);
    CodeTransparencyClient::with_options(
        Url::parse("https://mst.example.com").unwrap(),
        CodeTransparencyClientConfig::default(),
        CodeTransparencyClientOptions {
            client_options: mock.into_client_options(),
            ..Default::default()
        },
    )
}

/// Create a client factory that returns mock clients with canned JWKS responses.
fn make_factory_with_jwks(
    jwks_json: &str,
) -> Arc<dyn Fn(&str, &CodeTransparencyClientOptions) -> CodeTransparencyClient + Send + Sync> {
    let jwks = jwks_json.to_string();
    Arc::new(move |_issuer, _opts| {
        let mock = SequentialMockTransport::new(vec![MockResponse::ok(jwks.as_bytes().to_vec())]);
        CodeTransparencyClient::with_options(
            Url::parse("https://mst.example.com").unwrap(),
            CodeTransparencyClientConfig::default(),
            CodeTransparencyClientOptions {
                client_options: mock.into_client_options(),
                ..Default::default()
            },
        )
    })
}

/// Create a factory that returns clients with no responses (all calls fail).
fn make_failing_factory(
) -> Arc<dyn Fn(&str, &CodeTransparencyClientOptions) -> CodeTransparencyClient + Send + Sync> {
    Arc::new(|_issuer, _opts| {
        let mock = SequentialMockTransport::new(vec![]);
        CodeTransparencyClient::with_options(
            Url::parse("https://mst.example.com").unwrap(),
            CodeTransparencyClientConfig::default(),
            CodeTransparencyClientOptions {
                client_options: mock.into_client_options(),
                ..Default::default()
            },
        )
    })
}

// ==================== verify with client_factory ====================

#[test]
fn verify_with_factory_exercises_network_fetch() {
    let receipt = encode_receipt_with_issuer("mst.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: true,
        client_factory: Some(make_factory_with_jwks(&make_jwks_json())),
        ..Default::default()
    };

    // Verification will fail because the receipt signature is fake,
    // but it should exercise the JWKS fetch path without panicking
    let result = verify_transparent_statement(&stmt, Some(opts), None);
    // We expect errors (invalid signature) but the path through
    // resolve_jwks → fetch_and_cache_jwks → client.get_public_keys_typed()
    // should be exercised.
    assert!(result.is_err());
}

#[test]
fn verify_with_offline_keys_no_network() {
    let receipt = encode_receipt_with_issuer("offline.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let jwks = JwksDocument::from_json(&make_jwks_json()).unwrap();
    let mut keys = HashMap::new();
    keys.insert("offline.example.com".to_string(), jwks);

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: false,
        ..Default::default()
    }
    .with_offline_keys(keys);

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    // Offline verification will fail (fake sig) but exercises cache-hit path
    assert!(result.is_err());
}

#[test]
fn verify_with_failing_factory_returns_errors() {
    let receipt = encode_receipt_with_issuer("fail.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: true,
        client_factory: Some(make_failing_factory()),
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    assert!(result.is_err());
}

// ==================== Authorization policies ====================

#[test]
fn verify_any_matching_succeeds_if_no_authorized_receipts() {
    let receipt = encode_receipt_with_issuer("some.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["authorized.example.com".to_string()],
        authorized_receipt_behavior: AuthorizedReceiptBehavior::VerifyAnyMatching,
        unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::IgnoreAll,
        allow_network_fetch: false,
        client_factory: Some(make_failing_factory()),
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    // No authorized receipts found → error
    assert!(result.is_err());
}

#[test]
fn verify_all_matching_no_authorized_receipts() {
    let receipt = encode_receipt_with_issuer("random.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["required.example.com".to_string()],
        authorized_receipt_behavior: AuthorizedReceiptBehavior::VerifyAllMatching,
        unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::IgnoreAll,
        allow_network_fetch: false,
        client_factory: Some(make_failing_factory()),
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    assert!(result.is_err());
}

#[test]
fn require_all_missing_domain() {
    let receipt = encode_receipt_with_issuer("present.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec![
            "present.example.com".to_string(),
            "missing.example.com".to_string(),
        ],
        authorized_receipt_behavior: AuthorizedReceiptBehavior::RequireAll,
        allow_network_fetch: true,
        client_factory: Some(make_factory_with_jwks(&make_jwks_json())),
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.contains("missing.example.com")));
}

#[test]
fn fail_if_present_unauthorized() {
    let receipt = encode_receipt_with_issuer("unauthorized.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["only-this.example.com".to_string()],
        unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::FailIfPresent,
        allow_network_fetch: false,
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors
        .iter()
        .any(|e| e.contains("not in the authorized domain")));
}

#[test]
fn ignore_all_unauthorized_with_no_authorized_domains_errors() {
    let receipt = encode_receipt_with_issuer("ignored.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: Vec::new(),
        unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::IgnoreAll,
        allow_network_fetch: false,
        ..Default::default()
    };

    // No authorized domains + IgnoreAll → "No receipts would be verified" error
    let result = verify_transparent_statement(&stmt, Some(opts), None);
    assert!(result.is_err());
}

// ==================== Multiple receipts ====================

#[test]
fn multiple_receipts_different_issuers() {
    let r1 = encode_receipt_with_issuer("issuer-a.example.com");
    let r2 = encode_receipt_with_issuer("issuer-b.example.com");
    let stmt = encode_statement_with_receipts(&[r1, r2]);

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: true,
        client_factory: Some(make_factory_with_jwks(&make_jwks_json())),
        ..Default::default()
    };

    let result = verify_transparent_statement(&stmt, Some(opts), None);
    // Both fail sig verification, but the path is exercised
    assert!(result.is_err());
}

// ==================== JWKS Cache ====================

#[test]
fn cache_miss_eviction_after_threshold() {
    let cache = JwksCache::new();
    let jwks = JwksDocument::from_json(&make_jwks_json()).unwrap();
    cache.insert("stale.example.com", jwks);

    // Record misses up to threshold
    for _ in 0..4 {
        let evicted = cache.record_miss("stale.example.com");
        assert!(!evicted, "Should not evict before threshold");
    }

    // 5th miss triggers eviction
    let evicted = cache.record_miss("stale.example.com");
    assert!(evicted, "Should evict after 5 misses");

    // Entry should be gone
    assert!(cache.get("stale.example.com").is_none());
}

#[test]
fn cache_record_miss_nonexistent_issuer() {
    let cache = JwksCache::new();
    let evicted = cache.record_miss("nonexistent.example.com");
    assert!(!evicted, "Nonexistent issuers should not trigger eviction");
}

#[test]
fn cache_verification_hit_miss_tracking() {
    let cache = JwksCache::new();
    cache.record_verification_hit();
    cache.record_verification_miss();
    // Should not panic and should handle gracefully
    assert!(!cache.check_poisoned());
}

#[test]
fn cache_poisoning_detection() {
    let cache = JwksCache::new();
    // Fill the verification window with misses
    for _ in 0..20 {
        cache.record_verification_miss();
    }
    assert!(
        cache.check_poisoned(),
        "All misses should indicate poisoning"
    );
}

#[test]
fn cache_poisoning_not_triggered_with_hits() {
    let cache = JwksCache::new();
    for _ in 0..19 {
        cache.record_verification_miss();
    }
    cache.record_verification_hit();
    assert!(
        !cache.check_poisoned(),
        "One hit should prevent poisoning detection"
    );
}

#[test]
fn cache_force_refresh_clears_entries() {
    let cache = JwksCache::new();
    let jwks = JwksDocument::from_json(&make_jwks_json()).unwrap();
    cache.insert("entry.example.com", jwks);
    assert!(cache.get("entry.example.com").is_some());

    cache.force_refresh();
    assert!(
        cache.get("entry.example.com").is_none(),
        "force_refresh should clear cache"
    );
}

// ==================== File-backed cache ====================

#[test]
fn file_backed_cache_write_and_read() {
    use std::time::Duration;
    let dir = std::env::temp_dir().join("mst-test-cache-rw");
    let _ = std::fs::create_dir_all(&dir);
    let file = dir.join("test-cache.json");

    // Clean up any previous run
    let _ = std::fs::remove_file(&file);

    {
        let cache = JwksCache::with_file(file.clone(), Duration::from_secs(3600), 5);
        let jwks = JwksDocument::from_json(&make_jwks_json()).unwrap();
        cache.insert("persisted.example.com", jwks);
        // Cache should flush to file
    }

    // Verify file was written
    assert!(file.exists(), "Cache file should exist after insert");
    let content = std::fs::read_to_string(&file).unwrap();
    assert!(
        content.contains("persisted.example.com"),
        "File should contain issuer"
    );

    {
        // Create new cache from same file — should load persisted entries
        let cache = JwksCache::with_file(file.clone(), Duration::from_secs(3600), 5);
        let doc = cache.get("persisted.example.com");
        assert!(doc.is_some(), "Should load persisted entry from file");
    }

    // Clean up
    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn file_backed_cache_clear_removes_file() {
    let dir = std::env::temp_dir().join("mst-test-cache-clear");
    let _ = std::fs::create_dir_all(&dir);
    let file = dir.join("clear-test.json");
    let _ = std::fs::remove_file(&file);

    let cache = JwksCache::with_file(file.clone(), std::time::Duration::from_secs(3600), 5);
    let jwks = JwksDocument::from_json(&make_jwks_json()).unwrap();
    cache.insert("to-clear.example.com", jwks);
    assert!(file.exists());

    cache.clear();
    // After clear, file should be removed or empty
    if file.exists() {
        let content = std::fs::read_to_string(&file).unwrap_or_default();
        assert!(
            !content.contains("to-clear.example.com"),
            "Cleared content should not contain old entries"
        );
    }

    // Clean up
    let _ = std::fs::remove_file(&file);
    let _ = std::fs::remove_dir(&dir);
}

// ==================== Receipt extraction ====================

#[test]
fn extract_receipts_from_valid_statement() {
    let r1 = encode_receipt_with_issuer("issuer1.example.com");
    let r2 = encode_receipt_with_issuer("issuer2.example.com");
    let stmt = encode_statement_with_receipts(&[r1, r2]);

    let receipts = get_receipts_from_transparent_statement(&stmt).unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].issuer, "issuer1.example.com");
    assert_eq!(receipts[1].issuer, "issuer2.example.com");
}

#[test]
fn verify_statement_with_no_receipts() {
    let stmt = encode_statement_with_receipts(&[]);

    let result = verify_transparent_statement(&stmt, None, None);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(errors.iter().any(|e| e.contains("No receipts")));
}

// ==================== verify_transparent_statement_message ====================

#[test]
fn verify_message_with_factory() {
    let receipt = encode_receipt_with_issuer("msg.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);
    let msg = CoseSign1Message::parse(&stmt).unwrap();

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: true,
        client_factory: Some(make_factory_with_jwks(&make_jwks_json())),
        ..Default::default()
    };

    let result = verify_transparent_statement_message(&msg, &stmt, Some(opts), None);
    assert!(result.is_err()); // fake sig
}

// ==================== Verification options ====================

#[test]
fn options_with_client_factory_debug() {
    let opts = CodeTransparencyVerificationOptions {
        client_factory: Some(make_failing_factory()),
        ..Default::default()
    };
    let debug = format!("{:?}", opts);
    assert!(debug.contains("client_factory"));
    assert!(debug.contains("factory"));
}

#[test]
fn options_clone_with_factory() {
    let opts = CodeTransparencyVerificationOptions {
        client_factory: Some(make_failing_factory()),
        authorized_domains: vec!["test.example.com".to_string()],
        ..Default::default()
    };
    let cloned = opts.clone();
    assert_eq!(
        cloned.authorized_domains,
        vec!["test.example.com".to_string()]
    );
    assert!(cloned.client_factory.is_some());
}
