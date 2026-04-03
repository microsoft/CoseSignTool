// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use code_transparency_client::JwksDocument;
use cose_sign1_transparent_mst::validation::jwks_cache::JwksCache;
use std::time::Duration;

fn sample_jwks() -> JwksDocument {
    JwksDocument::from_json(r#"{"keys":[{"kty":"EC","kid":"k1","crv":"P-256"}]}"#).unwrap()
}

fn sample_jwks_2() -> JwksDocument {
    JwksDocument::from_json(r#"{"keys":[{"kty":"EC","kid":"k2","crv":"P-384"}]}"#).unwrap()
}

#[test]
fn cache_insert_and_get() {
    let cache = JwksCache::new();
    assert!(cache.is_empty());

    cache.insert("issuer.example.com", sample_jwks());
    assert_eq!(cache.len(), 1);
    assert!(!cache.is_empty());

    let jwks = cache.get("issuer.example.com").unwrap();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid, "k1");
}

#[test]
fn cache_miss_returns_none() {
    let cache = JwksCache::new();
    assert!(cache.get("nonexistent").is_none());
}

#[test]
fn cache_stale_entry_returns_none() {
    let cache = JwksCache::with_settings(Duration::from_millis(1), 5);
    cache.insert("issuer.example.com", sample_jwks());

    // Wait for TTL to expire
    std::thread::sleep(Duration::from_millis(10));

    assert!(cache.get("issuer.example.com").is_none());
}

#[test]
fn cache_miss_eviction() {
    let cache = JwksCache::with_settings(Duration::from_secs(3600), 3);
    cache.insert("issuer.example.com", sample_jwks());

    // Record misses up to threshold
    assert!(!cache.record_miss("issuer.example.com")); // miss 1
    assert!(!cache.record_miss("issuer.example.com")); // miss 2
    assert!(cache.record_miss("issuer.example.com")); // miss 3 → evicted

    assert!(cache.is_empty());
    assert!(cache.get("issuer.example.com").is_none());
}

#[test]
fn cache_insert_resets_miss_count() {
    let cache = JwksCache::with_settings(Duration::from_secs(3600), 3);
    cache.insert("issuer.example.com", sample_jwks());

    cache.record_miss("issuer.example.com"); // miss 1
    cache.record_miss("issuer.example.com"); // miss 2

    // Re-insert resets the counter
    cache.insert("issuer.example.com", sample_jwks_2());
    assert!(!cache.record_miss("issuer.example.com")); // miss 1 again
    assert!(!cache.record_miss("issuer.example.com")); // miss 2 again
    assert!(cache.record_miss("issuer.example.com")); // miss 3 → evicted
}

#[test]
fn cache_clear() {
    let cache = JwksCache::new();
    cache.insert("a.example.com", sample_jwks());
    cache.insert("b.example.com", sample_jwks_2());
    assert_eq!(cache.len(), 2);

    cache.clear();
    assert!(cache.is_empty());
}

#[test]
fn cache_issuers() {
    let cache = JwksCache::new();
    cache.insert("a.example.com", sample_jwks());
    cache.insert("b.example.com", sample_jwks_2());

    let mut issuers = cache.issuers();
    issuers.sort();
    assert_eq!(issuers, vec!["a.example.com", "b.example.com"]);
}

#[test]
fn cache_file_persistence() {
    let dir = std::env::temp_dir();
    let path = dir.join("jwks_cache_test.json");
    let _ = std::fs::remove_file(&path);

    // Create and populate
    {
        let cache = JwksCache::with_file(&path, Duration::from_secs(3600), 5);
        cache.insert("issuer.example.com", sample_jwks());
        assert_eq!(cache.len(), 1);
    }

    // Verify file exists
    assert!(path.exists());

    // Load from file
    {
        let cache = JwksCache::with_file(&path, Duration::from_secs(3600), 5);
        assert_eq!(cache.len(), 1);
        let jwks = cache.get("issuer.example.com").unwrap();
        assert_eq!(jwks.keys[0].kid, "k1");
    }

    // Clear deletes file
    {
        let cache = JwksCache::with_file(&path, Duration::from_secs(3600), 5);
        cache.clear();
        assert!(!path.exists());
    }
}

#[test]
fn cache_record_miss_nonexistent_issuer() {
    let cache = JwksCache::new();
    // Recording miss on nonexistent issuer is a no-op
    assert!(!cache.record_miss("nonexistent"));
}

// ============================================================================
// Cache-poisoning detection
// ============================================================================

#[test]
fn poisoning_not_triggered_with_hits() {
    let cache = JwksCache::new();
    // Fill window with hits — should not be poisoned
    for _ in 0..25 {
        cache.record_verification_hit();
    }
    assert!(!cache.check_poisoned());
}

#[test]
fn poisoning_not_triggered_with_mixed() {
    let cache = JwksCache::new();
    for _ in 0..10 {
        cache.record_verification_miss();
    }
    cache.record_verification_hit(); // one hit breaks the streak
    for _ in 0..9 {
        cache.record_verification_miss();
    }
    assert!(!cache.check_poisoned());
}

#[test]
fn poisoning_triggered_all_misses() {
    let cache = JwksCache::new();
    // Fill window (default 20) with all misses
    for _ in 0..20 {
        cache.record_verification_miss();
    }
    assert!(cache.check_poisoned());
}

#[test]
fn poisoning_not_triggered_partial_window() {
    let cache = JwksCache::new();
    // Only 10 misses — window not full yet
    for _ in 0..10 {
        cache.record_verification_miss();
    }
    assert!(!cache.check_poisoned());
}

#[test]
fn force_refresh_clears_entries_and_resets_window() {
    let cache = JwksCache::new();
    cache.insert("issuer.example.com", sample_jwks());
    for _ in 0..20 {
        cache.record_verification_miss();
    }
    assert!(cache.check_poisoned());
    assert!(!cache.is_empty());

    cache.force_refresh();

    assert!(cache.is_empty());
    assert!(!cache.check_poisoned());
}

#[test]
fn clear_resets_verification_window() {
    let cache = JwksCache::new();
    for _ in 0..20 {
        cache.record_verification_miss();
    }
    assert!(cache.check_poisoned());

    cache.clear();
    assert!(!cache.check_poisoned());
}

#[test]
fn cache_default_settings() {
    let cache = JwksCache::default();
    assert_eq!(cache.refresh_interval, Duration::from_secs(3600));
    assert_eq!(cache.miss_threshold, 5);
    assert!(cache.is_empty());
}
