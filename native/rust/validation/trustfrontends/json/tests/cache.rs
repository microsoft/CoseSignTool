// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Translator-cache tests: same inputs hit, different inputs miss, capacity bounds
//! eviction, capacity == 0 is rejected at construction.

use cose_sign1_trust_policy_spec::FactCapabilities;
use cose_sign1_trustfrontends_json::{
    CoseTpJsonFrontend, CoseTpJsonOptions, TranslatorCache, TranslatorCacheError,
    TrustPolicyTranslationContext,
};

const DOC_A: &str = r#"{ "frontend": "cose-tp-json/v1", "message": { "allow_all": true } }"#;
const DOC_B: &str = r#"{ "frontend": "cose-tp-json/v1", "primary_signing_key": { "allow_all": true } }"#;

#[test]
fn equal_inputs_return_equal_results() {
    let frontend = CoseTpJsonFrontend::new();
    let cache = TranslatorCache::with_capacity(8).unwrap();
    let ctx = TrustPolicyTranslationContext::empty();

    let a1 = cache.translate_text(&frontend, DOC_A, &ctx, None);
    let a2 = cache.translate_text(&frontend, DOC_A, &ctx, None);
    // moka returns equal Arc clones; pointer equality is the cleanest indicator.
    assert!(std::sync::Arc::ptr_eq(&a1, &a2));
}

#[test]
fn different_documents_produce_different_entries() {
    let frontend = CoseTpJsonFrontend::new();
    let cache = TranslatorCache::with_capacity(8).unwrap();
    let ctx = TrustPolicyTranslationContext::empty();

    let _ = cache.translate_text(&frontend, DOC_A, &ctx, None);
    let _ = cache.translate_text(&frontend, DOC_B, &ctx, None);
    assert_eq!(cache.entry_count(), 2);
}

#[test]
fn different_capabilities_produce_different_entries_for_same_document() {
    let frontend = CoseTpJsonFrontend::new();
    let cache = TranslatorCache::with_capacity(8).unwrap();

    let ctx_open = TrustPolicyTranslationContext::empty();
    let mut ctx_caps = TrustPolicyTranslationContext::empty();
    ctx_caps.available_facts = Some(FactCapabilities::ids_only(["x509-chain-trusted/v1"]));
    ctx_caps.allow_unknown_facts = true;

    let _ = cache.translate_text(&frontend, DOC_A, &ctx_open, None);
    let _ = cache.translate_text(&frontend, DOC_A, &ctx_caps, None);
    assert_eq!(cache.entry_count(), 2);
}

#[test]
fn capacity_bounds_eviction() {
    let frontend = CoseTpJsonFrontend::new();
    let cache = TranslatorCache::with_capacity(2).unwrap();
    let ctx = TrustPolicyTranslationContext::empty();

    let docs = [
        r#"{ "frontend": "cose-tp-json/v1", "message": { "allow_all": true } }"#,
        r#"{ "frontend": "cose-tp-json/v1", "primary_signing_key": { "allow_all": true } }"#,
        r#"{ "frontend": "cose-tp-json/v1", "any_counter_signature": { "allow_all": true } }"#,
    ];
    for doc in &docs {
        let _ = cache.translate_text(&frontend, doc, &ctx, None);
    }
    assert!(
        cache.entry_count() <= 2,
        "cache must respect capacity; got {}",
        cache.entry_count()
    );
}

#[test]
fn zero_capacity_is_rejected() {
    let err = TranslatorCache::with_capacity(0).unwrap_err();
    assert_eq!(err, TranslatorCacheError::InvalidCapacity { capacity: 0 });
}

#[test]
fn options_carry_capacity_setting() {
    let cache = TranslatorCache::with_options(
        CoseTpJsonOptions::new().with_cache_capacity(7),
    )
    .unwrap();
    assert_eq!(cache.capacity(), 7);
}
