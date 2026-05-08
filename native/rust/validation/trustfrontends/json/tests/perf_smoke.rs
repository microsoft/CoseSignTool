// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Loose perf smoke for Phase 2 — 1KB document → ≤50ms p99 (loose; Phase 4 enforces
//! the statistical p99 ≤ 10ms target). This test is here to catch order-of-magnitude
//! regressions early.

use cose_sign1_trustfrontends_json::{CoseTpJsonFrontend, TrustPolicyTranslationContext};
use std::time::Instant;

fn build_doc_around_1kb() -> String {
    // ~1KB document with non-trivial structure (3 scopes + multiple fact references).
    r#"{
        "frontend": "cose-tp-json/v1",
        "combinator": "and",
        "message": {
            "all_of": [
                { "fact": "content-type/v1", "predicate": { "matches": "application/cose" } },
                { "fact": "detached-payload-present/v1", "predicate": { "is_present": false } }
            ]
        },
        "primary_signing_key": {
            "all_of": [
                { "fact": "x509-chain-trusted/v1",         "predicate": { "is_trusted": true } },
                { "fact": "x509-cert-identity-allowed/v1", "predicate": { "is_allowed": true } },
                { "fact": "x509-cert-eku/v1",              "predicate": { "has_codesigning": true } }
            ]
        },
        "any_counter_signature": {
            "on_empty": "deny",
            "all_of": [
                { "fact": "mst-receipt-trusted/v1", "predicate": { "is_trusted": true } },
                { "fact": "mst-receipt-issuer-host/v1", "predicate": { "host_matches": "dataplane.codetransparency.azure.net" } }
            ]
        }
    }"#
    .to_owned()
}

#[test]
fn translate_under_50ms_smoke() {
    let frontend = CoseTpJsonFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let doc = build_doc_around_1kb();

    // Warm up the lazily-compiled embedded schema so the timing isn't dominated by
    // first-use compilation.
    let _ = frontend.translate_text(&doc, &ctx, None);

    let start = Instant::now();
    let result = frontend.translate_text(&doc, &ctx, None);
    let elapsed = start.elapsed();
    assert!(result.is_success(), "diag={:?}", result.diagnostics);
    assert!(
        elapsed.as_millis() <= 50,
        "translation took {}ms, expected ≤ 50ms (Phase 2 loose smoke). Phase 4 enforces ≤ 10ms p99 statistically.",
        elapsed.as_millis()
    );
}
