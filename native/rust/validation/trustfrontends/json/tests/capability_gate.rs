// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Capability gating (D4) — TPX200 for unknown fact ids when the host advertises
//! capabilities and didn't opt in to AllowUnknownFacts. Also covers the opt-in path.

use cose_sign1_trust_policy_spec::FactCapabilities;
use cose_sign1_trustfrontends_json::{CoseTpJsonFrontend, TrustPolicyTranslationContext};

const DOC: &str = r#"{
    "frontend": "cose-tp-json/v1",
    "primary_signing_key": {
        "fact": "made-up-fact/v1",
        "predicate": { "is_trusted": true }
    }
}"#;

#[test]
fn unknown_fact_id_emits_tpx200_when_capabilities_close() {
    let frontend = CoseTpJsonFrontend::new();
    let mut ctx = TrustPolicyTranslationContext::empty();
    ctx.available_facts = Some(FactCapabilities::ids_only([
        "x509-chain-trusted/v1",
        "x509-cert-eku/v1",
    ]));
    ctx.allow_unknown_facts = false;
    let result = frontend.translate_text(DOC, &ctx, None);
    assert!(!result.is_success());
    let diag = result
        .diagnostics
        .iter()
        .find(|d| d.code == "TPX200")
        .expect("expected TPX200 for unknown fact id");
    assert!(diag.message.contains("made-up-fact/v1"));
    assert!(diag.message.contains("x509-chain-trusted/v1"));
}

#[test]
fn unknown_fact_id_tolerated_when_allow_unknown_facts_is_true() {
    let frontend = CoseTpJsonFrontend::new();
    let mut ctx = TrustPolicyTranslationContext::empty();
    ctx.available_facts = Some(FactCapabilities::ids_only(["x509-chain-trusted/v1"]));
    ctx.allow_unknown_facts = true;
    let result = frontend.translate_text(DOC, &ctx, None);
    assert!(result.is_success(), "diagnostics={:?}", result.diagnostics);
    assert!(result.diagnostics.iter().all(|d| d.code != "TPX200"));
}

#[test]
fn no_capability_surface_means_no_gate() {
    let frontend = CoseTpJsonFrontend::new();
    let ctx = TrustPolicyTranslationContext::empty();
    let result = frontend.translate_text(DOC, &ctx, None);
    assert!(result.is_success(), "diagnostics={:?}", result.diagnostics);
}
