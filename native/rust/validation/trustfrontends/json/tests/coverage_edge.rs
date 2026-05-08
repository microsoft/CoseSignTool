// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Edge-case coverage: trait-method paths, builder helpers, Display impls, every
//! operator parser branch, recursion-cap path, on_empty=allow, top-level combinator
//! variants, deny_all node, not + reason, default failure messages, document_source
//! threading through the cache, and parameter-default fallback.

use cose_sign1_trust_policy_spec::{CoseTrustPolicyFrontend, FactCapabilities, TrustPolicySpec};
use cose_sign1_trustfrontends_json::{
    embedded_schema_bytes, CoseTpJsonFrontend, CoseTpJsonOptions, TranslatorCache,
    TranslatorCacheError, TrustPolicyTranslationContext, EMBEDDED_SCHEMA_RESOURCE_NAME,
    FRONTEND_ID,
};
use std::sync::Arc;

#[test]
fn frontend_default_and_options_accessors() {
    let frontend = CoseTpJsonFrontend::default();
    assert_eq!(frontend.options().max_depth, 64);
    assert_eq!(frontend.frontend_id(), "cose-tp-json/v1");
    assert_eq!(frontend.frontend_id(), FRONTEND_ID);
    let media_types = frontend.supported_media_types();
    assert!(media_types.contains(&"application/x-cose-trust-policy+json"));
    assert!(media_types.contains(&"application/x-cose-trust-policy+json5"));
}

#[test]
fn trait_translate_takes_value_directly() {
    let frontend = CoseTpJsonFrontend::new();
    let document: serde_json::Value = serde_json::from_str(
        r#"{ "frontend": "cose-tp-json/v1", "message": { "allow_all": true } }"#,
    )
    .unwrap();
    let ctx = TrustPolicyTranslationContext::default();
    let result = CoseTrustPolicyFrontend::translate(&frontend, document, &ctx);
    assert!(result.is_success(), "diag={:?}", result.diagnostics);
}

#[test]
fn options_builder_threads_overrides() {
    let opts = CoseTpJsonOptions::new()
        .with_max_depth(8)
        .with_cache_capacity(4);
    assert_eq!(opts.max_depth, 8);
    assert_eq!(opts.cache_capacity, 4);
    let frontend = CoseTpJsonFrontend::with_options(opts);
    assert_eq!(frontend.options().max_depth, 8);
}

#[test]
fn deny_all_node_translates_to_deny_all_spec() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "message": { "deny_all": "always-fail-by-policy" }
    }"#;
    let result =
        CoseTpJsonFrontend::new().translate_text(doc, &TrustPolicyTranslationContext::empty(), None);
    assert!(result.is_success(), "diag={:?}", result.diagnostics);
    let TrustPolicySpec::Message { requirements } = result.spec.unwrap() else {
        panic!("expected Message");
    };
    assert!(matches!(
        requirements[0],
        TrustPolicySpec::DenyAll { ref reason } if reason == "always-fail-by-policy"
    ));
}

#[test]
fn not_node_with_reason_carries_reason() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "not": { "fact": "x509-cert-eku/v1", "predicate": { "is_codesigning": true } },
            "reason": "must not be code-signing"
        }
    }"#;
    let result =
        CoseTpJsonFrontend::new().translate_text(doc, &TrustPolicyTranslationContext::empty(), None);
    assert!(result.is_success(), "diag={:?}", result.diagnostics);
    let TrustPolicySpec::PrimarySigningKey { requirements } = result.spec.unwrap() else {
        panic!("expected PrimarySigningKey");
    };
    let TrustPolicySpec::Not { reason, .. } = &requirements[0] else {
        panic!("expected Not");
    };
    assert_eq!(reason.as_deref(), Some("must not be code-signing"));
}

#[test]
fn any_of_with_two_children_produces_or_spec() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "any_of": [
                { "fact": "x509-chain-trusted/v1", "predicate": { "is_trusted": true } },
                { "fact": "x509-cert-eku/v1",      "predicate": { "is_eku": true } }
            ]
        }
    }"#;
    let result =
        CoseTpJsonFrontend::new().translate_text(doc, &TrustPolicyTranslationContext::empty(), None);
    let TrustPolicySpec::PrimarySigningKey { requirements } = result.spec.unwrap() else {
        panic!()
    };
    assert!(matches!(requirements[0], TrustPolicySpec::Or { ref specs } if specs.len() == 2));
}

#[test]
fn explicit_failure_message_is_preserved() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-chain-trusted/v1",
            "predicate": { "is_trusted": true },
            "failure_message": "the chain must be trusted by an explicit anchor"
        }
    }"#;
    let result =
        CoseTpJsonFrontend::new().translate_text(doc, &TrustPolicyTranslationContext::empty(), None);
    let TrustPolicySpec::PrimarySigningKey { requirements } = result.spec.unwrap() else {
        panic!()
    };
    let TrustPolicySpec::RequireFact {
        failure_message, ..
    } = &requirements[0]
    else {
        panic!()
    };
    assert_eq!(
        failure_message,
        "the chain must be trusted by an explicit anchor"
    );
}

#[test]
fn three_scopes_collapse_with_default_combinator() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "message": { "allow_all": true },
        "primary_signing_key": { "allow_all": true },
        "any_counter_signature": { "allow_all": true }
    }"#;
    let result =
        CoseTpJsonFrontend::new().translate_text(doc, &TrustPolicyTranslationContext::empty(), None);
    assert!(result.is_success());
    // No combinator specified → default "and".
    assert!(matches!(result.spec.unwrap(), TrustPolicySpec::And { .. }));
}

#[test]
fn recursion_cap_emits_tpx300() {
    // max_depth=3 with a doc that nests beyond that.
    let frontend = CoseTpJsonFrontend::with_options(CoseTpJsonOptions::new().with_max_depth(3));
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "all_of": [
                { "all_of": [
                    { "all_of": [
                        { "fact": "x509-chain-trusted/v1", "predicate": { "is_trusted": true } }
                    ]}
                ]}
            ]
        }
    }"#;
    let result = frontend.translate_text(doc, &TrustPolicyTranslationContext::empty(), None);
    assert!(!result.is_success());
    assert!(
        result.diagnostics.iter().any(|d| d.code == "TPX300"),
        "expected TPX300 with max_depth=3; got codes={:?}",
        result.diagnostics.iter().map(|d| &d.code).collect::<Vec<_>>()
    );
}

#[test]
fn pascalcase_operators_parse_to_canonical_irvariant() {
    use cose_sign1_trust_policy_spec::PredicateOperator;
    let cases = &[
        ("Exists", PredicateOperator::Exists),
        ("Equals", PredicateOperator::Equals),
        ("NotEquals", PredicateOperator::NotEquals),
        ("LessThan", PredicateOperator::LessThan),
        ("LessThanOrEqual", PredicateOperator::LessThanOrEqual),
        ("GreaterThan", PredicateOperator::GreaterThan),
        ("GreaterThanOrEqual", PredicateOperator::GreaterThanOrEqual),
        ("StartsWith", PredicateOperator::StartsWith),
        ("EndsWith", PredicateOperator::EndsWith),
        ("Contains", PredicateOperator::Contains),
        ("In", PredicateOperator::In),
    ];
    for (op_text, expected) in cases {
        let value_part = if *op_text == "Exists" {
            "".to_owned()
        } else {
            r#", "value": 5"#.to_owned()
        };
        let doc = format!(
            r#"{{
                "frontend": "cose-tp-json/v1",
                "primary_signing_key": {{
                    "fact": "x509-chain-trusted/v1",
                    "predicate": {{ "path": "$.x", "operator": "{op_text}"{value_part} }}
                }}
            }}"#,
        );
        let result = CoseTpJsonFrontend::new().translate_text(
            &doc,
            &TrustPolicyTranslationContext::empty(),
            None,
        );
        assert!(
            result.is_success(),
            "operator {op_text}: diag={:?}",
            result.diagnostics
        );
        let TrustPolicySpec::PrimarySigningKey { requirements } = result.spec.unwrap() else {
            panic!()
        };
        let TrustPolicySpec::RequireFact { predicate, .. } = &requirements[0] else {
            panic!()
        };
        let cose_sign1_trust_policy_spec::FactPredicateSpec::PathOperator(po) = predicate else {
            panic!("expected path-operator");
        };
        assert_eq!(po.operator, *expected, "for op {op_text}");
    }
}

#[test]
fn cache_with_options_threads_capacity() {
    let cache =
        TranslatorCache::with_options(CoseTpJsonOptions::new().with_cache_capacity(11)).unwrap();
    assert_eq!(cache.capacity(), 11);
}

#[test]
fn translator_cache_error_display() {
    let err = TranslatorCacheError::InvalidCapacity { capacity: 0 };
    let formatted = format!("{err}");
    assert!(formatted.contains("zero"), "got '{formatted}'");
}

#[test]
fn document_source_distinguishes_cache_entries() {
    let frontend = CoseTpJsonFrontend::new();
    let cache = TranslatorCache::with_capacity(8).unwrap();
    let ctx = TrustPolicyTranslationContext::empty();
    let doc = r#"{ "frontend": "cose-tp-json/v1", "message": { "allow_all": true } }"#;

    let a = cache.translate_text(&frontend, doc, &ctx, Some("file:///a"));
    let b = cache.translate_text(&frontend, doc, &ctx, Some("file:///b"));
    assert!(!Arc::ptr_eq(&a, &b));
    assert_eq!(cache.entry_count(), 2);
}

#[test]
fn parameters_modulate_cache_key() {
    use std::collections::BTreeMap;
    let frontend = CoseTpJsonFrontend::new();
    let cache = TranslatorCache::with_capacity(8).unwrap();

    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-cert-identity/v1",
            "predicate": { "thumbprint": { "$param": "expected" } }
        }
    }"#;

    let mut p1 = BTreeMap::new();
    p1.insert("expected".into(), serde_json::json!("a"));
    let mut p2 = BTreeMap::new();
    p2.insert("expected".into(), serde_json::json!("b"));

    let mut ctx_a = TrustPolicyTranslationContext::empty();
    ctx_a.parameters = p1;
    let mut ctx_b = TrustPolicyTranslationContext::empty();
    ctx_b.parameters = p2;

    let _ = cache.translate_text(&frontend, doc, &ctx_a, None);
    let _ = cache.translate_text(&frontend, doc, &ctx_b, None);
    assert_eq!(cache.entry_count(), 2);
}

#[test]
fn predicate_schemas_in_capabilities_modulate_cache_key() {
    let frontend = CoseTpJsonFrontend::new();
    let cache = TranslatorCache::with_capacity(8).unwrap();
    let doc = r#"{ "frontend": "cose-tp-json/v1", "message": { "allow_all": true } }"#;

    let mut caps_a = FactCapabilities::ids_only(["x509-chain-trusted/v1"]);
    caps_a.predicate_schemas.insert(
        "x509-chain-trusted/v1".into(),
        serde_json::json!({"type": "object"}),
    );
    let mut caps_b = caps_a.clone();
    caps_b.predicate_schemas.insert(
        "x509-chain-trusted/v1".into(),
        serde_json::json!({"type": "object", "additionalProperties": false}),
    );

    let mut ctx_a = TrustPolicyTranslationContext::empty();
    ctx_a.available_facts = Some(caps_a);
    ctx_a.allow_unknown_facts = true;
    let mut ctx_b = TrustPolicyTranslationContext::empty();
    ctx_b.available_facts = Some(caps_b);
    ctx_b.allow_unknown_facts = true;

    let _ = cache.translate_text(&frontend, doc, &ctx_a, None);
    let _ = cache.translate_text(&frontend, doc, &ctx_b, None);
    assert_eq!(cache.entry_count(), 2);
}

#[test]
fn predicate_schema_failure_emits_tpx201() {
    let mut caps = FactCapabilities::ids_only(["x509-chain-trusted/v1"]);
    caps.predicate_schemas.insert(
        "x509-chain-trusted/v1".into(),
        serde_json::json!({
            "type": "object",
            "required": ["is_trusted"],
            "properties": { "is_trusted": { "type": "boolean" } }
        }),
    );
    let mut ctx = TrustPolicyTranslationContext::empty();
    ctx.available_facts = Some(caps);
    ctx.allow_unknown_facts = true;

    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-chain-trusted/v1",
            "predicate": { "is_trusted": "not-a-bool" }
        }
    }"#;
    let result = CoseTpJsonFrontend::new().translate_text(doc, &ctx, None);
    assert!(!result.is_success());
    assert!(result.diagnostics.iter().any(|d| d.code == "TPX201"));
}

#[test]
fn predicate_schema_compile_failure_emits_tpx201() {
    let mut caps = FactCapabilities::ids_only(["x509-chain-trusted/v1"]);
    // "type" must be a string or array; using a number to make schema-compile fail.
    caps.predicate_schemas.insert(
        "x509-chain-trusted/v1".into(),
        serde_json::json!({"type": 123}),
    );
    let mut ctx = TrustPolicyTranslationContext::empty();
    ctx.available_facts = Some(caps);
    ctx.allow_unknown_facts = true;

    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-chain-trusted/v1",
            "predicate": { "is_trusted": true }
        }
    }"#;
    let result = CoseTpJsonFrontend::new().translate_text(doc, &ctx, None);
    assert!(!result.is_success());
    assert!(
        result.diagnostics.iter().any(|d| d.code == "TPX201"),
        "expected TPX201 from a malformed schema; got {:?}",
        result.diagnostics.iter().map(|d| &d.code).collect::<Vec<_>>()
    );
}

#[test]
fn embedded_schema_resource_name_is_stable() {
    assert!(EMBEDDED_SCHEMA_RESOURCE_NAME.contains("cose-tp/v1.json"));
    assert!(!embedded_schema_bytes().is_empty());
}

#[test]
fn spec_to_canonical_json_serializes() {
    let spec = TrustPolicySpec::message([TrustPolicySpec::AllowAll]);
    let json =
        cose_sign1_trustfrontends_json::cache::spec_to_canonical_json(&spec).unwrap();
    assert!(json.contains("\"type\":\"message\""));
}
