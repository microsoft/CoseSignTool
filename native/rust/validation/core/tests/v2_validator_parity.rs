// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use cose_sign1_validation_primitives::facts::TrustFactEngine;
use cose_sign1_validation_primitives::policy::TrustPolicyBuilder;
use cose_sign1_validation_primitives::rules::FnRule;
use cose_sign1_validation_primitives::subject::TrustSubject;
use cose_sign1_validation_primitives::{CoseSign1Message, TrustDecision, TrustEvaluationOptions};
use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use std::sync::Arc;

struct AlwaysOkVerifier;

impl CryptoVerifier for AlwaysOkVerifier {
    fn algorithm(&self) -> i64 { -7 }
    
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

struct AlwaysFailVerifier;

impl CryptoVerifier for AlwaysFailVerifier {
    fn algorithm(&self) -> i64 { -7 }
    
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(false)
    }
}

struct FixedCoseKeyResolver {
    key: Arc<dyn CryptoVerifier>,
}

impl CoseKeyResolver for FixedCoseKeyResolver {
    fn resolve(
        &self,
        _message: &CoseSign1Message,
        _options: &CoseSign1ValidationOptions,
    ) -> CoseKeyResolutionResult {
        CoseKeyResolutionResult {
            is_success: true,
            cose_key: Some(self.key.clone()),
            candidate_keys: Vec::new(),
            key_id: None,
            thumbprint: None,
            diagnostics: Vec::new(),
            error_code: None,
            error_message: None,
        }
    }
}

#[derive(Default)]
struct CountingFailingPostSignatureValidator {
    calls: std::sync::atomic::AtomicUsize,
}

impl CountingFailingPostSignatureValidator {
    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl PostSignatureValidator for CountingFailingPostSignatureValidator {
    fn validate(&self, _context: &PostSignatureValidationContext<'_>) -> ValidationResult {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        ValidationResult::failure_message("post", "nope", Some("E_POST"))
    }
}

fn build_cose_sign1(payload: Option<&[u8]>) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7})  (alg = ES256)
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(1).unwrap();
    hdr_enc.encode_i64(-7).unwrap();
    let protected_bytes = hdr_enc.into_bytes();
    enc.encode_bstr(&protected_bytes).unwrap();

    // unprotected header: empty map
    enc.encode_map(0).unwrap();

    // payload: bstr or nil
    match payload {
        Some(p) => enc.encode_bstr(p).unwrap(),
        None => enc.encode_null().unwrap(),
    }

    // signature: b"sig"
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

fn allow_all_plan() -> cose_sign1_validation_primitives::plan::CompiledTrustPlan {
    TrustPolicyBuilder::new()
        .add_trust_source(Arc::new(FnRule::new(
            "allow",
            |_e: &TrustFactEngine, _s: &TrustSubject| Ok(TrustDecision::trusted()),
        )))
        .build()
        .compile()
}

fn validator_with_components(
    signing_key_resolvers: Vec<Arc<dyn CoseKeyResolver>>,
    post_signature_validators: Vec<Arc<dyn PostSignatureValidator>>,
    trust_plan: cose_sign1_validation_primitives::plan::CompiledTrustPlan,
    options: Option<CoseSign1ValidationOptions>,
    trust_evaluation_options: Option<TrustEvaluationOptions>,
) -> CoseSign1Validator {
    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();

    if !signing_key_resolvers.is_empty() {
        let resolver_pack = signing_key_resolvers.into_iter().fold(
            SimpleTrustPack::no_facts("test_signing_key_resolvers"),
            |pack, resolver| pack.with_cose_key_resolver(resolver),
        );
        trust_packs.push(Arc::new(resolver_pack));
    }

    if !post_signature_validators.is_empty() {
        let post_pack = post_signature_validators.into_iter().fold(
            SimpleTrustPack::no_facts("test_post_signature_validators"),
            |pack, validator| pack.with_post_signature_validator(validator),
        );
        trust_packs.push(Arc::new(post_pack));
    }

    // Provide the test trust plan as the default plan so validator init can stay on the
    // trust-pack path (no public plan+pack bundling constructor).
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("test_trust_plan").with_default_trust_plan(trust_plan),
    ));

    let mut merged_options = options.unwrap_or_default();
    if let Some(trust_evaluation_options) = trust_evaluation_options {
        merged_options.trust_evaluation_options = trust_evaluation_options;
    }

    CoseSign1Validator::advanced(trust_packs, merged_options)
}

#[test]
fn v2_validate_when_trust_is_denied_without_reasons_skips_signature_and_post() {
    let cose = build_cose_sign1(Some(b"payload"));

    let deny_empty_rule = Arc::new(FnRule::new(
        "deny_empty",
        |_e: &TrustFactEngine, _s: &TrustSubject| Ok(TrustDecision::denied(Vec::new())),
    ));
    let deny_plan = cose_sign1_validation_primitives::plan::CompiledTrustPlan::new(
        Vec::new(),
        Vec::new(),
        vec![deny_empty_rule],
        Vec::new(),
    );

    let validator = validator_with_components(
        vec![Arc::new(FixedCoseKeyResolver {
            key: Arc::new(AlwaysOkVerifier),
        })],
        vec![Arc::new(CountingFailingPostSignatureValidator::default())],
        deny_plan,
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions::default()),
    );

    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.trust.is_failure());
    assert_eq!(
        Some("TRUST_PLAN_NOT_SATISFIED".to_string()),
        result.trust.failures[0].error_code.clone()
    );
    assert_eq!(ValidationResultKind::NotApplicable, result.signature.kind);
    assert_eq!(
        ValidationResultKind::NotApplicable,
        result.post_signature_policy.kind
    );
    assert!(result.overall.is_failure());
}

#[test]
fn v2_validate_when_no_resolvers_returns_resolution_failure() {
    let cose = build_cose_sign1(Some(b"payload"));

    let validator = validator_with_components(
        vec![],
        vec![],
        allow_all_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions::default()),
    );

    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_failure());
    assert_eq!(
        Some("NO_SIGNING_KEY_RESOLVED".to_string()),
        result.resolution.failures[0].error_code.clone()
    );
    assert_eq!(ValidationResultKind::NotApplicable, result.trust.kind);
    assert_eq!(ValidationResultKind::NotApplicable, result.signature.kind);
    assert_eq!(
        ValidationResultKind::NotApplicable,
        result.post_signature_policy.kind
    );
}

#[test]
fn v2_validate_when_signing_key_resolved_and_signature_valid_returns_success() {
    let cose = build_cose_sign1(Some(b"payload"));

    let validator = validator_with_components(
        vec![Arc::new(FixedCoseKeyResolver {
            key: Arc::new(AlwaysOkVerifier),
        })],
        vec![],
        allow_all_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions::default()),
    );

    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid());
    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_valid());
    assert!(result.overall.is_valid());
}

#[test]
fn v2_validate_when_signing_key_resolved_but_wrong_key_returns_signature_failure() {
    let cose = build_cose_sign1(Some(b"payload"));

    let validator = validator_with_components(
        vec![Arc::new(FixedCoseKeyResolver {
            key: Arc::new(AlwaysFailVerifier),
        })],
        vec![],
        allow_all_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions::default()),
    );

    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_failure());
    assert_eq!(
        Some("SIGNATURE_VERIFICATION_FAILED".to_string()),
        result.signature.failures[0].error_code.clone()
    );
    assert_eq!(
        ValidationResultKind::NotApplicable,
        result.post_signature_policy.kind
    );
}

#[test]
fn v2_validate_when_detached_signature_and_no_payload_provided_returns_signature_missing_payload() {
    let cose = build_cose_sign1(None);

    let validator = validator_with_components(
        vec![Arc::new(FixedCoseKeyResolver {
            key: Arc::new(AlwaysOkVerifier),
        })],
        vec![],
        allow_all_plan(),
        Some(CoseSign1ValidationOptions {
            detached_payload: None,
            associated_data: None,
            certificate_header_location: Default::default(),
            skip_post_signature_validation: false,
            ..Default::default()
        }),
        Some(TrustEvaluationOptions::default()),
    );

    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_failure());
    assert_eq!(
        Some("SIGNATURE_MISSING_PAYLOAD".to_string()),
        result.signature.failures[0].error_code.clone()
    );
}

#[test]
fn v2_validate_when_bypassing_trust_succeeds_and_includes_bypass_metadata() {
    let cose = build_cose_sign1(Some(b"payload"));

    // A plan that would deny, but bypass should override.
    let deny_plan = TrustPolicyBuilder::new()
        .add_trust_source(Arc::new(FnRule::new(
            "deny",
            |_e: &TrustFactEngine, _s: &TrustSubject| {
                Ok(TrustDecision::denied(vec!["would-fail".to_string()]))
            },
        )))
        .build()
        .compile();

    let validator = validator_with_components(
        vec![Arc::new(FixedCoseKeyResolver {
            key: Arc::new(AlwaysOkVerifier),
        })],
        vec![],
        deny_plan,
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..TrustEvaluationOptions::default()
        }),
    );

    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert_eq!(
        Some("true".to_string()),
        result.trust.metadata.get("BypassTrust").cloned()
    );
}

#[test]
fn v2_validate_when_skip_post_signature_validation_true_does_not_invoke_post_validators() {
    let cose = build_cose_sign1(Some(b"payload"));

    let post = Arc::new(CountingFailingPostSignatureValidator::default());

    let validator = validator_with_components(
        vec![Arc::new(FixedCoseKeyResolver {
            key: Arc::new(AlwaysOkVerifier),
        })],
        vec![post.clone()],
        allow_all_plan(),
        Some(CoseSign1ValidationOptions {
            skip_post_signature_validation: true,
            ..CoseSign1ValidationOptions::default()
        }),
        Some(TrustEvaluationOptions::default()),
    );

    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
    assert_eq!(0, post.calls());
}
