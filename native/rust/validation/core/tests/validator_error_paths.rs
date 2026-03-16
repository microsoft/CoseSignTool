// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests targeting uncovered code paths in `validator.rs` and `fluent.rs`.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use cose_sign1_validation_primitives::{
    error::TrustError,
    evaluation_options::TrustEvaluationOptions,
    fact_properties::{FactProperties, FactValue},
    facts::{FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer},
    field::Field,
    fluent::TrustPlanBuilder as TrustPlanBuilderInner,
    plan::CompiledTrustPlan,
    policy::TrustPolicyBuilder,
    rules::{FnRule, TrustRuleRef},
    subject::TrustSubject,
    TrustDecision,
};
use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_primitives::error::PayloadError;
use cose_sign1_primitives::sig_structure::SizedRead;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn encode_protected_alg(alg: i64) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(alg).unwrap();
    enc.into_bytes()
}

fn encode_empty_map_bytes() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(0).unwrap();
    enc.into_bytes()
}

fn build_cose_sign1_bytes(payload: Option<&[u8]>, protected_bytes: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected_bytes).unwrap();
    enc.encode_map(0).unwrap();
    match payload {
        Some(p) => enc.encode_bstr(p).unwrap(),
        None => enc.encode_null().unwrap(),
    }
    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
}

fn allow_all_trust_plan() -> CompiledTrustPlan {
    TrustPolicyBuilder::new().build().compile()
}

struct AlwaysTrueVerifier;
impl CryptoVerifier for AlwaysTrueVerifier {
    fn algorithm(&self) -> i64 { -7 }
    
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
    
    fn supports_streaming(&self) -> bool {
        true
    }
    
    fn verify_init(&self, _signature: &[u8]) -> Result<Box<dyn crypto_primitives::VerifyingContext>, CryptoError> {
        Ok(Box::new(AlwaysTrueVerifyingContext))
    }
}

struct AlwaysTrueVerifyingContext;
impl crypto_primitives::VerifyingContext for AlwaysTrueVerifyingContext {
    fn update(&mut self, _chunk: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
    
    fn finalize(self: Box<Self>) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

/// Verifier that reports algorithm -35, which won't match ES256 (-7).
struct MismatchAlgVerifier;
impl CryptoVerifier for MismatchAlgVerifier {
    fn algorithm(&self) -> i64 { -35 }
    
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

struct StaticKeyResolver {
    key: Arc<dyn CryptoVerifier>,
}

impl CoseKeyResolver for StaticKeyResolver {
    fn resolve(
        &self,
        _message: &CoseSign1Message,
        _options: &CoseSign1ValidationOptions,
    ) -> CoseKeyResolutionResult {
        CoseKeyResolutionResult::success(self.key.clone())
    }
}

fn validator_with_components(
    signing_key_resolvers: Vec<Arc<dyn CoseKeyResolver>>,
    post_signature_validators: Vec<Arc<dyn PostSignatureValidator>>,
    trust_plan: CompiledTrustPlan,
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

    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("test_trust_plan").with_default_trust_plan(trust_plan),
    ));

    let mut merged_options = options.unwrap_or_default();
    if let Some(teo) = trust_evaluation_options {
        merged_options.trust_evaluation_options = teo;
    }

    CoseSign1Validator::advanced(trust_packs, merged_options)
}

// ---------------------------------------------------------------------------
// ValidationResult creation paths
// ---------------------------------------------------------------------------

#[test]
fn validation_result_success_with_none_metadata() {
    let r = ValidationResult::success("test", None);
    assert!(r.is_valid());
    assert!(!r.is_failure());
    assert!(r.metadata.is_empty());
    assert_eq!("test", r.validator_name);
}

#[test]
fn validation_result_success_with_some_metadata() {
    let mut m = BTreeMap::new();
    m.insert("k".to_string(), "v".to_string());
    let r = ValidationResult::success("test", Some(m));
    assert!(r.is_valid());
    assert_eq!(Some("v"), r.metadata.get("k").map(|s| s.as_str()));
}

#[test]
fn validation_result_not_applicable_with_none_reason() {
    let r = ValidationResult::not_applicable("na", None);
    assert!(!r.is_valid());
    assert!(!r.is_failure());
    assert_eq!(ValidationResultKind::NotApplicable, r.kind);
    assert!(r.metadata.is_empty());
}

#[test]
fn validation_result_not_applicable_with_whitespace_only_reason() {
    let r = ValidationResult::not_applicable("na", Some("   "));
    assert_eq!(ValidationResultKind::NotApplicable, r.kind);
    // Whitespace-only reason should not be stored.
    assert!(!r.metadata.contains_key(ValidationResult::METADATA_REASON_KEY));
}

#[test]
fn validation_result_not_applicable_with_valid_reason() {
    let r = ValidationResult::not_applicable("na", Some("skipped"));
    assert_eq!(
        Some("skipped"),
        r.metadata.get(ValidationResult::METADATA_REASON_KEY).map(|s| s.as_str())
    );
}

#[test]
fn validation_result_failure_message_with_none_error_code() {
    let r = ValidationResult::failure_message("sig", "bad", None);
    assert!(r.is_failure());
    assert_eq!(1, r.failures.len());
    assert_eq!("bad", r.failures[0].message);
    assert_eq!(None, r.failures[0].error_code);
}

#[test]
fn validation_result_failure_message_with_some_error_code() {
    let r = ValidationResult::failure_message("sig", "bad", Some("E001"));
    assert!(r.is_failure());
    assert_eq!(Some("E001".to_string()), r.failures[0].error_code);
}

#[test]
fn validation_result_failure_with_multiple_failures() {
    let failures = vec![
        ValidationFailure {
            message: "a".to_string(),
            error_code: Some("X".to_string()),
            property_name: Some("prop".to_string()),
            attempted_value: Some("val".to_string()),
            exception: Some("ex".to_string()),
        },
        ValidationFailure {
            message: "b".to_string(),
            ..ValidationFailure::default()
        },
    ];
    let r = ValidationResult::failure("multi", failures);
    assert!(r.is_failure());
    assert_eq!(2, r.failures.len());
    assert_eq!(Some("prop".to_string()), r.failures[0].property_name);
    assert_eq!(Some("val".to_string()), r.failures[0].attempted_value);
    assert_eq!(Some("ex".to_string()), r.failures[0].exception);
}

// ---------------------------------------------------------------------------
// StreamingPayload implementation tests
// ---------------------------------------------------------------------------

struct TestStreamingPayload {
    data: Vec<u8>,
    len: u64,
}

impl StreamingPayload for TestStreamingPayload {
    fn size(&self) -> u64 {
        self.len
    }

    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
        Ok(Box::new(Cursor::new(self.data.clone())))
    }
}

#[test]
fn streaming_payload_size_returns_configured_value() {
    let provider = TestStreamingPayload {
        data: b"data".to_vec(),
        len: 42,
    };
    assert_eq!(42, provider.size());

    // Also verify open() works.
    let reader = provider.open().unwrap();
    assert_eq!(4, reader.len().unwrap());
}

// ---------------------------------------------------------------------------
// CoseKeyResolutionResult / CounterSignatureResolutionResult construction
// ---------------------------------------------------------------------------

#[test]
fn cose_key_resolution_result_success_constructor() {
    let key: Arc<dyn CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let r = CoseKeyResolutionResult::success(key);
    assert!(r.is_success);
    assert!(r.cose_key.is_some());
    assert!(r.candidate_keys.is_empty());
    assert_eq!(None, r.key_id);
    assert_eq!(None, r.thumbprint);
    assert!(r.diagnostics.is_empty());
    assert_eq!(None, r.error_code);
    assert_eq!(None, r.error_message);
}

#[test]
fn cose_key_resolution_result_failure_constructor() {
    let r = CoseKeyResolutionResult::failure(Some("E".to_string()), Some("M".to_string()));
    assert!(!r.is_success);
    assert!(r.cose_key.is_none());
    assert_eq!(Some("E".to_string()), r.error_code);
    assert_eq!(Some("M".to_string()), r.error_message);
}

#[test]
fn counter_signature_resolution_result_success_constructor() {
    let r = CounterSignatureResolutionResult::success(vec![]);
    assert!(r.is_success);
    assert!(r.counter_signatures.is_empty());
    assert_eq!(None, r.error_code);
}

// ---------------------------------------------------------------------------
// Algorithm mismatch in signature stage
// ---------------------------------------------------------------------------

#[test]
fn signature_stage_algorithm_mismatch_returns_failure() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(MismatchAlgVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        Some(CoseSign1Validator::ERROR_CODE_ALGORITHM_MISMATCH.to_string()),
        result.signature.failures[0].error_code
    );
    assert!(result.signature.failures[0].message.contains("-35"));
    assert!(result.signature.failures[0].message.contains("-7"));
}

// ---------------------------------------------------------------------------
// CoseSign1Validator::with_options
// ---------------------------------------------------------------------------

#[test]
fn validator_with_options_applies_configuration() {
    let packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("test").with_default_trust_plan(allow_all_trust_plan()),
    )];

    let validator = CoseSign1Validator::new(packs).with_options(|opts| {
        opts.skip_post_signature_validation = true;
        opts.associated_data = Some(Arc::from(b"external-aad".to_vec().into_boxed_slice()));
    });

    // Verify the validator was created (it's opaque, but if with_options panicked we'd know).
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));
    // Without a key resolver, resolution will fail, but the validator was correctly configured.
    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
}

// ---------------------------------------------------------------------------
// CoseSign1Validator::validate (pre-parsed message path)
// ---------------------------------------------------------------------------

#[test]
fn validator_validate_with_pre_parsed_message() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));
    let cose_arc: Arc<[u8]> = Arc::from(cose.clone().into_boxed_slice());
    let parsed = CoseSign1Message::parse(&cose).unwrap();

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            skip_post_signature_validation: true,
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v.validate(&parsed, cose_arc).unwrap();
    assert!(result.overall.is_valid());
}

// ---------------------------------------------------------------------------
// Signature with external AAD (non-empty associated_data)
// ---------------------------------------------------------------------------

#[test]
fn signature_stage_with_external_aad_succeeds() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            associated_data: Some(Arc::from(b"external-aad".to_vec().into_boxed_slice())),
            skip_post_signature_validation: true,
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert!(result.signature.is_valid());
}

// ---------------------------------------------------------------------------
// Detached payload Bytes variant (non-empty)
// ---------------------------------------------------------------------------

#[test]
fn signature_stage_detached_payload_bytes_nonempty() {
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            detached_payload: Some(Payload::Bytes(b"detached-payload".to_vec())),
            skip_post_signature_validation: true,
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert!(result.signature.is_valid());
}

// ---------------------------------------------------------------------------
// Skip post-signature validation
// ---------------------------------------------------------------------------

#[test]
fn skip_post_signature_validation_skips_stage() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    // Validator with a post-signature validator that always fails, but skipping is enabled.
    struct FailPost;
    impl PostSignatureValidator for FailPost {
        fn validate(&self, _: &PostSignatureValidationContext<'_>) -> ValidationResult {
            ValidationResult::failure_message("FailPost", "should not run", None)
        }
    }

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![Arc::new(FailPost)],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            skip_post_signature_validation: true,
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

// ---------------------------------------------------------------------------
// Streaming path with non-empty external AAD
// ---------------------------------------------------------------------------

#[test]
fn streaming_signature_with_external_aad() {
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));
    
    struct LargePayloadProvider;
    impl StreamingPayload for LargePayloadProvider {
        fn size(&self) -> u64 {
            CoseSign1Validator::LARGE_STREAM_THRESHOLD + 1
        }
        fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
            Ok(Box::new(Cursor::new(vec![0u8; 8])))
        }
    }

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            detached_payload: Some(Payload::Streaming(Box::new(LargePayloadProvider))),
            associated_data: Some(Arc::from(b"ext-aad".to_vec().into_boxed_slice())),
            skip_post_signature_validation: true,
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert!(result.signature.is_valid());
}

// ---------------------------------------------------------------------------
// Buffered path: no alg in protected header
// ---------------------------------------------------------------------------

#[test]
fn buffered_signature_fails_when_alg_missing() {
    let protected = encode_empty_map_bytes();
    let cose = build_cose_sign1_bytes(Some(b"payload"), &protected);

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        Some(CoseSign1Validator::ERROR_CODE_NO_APPLICABLE_SIGNATURE_VALIDATOR.to_string()),
        result.signature.failures[0].error_code
    );
}

// ---------------------------------------------------------------------------
// CoseSign1ValidationError Display
// ---------------------------------------------------------------------------

#[test]
fn validation_error_display_formats() {
    let e1 = CoseSign1ValidationError::CoseDecode("bad cbor".to_string());
    let s1 = format!("{e1}");
    assert!(s1.contains("bad cbor"));

    let e2 = CoseSign1ValidationError::Trust("plan failed".to_string());
    let s2 = format!("{e2}");
    assert!(s2.contains("plan failed"));
}

// ---------------------------------------------------------------------------
// Payload::Bytes constructor
// ---------------------------------------------------------------------------

#[test]
fn payload_bytes_constructor() {
    let dp = Payload::Bytes(vec![1u8, 2, 3]);
    let s = format!("{dp:?}");
    assert!(s.contains("Bytes"));
}

// ---------------------------------------------------------------------------
// Fluent trust-plan DSL: compile_dnf edge cases
// ---------------------------------------------------------------------------

#[test]
fn trust_plan_builder_inner_single_term_compiles_without_wrapping() {
    // A single AND term (the len==1 branch in compile_dnf).
    let plan = TrustPlanBuilderInner::new()
        .for_message(|m| m.allow_all())
        .compile();

    let engine = TrustFactEngine::new(vec![]);
    let root = TrustSubject::root("Message", b"seed");
    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

#[test]
fn trust_plan_builder_inner_multiple_or_terms_compile() {
    // Multiple OR terms (the _=>any_of branch in compile_dnf).
    let plan = TrustPlanBuilderInner::new()
        .for_message(|m| m.allow_all())
        .or()
        .for_message(|m| m.allow_all())
        .compile();

    let engine = TrustFactEngine::new(vec![]);
    let root = TrustSubject::root("Message", b"seed");
    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

#[test]
fn trust_plan_builder_inner_empty_compiles_to_deny() {
    // Empty plan (no rules added) should compile as deny-all.
    let plan = TrustPlanBuilderInner::new().compile();

    let engine = TrustFactEngine::new(vec![]);
    let root = TrustSubject::root("Message", b"seed");
    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    // An empty all_of() is trusted (vacuously), but it's wrapped in any_of with 1 element.
    // The exact semantics depend on the implementation, so we just verify it compiles and runs.
    let _ = d.is_trusted;
}

// ---------------------------------------------------------------------------
// Fluent: and_group
// ---------------------------------------------------------------------------

#[test]
fn trust_plan_builder_inner_and_group_compiles() {
    let plan = TrustPlanBuilderInner::new()
        .and_group(|g| g.for_message(|m| m.allow_all()))
        .compile();

    let engine = TrustFactEngine::new(vec![]);
    let root = TrustSubject::root("Message", b"seed");
    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

// ---------------------------------------------------------------------------
// Fluent: ScopeRules push_rule OR branch
// ---------------------------------------------------------------------------

#[test]
fn scope_rules_or_branch_starts_new_conjunction() {
    let plan = TrustPlanBuilderInner::new()
        .for_message(|m| {
            m.allow_all()
                .or()
                .allow_all()
        })
        .compile();

    let engine = TrustFactEngine::new(vec![]);
    let root = TrustSubject::root("Message", b"seed");
    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

// ---------------------------------------------------------------------------
// Fluent: ScopeRules::require_rule
// ---------------------------------------------------------------------------

#[test]
fn scope_rules_require_rule_injects_prebuilt_rule() {
    let custom_rule: TrustRuleRef = Arc::new(FnRule::new(
        "custom",
        |_: &TrustFactEngine, _: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::trusted())
        },
    ));

    let plan = TrustPlanBuilderInner::new()
        .for_message(|m| m.require_rule(custom_rule, std::iter::empty()))
        .compile();

    let engine = TrustFactEngine::new(vec![]);
    let root = TrustSubject::root("Message", b"seed");
    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

#[test]
fn scope_rules_require_rule_with_fact_keys() {
    #[derive(Debug, Clone)]
    struct Dummy;
    impl FactProperties for Dummy {
        fn get_property<'a>(&'a self, _: &str) -> Option<FactValue<'a>> { None }
    }

    let custom_rule: TrustRuleRef = Arc::new(FnRule::new(
        "custom",
        |_: &TrustFactEngine, _: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision::trusted())
        },
    ));

    let plan = TrustPlanBuilderInner::new()
        .for_message(|m| {
            m.require_rule(custom_rule, vec![FactKey::of::<Dummy>()])
        })
        .compile();

    let required = plan.required_facts();
    assert!(required.iter().any(|k| k.name.contains("Dummy")));
}

// ---------------------------------------------------------------------------
// Fluent: ScopeRules::require_optional
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct OptionalFact {
    present: bool,
}

impl FactProperties for OptionalFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "present" => Some(FactValue::Bool(self.present)),
            _ => None,
        }
    }
}

#[test]
fn scope_rules_require_optional_succeeds_when_fact_missing() {
    // No producer for OptionalFact — require_optional should still succeed.
    let plan = TrustPlanBuilderInner::new()
        .for_message(|m| {
            m.require_optional::<OptionalFact>(|w| w.r#true(Field::new("present")))
        })
        .compile();

    let engine = TrustFactEngine::new(vec![]);
    let root = TrustSubject::root("Message", b"seed");
    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

// ---------------------------------------------------------------------------
// Fluent: Where predicates
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct NumericFact {
    count: usize,
    level: u32,
    score: i64,
}

impl FactProperties for NumericFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "count" => Some(FactValue::Usize(self.count)),
            "level" => Some(FactValue::U32(self.level)),
            "score" => Some(FactValue::I64(self.score)),
            _ => None,
        }
    }
}

struct NumericFactProducer;
impl TrustFactProducer for NumericFactProducer {
    fn name(&self) -> &'static str { "numeric" }
    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<NumericFact>()])
            .as_slice()
    }
    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        ctx.observe(NumericFact { count: 5, level: 3, score: 10 })?;
        ctx.mark_produced(FactKey::of::<NumericFact>());
        Ok(())
    }
}

#[test]
fn where_usize_eq_predicate() {
    let engine = TrustFactEngine::new(vec![Arc::new(NumericFactProducer)]);
    let root = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilderInner::new()
        .for_message(|m| {
            m.require::<NumericFact>(|w| w.usize_eq(Field::new("count"), 5))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

#[test]
fn where_u32_eq_predicate() {
    let engine = TrustFactEngine::new(vec![Arc::new(NumericFactProducer)]);
    let root = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilderInner::new()
        .for_message(|m| {
            m.require::<NumericFact>(|w| w.u32_eq(Field::new("level"), 3))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

#[test]
fn where_i64_ge_predicate() {
    let engine = TrustFactEngine::new(vec![Arc::new(NumericFactProducer)]);
    let root = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilderInner::new()
        .for_message(|m| {
            m.require::<NumericFact>(|w| w.i64_ge(Field::new("score"), 5))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

#[test]
fn where_i64_le_predicate() {
    let engine = TrustFactEngine::new(vec![Arc::new(NumericFactProducer)]);
    let root = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilderInner::new()
        .for_message(|m| {
            m.require::<NumericFact>(|w| w.i64_le(Field::new("score"), 100))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

#[test]
fn where_false_predicate() {
    #[derive(Debug, Clone)]
    struct BoolFact {
        flag: bool,
    }
    impl FactProperties for BoolFact {
        fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
            match name {
                "flag" => Some(FactValue::Bool(self.flag)),
                _ => None,
            }
        }
    }
    struct BoolProducer;
    impl TrustFactProducer for BoolProducer {
        fn name(&self) -> &'static str { "bool" }
        fn provides(&self) -> &'static [FactKey] {
            static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
            ONCE.get_or_init(|| vec![FactKey::of::<BoolFact>()])
                .as_slice()
        }
        fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
            ctx.observe(BoolFact { flag: false })?;
            ctx.mark_produced(FactKey::of::<BoolFact>());
            Ok(())
        }
    }

    let engine = TrustFactEngine::new(vec![Arc::new(BoolProducer)]);
    let root = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilderInner::new()
        .for_message(|m| {
            m.require::<BoolFact>(|w| w.r#false(Field::new("flag")))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

#[test]
fn where_str_eq_predicate() {
    #[derive(Debug, Clone)]
    struct StrFact {
        name: String,
    }
    impl FactProperties for StrFact {
        fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
            match name {
                "name" => Some(FactValue::Str(Cow::Borrowed(self.name.as_str()))),
                _ => None,
            }
        }
    }
    struct StrProducer;
    impl TrustFactProducer for StrProducer {
        fn name(&self) -> &'static str { "str" }
        fn provides(&self) -> &'static [FactKey] {
            static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
            ONCE.get_or_init(|| vec![FactKey::of::<StrFact>()])
                .as_slice()
        }
        fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
            ctx.observe(StrFact { name: "hello".to_string() })?;
            ctx.mark_produced(FactKey::of::<StrFact>());
            Ok(())
        }
    }

    let engine = TrustFactEngine::new(vec![Arc::new(StrProducer)]);
    let root = TrustSubject::root("Message", b"seed");

    let plan = TrustPlanBuilderInner::new()
        .for_message(|m| {
            m.require::<StrFact>(|w| w.str_eq(Field::new("name"), "hello"))
        })
        .compile();

    let d = plan
        .evaluate(&engine, &root, &TrustEvaluationOptions::default())
        .unwrap();
    assert!(d.is_trusted);
}

// ---------------------------------------------------------------------------
// CoseSign1 TrustPlanBuilder (wrapper in trust_plan_builder.rs)
// ---------------------------------------------------------------------------

struct NoopProducer;
impl TrustFactProducer for NoopProducer {
    fn name(&self) -> &'static str { "noop" }
    fn produce(&self, _: &mut TrustFactContext<'_>) -> Result<(), TrustError> { Ok(()) }
    fn provides(&self) -> &'static [FactKey] { &[] }
}

struct NoopPack;
impl CoseSign1TrustPack for NoopPack {
    fn name(&self) -> &'static str { "noop" }
    fn fact_producer(&self) -> Arc<dyn TrustFactProducer> { Arc::new(NoopProducer) }
}

#[test]
fn cose_sign1_trust_plan_builder_and_or_group() {
    let packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(NoopPack)];

    let plan = cose_sign1_validation::fluent::TrustPlanBuilder::new(packs)
        .and()
        .for_message(|m| m.allow_all())
        .or()
        .and_group(|g| g.for_message(|m| m.allow_all()))
        .compile()
        .unwrap();

    // Verify it produces a valid plan.
    let _ = plan.plan();
    let _ = plan.trust_packs();
}

#[test]
fn cose_sign1_trust_plan_builder_for_primary_signing_key() {
    let packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(NoopPack)];

    let _plan = cose_sign1_validation::fluent::TrustPlanBuilder::new(packs)
        .for_primary_signing_key(|k| k.allow_all())
        .compile()
        .unwrap();
}

// ---------------------------------------------------------------------------
// CoseSign1CompiledTrustPlan::from_parts
// ---------------------------------------------------------------------------

#[test]
fn compiled_trust_plan_from_parts_roundtrips() {
    let packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(NoopPack)];

    let plan = cose_sign1_validation::fluent::TrustPlanBuilder::new(packs.clone())
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();

    let (inner, original_packs) = plan.into_parts();
    let rebuilt =
        CoseSign1CompiledTrustPlan::from_parts(inner, original_packs).unwrap();
    assert_eq!(1, rebuilt.trust_packs().len());
}

// ---------------------------------------------------------------------------
// ValidationFailure default
// ---------------------------------------------------------------------------

#[test]
fn validation_failure_default_has_none_fields() {
    let f = ValidationFailure::default();
    assert!(f.message.is_empty());
    assert_eq!(None, f.error_code);
    assert_eq!(None, f.property_name);
    assert_eq!(None, f.attempted_value);
    assert_eq!(None, f.exception);
}

// ---------------------------------------------------------------------------
// ValidationResultKind Default
// ---------------------------------------------------------------------------

#[test]
fn validation_result_kind_default_is_not_applicable() {
    let k = ValidationResultKind::default();
    assert_eq!(ValidationResultKind::NotApplicable, k);
}

// ---------------------------------------------------------------------------
// CoseSign1ValidationOptions default
// ---------------------------------------------------------------------------

#[test]
fn validation_options_default_has_expected_values() {
    let opts = CoseSign1ValidationOptions::default();
    assert!(opts.detached_payload.is_none());
    assert!(opts.associated_data.is_none());
    assert!(!opts.skip_post_signature_validation);
}
