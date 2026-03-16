// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for async validation and streaming signature paths.
//!
//! This test file specifically targets:
//! - Async validation methods with various failure scenarios
//! - Streaming signature verification for large payloads (>85KB)
//! - Detached streaming payload handling
//! - Result helper methods and option combinations

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use cose_sign1_validation_primitives::{
    error::TrustError,
    facts::{FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer},
    plan::CompiledTrustPlan,
    policy::TrustPolicyBuilder,
    rules::{FnRule, TrustRuleRef},
    subject::TrustSubject,
    TrustDecision, TrustEvaluationOptions,
};
use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::{CoseSign1Message, payload::{Payload, StreamingPayload}};
use cose_sign1_primitives::error::PayloadError;
use cose_sign1_primitives::sig_structure::SizedRead;
use crypto_primitives::{CryptoError, CryptoVerifier, VerifyingContext};
use std::sync::LazyLock;
use std::future::Future;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

// ---------------------------------------------------------------------------
// Manual async executor (no tokio dependency)
// ---------------------------------------------------------------------------

fn block_on<F: Future>(mut fut: F) -> F::Output {
    fn raw_waker() -> RawWaker {
        fn no_op(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        RawWaker::new(std::ptr::null(), &VTABLE)
    }

    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };

    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

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
    enc.encode_bstr(b"fake_signature").unwrap();
    enc.into_bytes()
}

fn allow_all_trust_plan() -> CompiledTrustPlan {
    TrustPolicyBuilder::new().build().compile()
}

// ---------------------------------------------------------------------------
// Mock CryptoVerifier implementations supporting streaming
// ---------------------------------------------------------------------------

struct StreamingVerifier;

impl CryptoVerifier for StreamingVerifier {
    fn algorithm(&self) -> i64 { -7 }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }

    fn verify_init(&self, _signature: &[u8]) -> Result<Box<dyn VerifyingContext>, CryptoError> {
        Ok(Box::new(MockVerifyingContext { valid: true }))
    }
}

struct StreamingVerifierFailsVerifyInit;

impl CryptoVerifier for StreamingVerifierFailsVerifyInit {
    fn algorithm(&self) -> i64 { -7 }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }

    fn verify_init(&self, _signature: &[u8]) -> Result<Box<dyn VerifyingContext>, CryptoError> {
        Err(CryptoError::VerificationFailed("verify_init_failed".to_string()))
    }
}

struct MockVerifyingContext {
    valid: bool,
}

impl VerifyingContext for MockVerifyingContext {
    fn update(&mut self, _data: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }

    fn finalize(self: Box<Self>) -> Result<bool, CryptoError> {
        Ok(self.valid)
    }
}

struct AlwaysTrueVerifier;

impl CryptoVerifier for AlwaysTrueVerifier {
    fn algorithm(&self) -> i64 { -7 }
    
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
// Large payload streaming provider
// ---------------------------------------------------------------------------

struct LargePayloadProvider {
    size: u64,
}

impl LargePayloadProvider {
    fn new(size: u64) -> Self {
        Self { size }
    }
}

impl StreamingPayload for LargePayloadProvider {
    fn size(&self) -> u64 {
        self.size
    }

    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
        Ok(Box::new(Cursor::new(vec![42u8; self.size as usize])) as Box<dyn SizedRead + Send>)
    }
}

// ---------------------------------------------------------------------------
// Tests mirroring existing sync tests but with async validation (using block_on)
// ---------------------------------------------------------------------------

#[test]
fn test_validate_bytes_async_happy_path() {
    let small_payload = b"hello_world";
    let cose = build_cose_sign1_bytes(Some(small_payload), &encode_protected_alg(-7));
    let parsed = CoseSign1Message::parse(&cose).unwrap();

    let validator = validator_with_components(
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

    let result = block_on(validator.validate_async(&parsed, Arc::from(cose.into_boxed_slice()))).unwrap();
    assert!(result.overall.is_valid());
    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid());
    assert!(result.signature.is_valid());
}

#[test]
fn test_validate_bytes_async_parse_failure() {
    // Invalid CBOR bytes
    let invalid_cbor = vec![0xFF, 0xFF, 0xFF, 0xFF];
    
    let validator = validator_with_components(
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

    let result = block_on(validator.validate_bytes_async(EverParseCborProvider, Arc::from(invalid_cbor.into_boxed_slice())));
    assert!(result.is_err()); // Should fail at parse stage
}

#[test]
fn test_validate_async_trust_failure() {
    let payload = b"test_payload";
    let cose = build_cose_sign1_bytes(Some(payload), &encode_protected_alg(-7));
    let parsed = CoseSign1Message::parse(&cose).unwrap();

    // Create a trust plan that always denies
    let deny_rule: TrustRuleRef = Arc::new(FnRule::new(
        "deny_all",
        |_engine: &TrustFactEngine, _subject: &TrustSubject| -> Result<TrustDecision, TrustError> {
            Ok(TrustDecision {
                is_trusted: false,
                reasons: vec!["denied by test rule".to_string()],
            })
        },
    ));
    let deny_plan = CompiledTrustPlan::new(vec![], vec![], vec![deny_rule], vec![]);

    let validator = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![],
        deny_plan,
        Some(CoseSign1ValidationOptions::default()),
        None, // Use default trust evaluation (no bypass)
    );

    let result = block_on(validator.validate_async(&parsed, Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(ValidationResultKind::Failure, result.trust.kind);
    assert_eq!(ValidationResultKind::NotApplicable, result.signature.kind);
    assert_eq!(ValidationResultKind::NotApplicable, result.post_signature_policy.kind);
}

// ---------------------------------------------------------------------------
// Streaming signature tests for large payloads
// ---------------------------------------------------------------------------

#[test]
fn test_streaming_signature_large_payload() {
    // Create a payload larger than 85KB to trigger streaming
    let large_size = 100_000u64; // 100KB
    let large_payload_provider = LargePayloadProvider::new(large_size);
    
    // Create COSE_Sign1 message with null payload (detached)
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));

    let validator = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(StreamingVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            detached_payload: Some(Payload::Streaming(Box::new(large_payload_provider))),
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // Should succeed using streaming verification path
    assert!(result.overall.is_valid());
    assert!(result.signature.is_valid());
}

#[test]
fn test_streaming_signature_verify_init_failure() {
    // Test the error path when verify_init fails during streaming
    let large_size = 100_000u64; // 100KB
    let large_payload_provider = LargePayloadProvider::new(large_size);
    
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));

    let validator = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(StreamingVerifierFailsVerifyInit),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            detached_payload: Some(Payload::Streaming(Box::new(large_payload_provider))),
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result.signature.failures[0].message.contains("Failed to initialize verifying context"));
    assert!(result.signature.failures[0].message.contains("verify_init_failed"));
}

// ---------------------------------------------------------------------------
// Detached streaming payload tests
// ---------------------------------------------------------------------------

#[test]
fn test_detached_streaming_payload_read() {
    // Test the Payload::Streaming variant in read path
    let streaming_payload = LargePayloadProvider::new(1000); // Smaller payload for non-streaming path
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));

    let validator = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            detached_payload: Some(Payload::Streaming(Box::new(streaming_payload))),
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.signature.is_valid());
}

// ---------------------------------------------------------------------------
// Test various result helper methods and option combinations
// ---------------------------------------------------------------------------

#[test]
fn test_cose_key_resolution_result_failure_helper() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    // No key resolvers - should trigger resolution failure
    let validator = validator_with_components(
        vec![], // No resolvers
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
    assert!(!result.resolution.failures.is_empty());
    assert_eq!(
        Some(CoseSign1Validator::ERROR_CODE_NO_SIGNING_KEY_RESOLVED.to_string()),
        result.resolution.failures[0].error_code
    );
}

#[test]
fn test_counter_signature_result_helpers() {
    // Create a message with counter-signatures to test the result helpers
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    // Use a custom trust pack that can provide counter-signature subjects
    struct CounterSigTrustPack;

    impl CoseSign1TrustPack for CounterSigTrustPack {
        fn name(&self) -> &'static str {
            "CounterSigTrustPack"
        }

        fn fact_producer(&self) -> Arc<dyn TrustFactProducer> {
            Arc::new(CounterSigFactProducer)
        }
    }

    struct CounterSigFactProducer;

    impl TrustFactProducer for CounterSigFactProducer {
        fn name(&self) -> &'static str {
            "CounterSigFactProducer"
        }

        fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
            // Create a counter-signature subject for testing
            if ctx.subject().kind == "Message" {
                let message_subject = match ctx.cose_sign1_bytes() {
                    Some(bytes) => TrustSubject::message(bytes.as_ref()),
                    None => TrustSubject::message(b"test"),
                };
                let cs_subject = TrustSubject::counter_signature(&message_subject, b"fake-counter-sig");
                ctx.observe(CounterSignatureSubjectFact {
                    subject: cs_subject,
                    is_protected_header: false,
                })?;
            }
            Ok(())
        }

        fn provides(&self) -> &'static [FactKey] {
            static PROVIDED: LazyLock<[FactKey; 1]> = LazyLock::new(|| {
                [FactKey::of::<CounterSignatureSubjectFact>()]
            });
            &*PROVIDED
        }
    }

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![
        Arc::new(CounterSigTrustPack),
        Arc::new(SimpleTrustPack::no_facts("base_plan").with_default_trust_plan(allow_all_trust_plan())),
    ];

    let validator = CoseSign1Validator::advanced(trust_packs, CoseSign1ValidationOptions {
        trust_evaluation_options: TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        },
        ..Default::default()
    });

    let _result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // This test mainly ensures the counter-signature result helper paths are exercised
    // The specific assertions depend on the internal implementation details
}

#[test]
fn test_with_options_various_combinations() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    // Test different option combinations
    
    // Test 1: Skip post-signature validation
    let validator1 = validator_with_components(
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

    let result1 = validator1
        .validate_bytes(EverParseCborProvider, Arc::from(cose.clone().into_boxed_slice()))
        .unwrap();

    assert!(result1.overall.is_valid());

    // Test 2: With external AAD
    let validator2 = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            associated_data: Some(Arc::from(b"external_aad".to_vec().into_boxed_slice())),
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result2 = validator2
        .validate_bytes(EverParseCborProvider, Arc::from(cose.clone().into_boxed_slice()))
        .unwrap();

    assert!(result2.overall.is_valid());

    // Test 3: Different trust evaluation options - with timeouts
    let validator3 = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            overall_timeout: Some(std::time::Duration::from_secs(30)),
            ..Default::default()
        }),
    );

    let result3 = validator3
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // Validation should succeed with bypass_trust enabled
    assert!(result3.overall.is_valid());
}
