// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests targeting uncovered code paths in `validator.rs`, focusing on:
//! - `validate_async()` (lines 648-652)
//! - Missing detached payload (lines 1456-1459)
//! - sig_structure build failure (lines 1491-1495)
//! - Signature verification error (lines 1513-1517)
//! - No applicable signature validator / missing alg (lines 1476-1481)
//! - Counter-signature fact resolution error paths (lines 1305, 1314)

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::error::PayloadError;
use cose_sign1_primitives::sig_structure::SizedRead;
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::{
    error::TrustError,
    facts::{FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer},
    plan::CompiledTrustPlan,
    policy::TrustPolicyBuilder,
    rules::{FnRule, TrustRuleRef},
    subject::TrustSubject,
    TrustDecision, TrustEvaluationOptions,
};
use cose_sign1_validation_test_utils::SimpleTrustPack;
use std::future::Future;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::LazyLock;
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

// ---------------------------------------------------------------------------
// Mock CryptoVerifier implementations
// ---------------------------------------------------------------------------

struct AlwaysTrueVerifier;
impl CryptoVerifier for AlwaysTrueVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

/// Verifier whose `verify` returns `Err` (not just `Ok(false)`).
struct ErrorVerifyVerifier;
impl CryptoVerifier for ErrorVerifyVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Err(CryptoError::VerificationFailed("verify_boom".to_string()))
    }
}

/// Verifier whose `verify` returns `Ok(false)`.
struct AlwaysFalseVerifier;
impl CryptoVerifier for AlwaysFalseVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// Mock resolvers and validators
// ---------------------------------------------------------------------------

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

fn validator_with_extra_trust_packs(
    mut extra_trust_packs: Vec<Arc<dyn CoseSign1TrustPack>>,
    signing_key_resolvers: Vec<Arc<dyn CoseKeyResolver>>,
    post_signature_validators: Vec<Arc<dyn PostSignatureValidator>>,
    trust_plan: CompiledTrustPlan,
    options: Option<CoseSign1ValidationOptions>,
    trust_evaluation_options: Option<TrustEvaluationOptions>,
) -> CoseSign1Validator {
    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();

    trust_packs.append(&mut extra_trust_packs);

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
// Counter-signature bypass helpers (for testing fact resolution error paths)
// ---------------------------------------------------------------------------

/// A trust pack that produces counter-signature facts that will trigger
/// the error path in `signature_bypass_metadata_from_counter_signatures`
/// when the fact engine cannot find the expected fact types.
#[derive(Clone)]
struct FailingCounterSigFactPack;

impl CoseSign1TrustPack for FailingCounterSigFactPack {
    fn name(&self) -> &'static str {
        "FailingCounterSigFactPack"
    }

    fn fact_producer(&self) -> Arc<dyn TrustFactProducer> {
        Arc::new(FailingCounterSigFactProducer)
    }
}

/// Producer that registers CounterSignatureSubjectFact but deliberately
/// does NOT produce CounterSignatureEnvelopeIntegrityFact for the
/// counter-signature subject, so `get_facts` on integrity will hit
/// the error/empty path (line 1314).
#[derive(Clone)]
struct FailingCounterSigFactProducer;

impl TrustFactProducer for FailingCounterSigFactProducer {
    fn name(&self) -> &'static str {
        "FailingCounterSigFactProducer"
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.subject().kind == "Message" {
            let message_subject = match ctx.cose_sign1_bytes() {
                Some(bytes) => TrustSubject::message(bytes.as_ref()),
                None => TrustSubject::message(b"seed"),
            };

            let cs_subject = TrustSubject::counter_signature(&message_subject, b"fake-cs");
            ctx.observe(CounterSignatureSubjectFact {
                subject: cs_subject,
                is_protected_header: false,
            })?;
        }

        // Intentionally do NOT produce CounterSignatureEnvelopeIntegrityFact
        // for the CounterSignature subject so the integrity fact lookup fails.

        for k in self.provides() {
            ctx.mark_produced(*k);
        }
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        static PROVIDED: LazyLock<[FactKey; 2]> = LazyLock::new(|| {
            [
                FactKey::of::<CounterSignatureSubjectFact>(),
                FactKey::of::<CounterSignatureEnvelopeIntegrityFact>(),
            ]
        });
        &*PROVIDED
    }
}

// ===========================================================================
// Test: validate_async() with a simple mock validator (lines 648-652)
// ===========================================================================

#[test]
fn validate_async_success_path() {
    let cose = build_cose_sign1_bytes(Some(b"hello"), &encode_protected_alg(-7));
    let parsed = CoseSign1Message::parse(&cose).unwrap();

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

    let result = block_on(v.validate_async(&parsed, Arc::from(cose.into_boxed_slice()))).unwrap();
    assert!(result.overall.is_valid());
    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid());
    assert!(result.signature.is_valid());
}

#[test]
fn validate_async_signature_failure_path() {
    let cose = build_cose_sign1_bytes(Some(b"hello"), &encode_protected_alg(-7));
    let parsed = CoseSign1Message::parse(&cose).unwrap();

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysFalseVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = block_on(v.validate_async(&parsed, Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        ValidationResultKind::NotApplicable,
        result.post_signature_policy.kind
    );
}

// ===========================================================================
// Test: Missing detached payload (lines 1456-1459)
// ===========================================================================

#[test]
fn signature_stage_no_payload_and_no_detached_returns_missing_payload() {
    // Build message with nil payload and NO detached payload option.
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            detached_payload: None,
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

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        Some(CoseSign1Validator::ERROR_CODE_SIGNATURE_MISSING_PAYLOAD.to_string()),
        result.signature.failures[0].error_code
    );
    assert_eq!(
        CoseSign1Validator::ERROR_MESSAGE_SIGNATURE_MISSING_PAYLOAD,
        result.signature.failures[0].message
    );
}

#[test]
fn validate_async_no_payload_and_no_detached_returns_missing_payload() {
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));
    let parsed = CoseSign1Message::parse(&cose).unwrap();

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            detached_payload: None,
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = block_on(v.validate_async(&parsed, Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        Some(CoseSign1Validator::ERROR_CODE_SIGNATURE_MISSING_PAYLOAD.to_string()),
        result.signature.failures[0].error_code
    );
}

// ===========================================================================
// Test: No applicable signature validator / missing alg (lines 1476-1481)
// ===========================================================================

#[test]
fn signature_stage_no_alg_in_protected_header_returns_no_applicable_validator() {
    // Protected header with empty map (no algorithm).
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

// ===========================================================================
// Test: verify_sig_structure returns Err (lines 1513-1517)
// ===========================================================================

#[test]
fn signature_stage_verify_sig_structure_error_returns_failure() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(ErrorVerifyVerifier),
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
        Some(CoseSign1Validator::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED.to_string()),
        result.signature.failures[0].error_code
    );
    assert!(result.signature.failures[0].message.contains("verify_boom"));
}

#[test]
fn validate_async_verify_sig_structure_error_returns_failure() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));
    let parsed = CoseSign1Message::parse(&cose).unwrap();

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(ErrorVerifyVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = block_on(v.validate_async(&parsed, Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result.signature.failures[0].message.contains("verify_boom"));
}

// ===========================================================================
// Test: Counter-signature fact resolution error paths (lines 1305, 1314)
// ===========================================================================

#[test]
fn counter_signature_integrity_fact_missing_returns_none_bypass() {
    // When resolution fails AND the counter-sig fact producer does not
    // emit integrity facts, the bypass metadata is absent and validation
    // falls through to resolution failure.
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_extra_trust_packs(
        vec![Arc::new(FailingCounterSigFactPack)],
        vec![], // no key resolvers -> resolution fails
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

    // Resolution fails, no bypass => overall failure.
    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}

// ===========================================================================
// Test: validate_async with resolution failure (no resolvers)
// ===========================================================================

#[test]
fn validate_async_no_resolvers_resolution_fails() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));
    let parsed = CoseSign1Message::parse(&cose).unwrap();

    let v = validator_with_components(
        vec![],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = block_on(v.validate_async(&parsed, Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
    assert_eq!(
        Some(CoseSign1Validator::ERROR_CODE_NO_SIGNING_KEY_RESOLVED.to_string()),
        result.resolution.failures[0].error_code
    );
}

// ===========================================================================
// Test: validate_async with trust denied
// ===========================================================================

#[test]
fn validate_async_trust_denied_short_circuits() {
    let deny_plan = {
        let rule: TrustRuleRef = Arc::new(FnRule::new(
            "deny",
            |_e: &TrustFactEngine, _s: &TrustSubject| -> Result<TrustDecision, TrustError> {
                Ok(TrustDecision {
                    is_trusted: false,
                    reasons: vec!["denied".to_string()],
                })
            },
        ));
        CompiledTrustPlan::new(vec![], vec![], vec![rule], vec![])
    };

    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));
    let parsed = CoseSign1Message::parse(&cose).unwrap();

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![],
        deny_plan,
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions::default()),
    );

    let result = block_on(v.validate_async(&parsed, Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(ValidationResultKind::Failure, result.trust.kind);
    assert_eq!(ValidationResultKind::NotApplicable, result.signature.kind);
    assert_eq!(
        ValidationResultKind::NotApplicable,
        result.post_signature_policy.kind
    );
}

// ===========================================================================
// Test: validate_async with post-signature failure
// ===========================================================================

struct FailingPostValidator;

impl PostSignatureValidator for FailingPostValidator {
    fn validate(&self, _context: &PostSignatureValidationContext<'_>) -> ValidationResult {
        ValidationResult::failure(
            "post",
            vec![ValidationFailure {
                message: "post_failed".to_string(),
                error_code: Some("POST_ERR".to_string()),
                ..Default::default()
            }],
        )
    }
}

#[test]
fn validate_async_post_signature_failure() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));
    let parsed = CoseSign1Message::parse(&cose).unwrap();

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![Arc::new(FailingPostValidator)],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            skip_post_signature_validation: false,
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = block_on(v.validate_async(&parsed, Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(
        ValidationResultKind::Failure,
        result.post_signature_policy.kind
    );
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}

// ===========================================================================
// Test: Detached empty bytes provider triggers missing payload via read path
// (lines 1619-1622)
// ===========================================================================

#[test]
fn detached_provider_empty_stream_triggers_missing_payload_error() {
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));

    struct EmptyPayloadProvider;
    impl StreamingPayload for EmptyPayloadProvider {
        fn size(&self) -> u64 {
            0
        }
        fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
            Ok(Box::new(Cursor::new(Vec::<u8>::new())) as Box<dyn SizedRead + Send>)
        }
    }

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            detached_payload: Some(Payload::Streaming(Box::new(EmptyPayloadProvider))),
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

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result.signature.failures[0]
        .message
        .contains("detached content"));
}
