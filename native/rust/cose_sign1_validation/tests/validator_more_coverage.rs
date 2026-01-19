// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use cose_sign1_validation_trust::{
    plan::CompiledTrustPlan,
    policy::TrustPolicyBuilder,
    rules::{FnRule, TrustRuleRef},
    CoseSign1ParsedMessage, TrustDecision, TrustEvaluationOptions,
};
use std::future::Future;
use std::io::{Cursor, Read};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use tinycbor::{Encode, Encoder};

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
    // SAFETY: we will not move fut after pin.
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };

    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn encode_protected_alg(alg: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 64];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(1).unwrap();
    (1i64).encode(&mut enc).unwrap();
    alg.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_empty_map_bytes() -> Vec<u8> {
    let mut buf = vec![0u8; 16];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(0).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn build_cose_sign1_bytes(payload: Option<&[u8]>, protected_bytes: &[u8]) -> Vec<u8> {
    let payload_len = payload.map(|p| p.len()).unwrap_or(0);
    let mut buf = vec![0u8; protected_bytes.len() + payload_len + 256];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();
    protected_bytes.encode(&mut enc).unwrap();
    enc.map(0).unwrap();

    match payload {
        Some(p) => p.encode(&mut enc).unwrap(),
        None => {
            let none: Option<&[u8]> = None;
            none.encode(&mut enc).unwrap();
        }
    }

    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn allow_all_trust_plan() -> cose_sign1_validation_trust::plan::CompiledTrustPlan {
    TrustPolicyBuilder::new().build().compile()
}

fn validator_with_components(
    signing_key_resolvers: Vec<Arc<dyn SigningKeyResolver>>,
    post_signature_validators: Vec<Arc<dyn PostSignatureValidator>>,
    trust_plan: CompiledTrustPlan,
    options: Option<CoseSign1ValidationOptions>,
    trust_evaluation_options: Option<TrustEvaluationOptions>,
) -> CoseSign1Validator {
    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();

    if !signing_key_resolvers.is_empty() {
        let resolver_pack = signing_key_resolvers.into_iter().fold(
            SimpleTrustPack::no_facts("test_signing_key_resolvers"),
            |pack, resolver| pack.with_signing_key_resolver(resolver),
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

    // Provide the supplied plan as the default trust plan so we can initialize via trust packs.
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("test_trust_plan").with_default_trust_plan(trust_plan),
    ));

    let mut merged_options = options.unwrap_or_default();
    if let Some(trust_evaluation_options) = trust_evaluation_options {
        merged_options.trust_evaluation_options = trust_evaluation_options;
    }

    CoseSign1Validator::advanced(trust_packs, merged_options)
}

fn deny_trust_plan_empty_reasons() -> CompiledTrustPlan {
    let rule: TrustRuleRef = Arc::new(FnRule::new(
        "deny_empty",
        |_e: &cose_sign1_validation_trust::facts::TrustFactEngine,
         _s: &cose_sign1_validation_trust::subject::TrustSubject|
         -> Result<TrustDecision, cose_sign1_validation_trust::error::TrustError> {
            Ok(TrustDecision {
                is_trusted: false,
                reasons: Vec::new(),
            })
        },
    ));
    CompiledTrustPlan::new(vec![], vec![], vec![rule], vec![])
}

fn deny_trust_plan_with_reason() -> CompiledTrustPlan {
    let rule: TrustRuleRef = Arc::new(FnRule::new(
        "deny_with_reason",
        |_e: &cose_sign1_validation_trust::facts::TrustFactEngine,
         _s: &cose_sign1_validation_trust::subject::TrustSubject|
         -> Result<TrustDecision, cose_sign1_validation_trust::error::TrustError> {
            Ok(TrustDecision {
                is_trusted: false,
                reasons: vec!["not trusted".to_string()],
            })
        },
    ));
    CompiledTrustPlan::new(vec![], vec![], vec![rule], vec![])
}

fn allow_trust_plan_with_audit() -> CompiledTrustPlan {
    let rule: TrustRuleRef = Arc::new(FnRule::new(
        "allow_with_audit",
        |_e: &cose_sign1_validation_trust::facts::TrustFactEngine,
         _s: &cose_sign1_validation_trust::subject::TrustSubject|
         -> Result<TrustDecision, cose_sign1_validation_trust::error::TrustError> {
            Ok(TrustDecision::trusted_reason("ok"))
        },
    ));
    CompiledTrustPlan::new(vec![], vec![], vec![rule], vec![])
}

struct StaticKeyResolver {
    key: Arc<dyn SigningKey>,
}

impl SigningKeyResolver for StaticKeyResolver {
    fn resolve(
        &self,
        _message: &CoseSign1<'_>,
        _options: &CoseSign1ValidationOptions,
    ) -> SigningKeyResolutionResult {
        SigningKeyResolutionResult::success(self.key.clone())
    }
}

struct DiagnosticsOnlyResolver;

impl SigningKeyResolver for DiagnosticsOnlyResolver {
    fn resolve(
        &self,
        _message: &CoseSign1<'_>,
        _options: &CoseSign1ValidationOptions,
    ) -> SigningKeyResolutionResult {
        SigningKeyResolutionResult {
            is_success: false,
            diagnostics: vec!["d1".to_string(), "d2".to_string()],
            ..Default::default()
        }
    }
}

struct SuccessButNoKeyResolver;

impl SigningKeyResolver for SuccessButNoKeyResolver {
    fn resolve(
        &self,
        _message: &CoseSign1<'_>,
        _options: &CoseSign1ValidationOptions,
    ) -> SigningKeyResolutionResult {
        SigningKeyResolutionResult {
            is_success: true,
            signing_key: None,
            diagnostics: vec!["success_but_missing_key".to_string()],
            ..Default::default()
        }
    }
}

struct AlwaysTrueKey;
impl SigningKey for AlwaysTrueKey {
    fn key_type(&self) -> &'static str {
        "AlwaysTrue"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Ok(true)
    }
}

struct AlwaysFalseKey;
impl SigningKey for AlwaysFalseKey {
    fn key_type(&self) -> &'static str {
        "AlwaysFalse"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Ok(false)
    }
}

struct ErrVerifyReaderKey;
impl SigningKey for ErrVerifyReaderKey {
    fn key_type(&self) -> &'static str {
        "ErrVerifyReader"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Ok(false)
    }

    fn verify_reader(
        &self,
        _alg: i64,
        _sig_structure: &mut dyn Read,
        _signature: &[u8],
    ) -> Result<bool, String> {
        Err("verify_reader_failed".to_string())
    }
}

struct FailingPostValidator;

impl PostSignatureValidator for FailingPostValidator {
    fn validate(&self, _context: &PostSignatureValidationContext<'_>) -> ValidationResult {
        ValidationResult::failure(
            "post",
            vec![ValidationFailure {
                message: "bad".to_string(),
                error_code: Some("X".to_string()),
                ..Default::default()
            }],
        )
    }
}

struct DefaultVerifyReaderKey;

impl SigningKey for DefaultVerifyReaderKey {
    fn key_type(&self) -> &'static str {
        "DefaultVerifyReader"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Ok(true)
    }
}

struct StreamingOkFalseKey;
impl SigningKey for StreamingOkFalseKey {
    fn key_type(&self) -> &'static str {
        "StreamingOkFalse"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Ok(true)
    }

    fn verify_reader(
        &self,
        _alg: i64,
        _sig_structure: &mut dyn Read,
        _signature: &[u8],
    ) -> Result<bool, String> {
        Ok(false)
    }
}

struct EofProbeStreamingKey;
impl SigningKey for EofProbeStreamingKey {
    fn key_type(&self) -> &'static str {
        "EofProbeStreaming"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Ok(true)
    }

    fn verify_reader(
        &self,
        _alg: i64,
        sig_structure: &mut dyn Read,
        _signature: &[u8],
    ) -> Result<bool, String> {
        let mut tmp = [0u8; 7];
        loop {
            let n = sig_structure
                .read(&mut tmp)
                .map_err(|e| format!("sig_structure_read_failed: {e}"))?;
            if n == 0 {
                break;
            }
        }
        // Probe the EOF/done path with an extra read.
        let n2 = sig_structure
            .read(&mut tmp)
            .map_err(|e| format!("sig_structure_read_failed: {e}"))?;
        assert_eq!(0, n2);
        Ok(true)
    }
}

struct CborLenAssertingKey {
    expected_payload_len: usize,
}

impl SigningKey for CborLenAssertingKey {
    fn key_type(&self) -> &'static str {
        "CborLenAsserting"
    }

    fn verify(&self, _alg: i64, sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        assert!(sig_structure.ends_with(&vec![0xAAu8; self.expected_payload_len]));
        Ok(true)
    }
}

struct SimpleDetachedProvider;

impl DetachedPayloadProvider for SimpleDetachedProvider {
    fn open(&self) -> Result<Box<dyn Read + Send>, String> {
        Ok(Box::new(Cursor::new(Vec::<u8>::new())))
    }
}

#[test]
fn validate_bytes_returns_cose_decode_error_on_invalid_cbor() {
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

    let err = v
        .validate_bytes(Arc::from(vec![0xA0u8].into_boxed_slice()))
        .expect_err("expected decode error");

    match err {
        CoseSign1ValidationError::CoseDecode(_) => {}
        other => panic!("expected CoseDecode, got {other:?}"),
    }
}

#[test]
fn validator_public_types_have_expected_defaults_and_helpers() {
    let _ = encode_empty_map_bytes();
    assert_eq!(
        ValidationResultKind::NotApplicable,
        ValidationResultKind::default()
    );

    let kind = ValidationResultKind::default();
    let vr = ValidationResult {
        kind,
        validator_name: "v".to_string(),
        failures: vec![],
        metadata: Default::default(),
    };
    assert!(!vr.is_valid());

    let dp = DetachedPayload::bytes(Arc::from([1u8, 2u8].as_slice()));
    let s = format!("{dp:?}");
    assert!(s.contains("DetachedPayload::Bytes"));
    assert!(s.contains("len"));

    let provider: Arc<dyn DetachedPayloadProvider> = Arc::new(SimpleDetachedProvider);
    let dp = DetachedPayload::Provider(provider.clone());
    let s = format!("{dp:?}");
    assert!(s.contains("DetachedPayload::Provider"));
    assert_eq!(None, provider.len_hint());

    let fail = SigningKeyResolutionResult::failure(Some("E".to_string()), Some("M".to_string()));
    assert!(!fail.is_success);
    assert_eq!(Some("E".to_string()), fail.error_code);
    assert_eq!(Some("M".to_string()), fail.error_message);

    let cs_fail =
        CounterSignatureResolutionResult::failure(Some("E".to_string()), Some("M".to_string()));
    assert!(!cs_fail.is_success);
    assert_eq!(Some("E".to_string()), cs_fail.error_code);
    assert_eq!(Some("M".to_string()), cs_fail.error_message);
}

#[test]
fn validate_bytes_trust_denied_with_empty_reasons_uses_default_failure_message_and_includes_audit()
{
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));

    let key: Arc<dyn SigningKey> = Arc::new(AlwaysTrueKey);
    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver { key })],
        vec![],
        deny_trust_plan_empty_reasons(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions::default()),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.trust.is_failure());
    assert_eq!(
        CoseSign1Validator::ERROR_MESSAGE_TRUST_PLAN_NOT_SATISFIED,
        result.trust.failures[0].message
    );
    assert!(result.trust.metadata.contains_key("TrustDecisionAudit"));
    assert!(result.signature.kind == ValidationResultKind::NotApplicable);
}

#[test]
fn validate_bytes_streaming_path_can_surface_default_verify_reader_read_errors() {
    struct ErrRead;
    impl Read for ErrRead {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("boom"))
        }
    }

    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));

    let provider = DetachedPayloadFnProvider::new(|| Ok(Box::new(ErrRead) as Box<dyn Read + Send>))
        .with_len_hint(u64::MAX);

    let key: Arc<dyn SigningKey> = Arc::new(DefaultVerifyReaderKey);
    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver { key })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            detached_payload: Some(DetachedPayload::Provider(Arc::new(provider))),
            associated_data: None,
            certificate_header_location: cose_sign1_validation_trust::CoseHeaderLocation::Protected,
            skip_post_signature_validation: true,
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert!(result.signature.is_failure());
    assert!(result.signature.failures[0]
        .message
        .contains("sig_structure_read_failed"));
}

#[test]
fn validate_bytes_detached_provider_empty_stream_is_missing_payload() {
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));

    // No len_hint => buffered path => empty stream triggers missing-payload error.
    let provider = DetachedPayloadFnProvider::new(|| Ok(Box::new(Cursor::new(Vec::<u8>::new()))));

    let key: Arc<dyn SigningKey> = Arc::new(AlwaysTrueKey);
    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver { key })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            detached_payload: Some(DetachedPayload::Provider(Arc::new(provider))),
            associated_data: None,
            certificate_header_location: cose_sign1_validation_trust::CoseHeaderLocation::Protected,
            skip_post_signature_validation: true,
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert!(result.signature.is_failure());
    assert_eq!(
        Some(CoseSign1Validator::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED.to_string()),
        result.signature.failures[0].error_code
    );
    assert_eq!(
        CoseSign1Validator::ERROR_MESSAGE_SIGNATURE_MISSING_PAYLOAD,
        result.signature.failures[0].message
    );
}

#[test]
fn validate_success_merges_stage_metadata_with_prefixes() {
    let cose = build_cose_sign1_bytes(Some(b"payload".as_slice()), &encode_protected_alg(-7));

    let key: Arc<dyn SigningKey> = Arc::new(AlwaysTrueKey);
    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver { key })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions {
            detached_payload: None,
            associated_data: None,
            certificate_header_location: cose_sign1_validation_trust::CoseHeaderLocation::Protected,
            skip_post_signature_validation: true,
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.overall.metadata.contains_key("Trust.BypassTrust"));
    assert!(result.overall.metadata.contains_key("Trust.TrustDecision"));
}

#[test]
fn validate_bytes_returns_cose_decode_error_when_parsed_message_invalid() {
    // protected header bytes are not a CBOR map -> from_parts fails
    let protected = b"\x01".as_slice();
    let cose = build_cose_sign1_bytes(Some(b"payload"), protected);

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueKey),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let err = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .expect_err("expected parse error");

    match err {
        CoseSign1ValidationError::CoseDecode(_) => {}
        other => panic!("expected CoseDecode, got {other:?}"),
    }
}

#[test]
fn validate_bytes_resolution_failure_includes_diagnostics_metadata() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(DiagnosticsOnlyResolver)],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
    assert!(result
        .resolution
        .metadata
        .get("Diagnostics")
        .unwrap()
        .contains("d1"));
}

#[test]
fn validate_bytes_async_success_path_runs() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueKey),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = block_on(v.validate_bytes_async(Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(ValidationResultKind::Success, result.overall.kind);
}

#[test]
fn validate_bytes_async_resolution_failure_includes_exception_diagnostics() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(DiagnosticsOnlyResolver)],
        vec![],
        allow_all_trust_plan(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = block_on(v.validate_bytes_async(Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
    let ex = result.resolution.failures[0]
        .exception
        .as_deref()
        .unwrap_or_default();
    assert!(ex.contains("d1"));
    assert!(ex.contains("d2"));
}

#[test]
fn signature_stage_returns_failure_when_verification_returns_false() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysFalseKey),
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
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
}

#[test]
fn signature_stage_detached_payload_bytes_empty_is_error() {
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));

    let opts = CoseSign1ValidationOptions {
        detached_payload: Some(DetachedPayload::Bytes(Arc::from(
            Vec::<u8>::new().into_boxed_slice(),
        ))),
        ..Default::default()
    };

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueKey),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(opts),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
}

#[test]
fn signature_stage_detached_provider_open_error_is_surface_as_failure() {
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));

    let provider = DetachedPayloadFnProvider::new(|| Err("open_failed".to_string()));

    let opts = CoseSign1ValidationOptions {
        detached_payload: Some(DetachedPayload::Provider(Arc::new(provider))),
        ..Default::default()
    };

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueKey),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(opts),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result.signature.failures[0].message.contains("open_failed"));
}

#[test]
fn signature_stage_detached_provider_read_error_is_surface_as_failure() {
    struct ErrReader;
    impl Read for ErrReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("read_failed"))
        }
    }

    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));

    let provider =
        DetachedPayloadFnProvider::new(|| Ok(Box::new(ErrReader) as Box<dyn Read + Send>));

    let opts = CoseSign1ValidationOptions {
        detached_payload: Some(DetachedPayload::Provider(Arc::new(provider))),
        ..Default::default()
    };

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueKey),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(opts),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result.signature.failures[0]
        .message
        .contains("detached_payload_read_failed"));
}

#[test]
fn signature_stage_streaming_path_handles_verify_reader_error() {
    // Use a large len_hint to force streaming path.
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));

    let payload = Arc::new(vec![0u8; 8]);
    let provider = DetachedPayloadFnProvider::new({
        let payload = payload.clone();
        move || Ok(Box::new(Cursor::new(payload.to_vec())) as Box<dyn Read + Send>)
    })
    .with_len_hint(CoseSign1Validator::LARGE_STREAM_THRESHOLD + 1);

    let opts = CoseSign1ValidationOptions {
        detached_payload: Some(DetachedPayload::Provider(Arc::new(provider))),
        ..Default::default()
    };

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(ErrVerifyReaderKey),
        })],
        vec![],
        allow_all_trust_plan(),
        Some(opts),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result.signature.failures[0]
        .message
        .contains("verify_reader_failed"));
}

#[test]
fn post_signature_stage_failure_is_propagated_to_overall() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueKey),
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

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(
        ValidationResultKind::Failure,
        result.post_signature_policy.kind
    );
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}

#[test]
fn post_signature_stage_async_path_runs() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueKey),
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

    let result = block_on(v.validate_bytes_async(Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}

struct SyncOnlyCounterSigResolver;

impl CounterSignatureResolver for SyncOnlyCounterSigResolver {
    fn name(&self) -> &'static str {
        "SyncOnlyCounterSigResolver"
    }

    fn resolve(&self, _message: &CoseSign1ParsedMessage) -> CounterSignatureResolutionResult {
        CounterSignatureResolutionResult::failure(Some("X".to_string()), Some("nope".to_string()))
    }
}

#[test]
fn counter_signature_resolver_default_resolve_async_delegates_to_sync() {
    let msg = CoseSign1ParsedMessage::from_parts(
        &encode_empty_map_bytes(),
        &encode_empty_map_bytes(),
        Some(b"p"),
        b"sig",
    )
    .unwrap();
    let r = SyncOnlyCounterSigResolver;
    let out = block_on(r.resolve_async(&msg));
    assert!(!out.is_success);
    assert_eq!(Some("X".to_string()), out.error_code);
}

#[test]
fn validate_bytes_async_trust_denied_short_circuits_signature_and_post() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysTrueKey),
        })],
        vec![],
        deny_trust_plan_with_reason(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions::default()),
    );

    let result = block_on(v.validate_bytes_async(Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(ValidationResultKind::Failure, result.trust.kind);
    assert_eq!(ValidationResultKind::NotApplicable, result.signature.kind);
    assert_eq!(
        ValidationResultKind::NotApplicable,
        result.post_signature_policy.kind
    );
}

#[test]
fn validate_bytes_async_signature_failure_path_is_exercised() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(AlwaysFalseKey),
        })],
        vec![],
        allow_trust_plan_with_audit(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions::default()),
    );

    let result = block_on(v.validate_bytes_async(Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        ValidationResultKind::NotApplicable,
        result.post_signature_policy.kind
    );
}

#[test]
fn validate_bytes_resolution_success_but_missing_key_is_failure() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(SuccessButNoKeyResolver)],
        vec![],
        allow_trust_plan_with_audit(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions::default()),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
}

#[test]
fn validate_bytes_async_resolution_success_but_missing_key_is_failure() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), &encode_protected_alg(-7));

    let v = validator_with_components(
        vec![Arc::new(SuccessButNoKeyResolver)],
        vec![],
        allow_trust_plan_with_audit(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions::default()),
    );

    let result = block_on(v.validate_bytes_async(Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
}

#[test]
fn signature_stage_streaming_path_fails_when_alg_missing() {
    // No alg in protected header.
    let protected = encode_empty_map_bytes();
    let cose = build_cose_sign1_bytes(None, &protected);

    let provider = DetachedPayloadFnProvider::new(|| {
        Ok(Box::new(Cursor::new(vec![0u8; 8])) as Box<dyn Read + Send>)
    })
    .with_len_hint(CoseSign1Validator::LARGE_STREAM_THRESHOLD + 1);

    let opts = CoseSign1ValidationOptions {
        detached_payload: Some(DetachedPayload::Provider(Arc::new(provider))),
        ..Default::default()
    };

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(DefaultVerifyReaderKey),
        })],
        vec![],
        allow_trust_plan_with_audit(),
        Some(opts),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        Some(CoseSign1Validator::ERROR_CODE_NO_APPLICABLE_SIGNATURE_VALIDATOR.to_string()),
        result.signature.failures[0].error_code
    );
}

#[test]
fn signature_stage_streaming_path_surfaces_provider_open_error() {
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));
    let provider = DetachedPayloadFnProvider::new(|| Err("open_failed".to_string()))
        .with_len_hint(CoseSign1Validator::LARGE_STREAM_THRESHOLD + 1);

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(DefaultVerifyReaderKey),
        })],
        vec![],
        allow_trust_plan_with_audit(),
        Some(CoseSign1ValidationOptions {
            detached_payload: Some(DetachedPayload::Provider(Arc::new(provider))),
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result.signature.failures[0].message.contains("open_failed"));
}

#[test]
fn signature_stage_streaming_path_ok_false_is_failure() {
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));
    let provider = DetachedPayloadFnProvider::new(|| {
        Ok(Box::new(Cursor::new(vec![0u8; 8])) as Box<dyn Read + Send>)
    })
    .with_len_hint(CoseSign1Validator::LARGE_STREAM_THRESHOLD + 1);

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(StreamingOkFalseKey),
        })],
        vec![],
        allow_trust_plan_with_audit(),
        Some(CoseSign1ValidationOptions {
            detached_payload: Some(DetachedPayload::Provider(Arc::new(provider))),
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
}

#[test]
fn signature_stage_streaming_path_exercises_sig_structure_reader_eof_done_branch() {
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));
    let provider = DetachedPayloadFnProvider::new(|| {
        Ok(Box::new(Cursor::new(vec![0u8; 8])) as Box<dyn Read + Send>)
    })
    .with_len_hint(CoseSign1Validator::LARGE_STREAM_THRESHOLD + 1);

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(EofProbeStreamingKey),
        })],
        vec![],
        allow_trust_plan_with_audit(),
        Some(CoseSign1ValidationOptions {
            detached_payload: Some(DetachedPayload::Provider(Arc::new(provider))),
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert_eq!(ValidationResultKind::Success, result.signature.kind);
}

#[test]
fn build_sig_structure_covers_u8_and_u16_bstr_len_encodings() {
    // 24 => CBOR bstr with uint8 length.
    let payload_24 = vec![0xAAu8; 24];
    let cose_24 = build_cose_sign1_bytes(Some(payload_24.as_slice()), &encode_protected_alg(-7));
    let v_24 = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(CborLenAssertingKey {
                expected_payload_len: 24,
            }),
        })],
        vec![],
        allow_trust_plan_with_audit(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );
    let r_24 = v_24
        .validate_bytes(Arc::from(cose_24.into_boxed_slice()))
        .unwrap();
    assert_eq!(ValidationResultKind::Success, r_24.signature.kind);

    // 256 => CBOR bstr with uint16 length.
    let payload_256 = vec![0xAAu8; 256];
    let cose_256 = build_cose_sign1_bytes(Some(payload_256.as_slice()), &encode_protected_alg(-7));
    let v_256 = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(CborLenAssertingKey {
                expected_payload_len: 256,
            }),
        })],
        vec![],
        allow_trust_plan_with_audit(),
        Some(CoseSign1ValidationOptions::default()),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );
    let r_256 = v_256
        .validate_bytes(Arc::from(cose_256.into_boxed_slice()))
        .unwrap();
    assert_eq!(ValidationResultKind::Success, r_256.signature.kind);
}

#[test]
fn streaming_sig_structure_prefix_covers_u64_bstr_len_encoding_without_allocating() {
    // Use a payload len that forces the u64-length encoding branch.
    let huge = (u32::MAX as u64) + 1;
    let cose = build_cose_sign1_bytes(None, &encode_protected_alg(-7));
    let provider = DetachedPayloadFnProvider::new(|| {
        Ok(Box::new(Cursor::new(vec![0u8; 1])) as Box<dyn Read + Send>)
    })
    .with_len_hint(huge);

    let v = validator_with_components(
        vec![Arc::new(StaticKeyResolver {
            key: Arc::new(DefaultVerifyReaderKey),
        })],
        vec![],
        allow_trust_plan_with_audit(),
        Some(CoseSign1ValidationOptions {
            detached_payload: Some(DetachedPayload::Provider(Arc::new(provider))),
            ..Default::default()
        }),
        Some(TrustEvaluationOptions {
            bypass_trust: true,
            ..Default::default()
        }),
    );

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert_eq!(ValidationResultKind::Success, result.signature.kind);
}
