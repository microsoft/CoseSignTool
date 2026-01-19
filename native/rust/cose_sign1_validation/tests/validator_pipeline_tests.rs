// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use cose_sign1_validation_trust::policy::TrustPolicyBuilder;
use std::io::{Cursor, Read};
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

fn encode_protected_alg(alg: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 64];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(1).unwrap();
    (1i64).encode(&mut enc).unwrap(); // alg header
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

fn build_cose_sign1_bytes(payload: Option<&[u8]>, alg: Option<i64>) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header bstr
    let protected = alg
        .map(encode_protected_alg)
        .unwrap_or_else(encode_empty_map_bytes);
    protected.as_slice().encode(&mut enc).unwrap();

    // unprotected header map
    enc.map(0).unwrap();

    // payload: bstr or null
    match payload {
        Some(p) => p.encode(&mut enc).unwrap(),
        None => {
            // COSE detached payload is represented as CBOR null.
            // tinycbor encodes Option::None as null.
            let none: Option<&[u8]> = None;
            none.encode(&mut enc).unwrap();
        }
    }

    // signature (opaque bytes)
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn allow_all_trust_plan() -> cose_sign1_validation_trust::plan::CompiledTrustPlan {
    // We bypass trust in most tests, so an empty policy is fine.
    TrustPolicyBuilder::new().build().compile()
}

fn validator_with(
    resolver: Option<Arc<dyn SigningKeyResolver>>,
    post_validators: Vec<Arc<dyn PostSignatureValidator>>,
    configure: impl FnOnce(&mut CoseSign1ValidationOptions),
) -> CoseSign1Validator {
    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();

    if let Some(resolver) = resolver {
        trust_packs.push(Arc::new(
            SimpleTrustPack::no_facts("test_signing_key_resolver")
                .with_signing_key_resolver(resolver),
        ));
    }

    if !post_validators.is_empty() {
        let post_pack = post_validators.into_iter().fold(
            SimpleTrustPack::no_facts("test_post_signature_validators"),
            |pack, validator| pack.with_post_signature_validator(validator),
        );
        trust_packs.push(Arc::new(post_pack));
    }

    // Provide an explicit allow-all plan so these pipeline tests don't fail due to trust.
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust").with_default_trust_plan(allow_all_trust_plan()),
    ));

    CoseSign1Validator::new(trust_packs).with_options(configure)
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

struct ErrorKey;
impl SigningKey for ErrorKey {
    fn key_type(&self) -> &'static str {
        "ErrorKey"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Err("boom".to_string())
    }
}

struct StreamingTrueKey;
impl SigningKey for StreamingTrueKey {
    fn key_type(&self) -> &'static str {
        "StreamingTrue"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        // If streaming isn't used, we want to fail this test.
        Ok(false)
    }

    fn verify_reader(
        &self,
        _alg: i64,
        sig_structure: &mut dyn Read,
        _signature: &[u8],
    ) -> Result<bool, String> {
        let mut buf = Vec::new();
        sig_structure
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        if buf.is_empty() {
            return Err("empty".to_string());
        }
        Ok(true)
    }
}

#[test]
fn validation_result_not_applicable_reason_is_trimmed() {
    let r1 = ValidationResult::not_applicable("v", None);
    assert!(!r1
        .metadata
        .contains_key(ValidationResult::METADATA_REASON_KEY));

    let r2 = ValidationResult::not_applicable("v", Some("   "));
    assert!(!r2
        .metadata
        .contains_key(ValidationResult::METADATA_REASON_KEY));

    let r3 = ValidationResult::not_applicable("v", Some("because"));
    assert_eq!(
        Some("because".to_string()),
        r3.metadata
            .get(ValidationResult::METADATA_REASON_KEY)
            .cloned()
    );
}

#[test]
fn signing_key_default_verify_reader_buffers_and_calls_verify() {
    struct CapturingKey(std::sync::Mutex<Vec<u8>>);

    impl SigningKey for CapturingKey {
        fn key_type(&self) -> &'static str {
            "Capturing"
        }

        fn verify(
            &self,
            _alg: i64,
            sig_structure: &[u8],
            _signature: &[u8],
        ) -> Result<bool, String> {
            self.0.lock().unwrap().extend_from_slice(sig_structure);
            Ok(true)
        }
    }

    let key = CapturingKey(std::sync::Mutex::new(Vec::new()));
    let mut reader = Cursor::new(b"abc".to_vec());
    let ok = key.verify_reader(-7, &mut reader, b"sig").unwrap();
    assert!(ok);
    assert_eq!(b"abc".to_vec(), *key.0.lock().unwrap());
}

#[test]
fn validate_bytes_resolution_fails_when_no_resolvers() {
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust").with_default_trust_plan(allow_all_trust_plan()),
    )];

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1_bytes(Some(b"payload"), Some(-7));
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
    assert_eq!(ValidationResultKind::NotApplicable, result.trust.kind);
    assert_eq!(ValidationResultKind::NotApplicable, result.signature.kind);
    assert_eq!(
        ValidationResultKind::NotApplicable,
        result.post_signature_policy.kind
    );
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}

#[test]
fn validate_bytes_signature_missing_payload_when_detached_and_no_payload_provided() {
    let key: Arc<dyn SigningKey> = Arc::new(AlwaysTrueKey);
    let resolver: Arc<dyn SigningKeyResolver> = Arc::new(StaticKeyResolver { key });

    let v = validator_with(
        Some(resolver),
        vec![],
        |o| {
            o.detached_payload = None;
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1_bytes(None, Some(-7));
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        Some(CoseSign1Validator::ERROR_CODE_SIGNATURE_MISSING_PAYLOAD.to_string()),
        result
            .signature
            .failures
            .first()
            .and_then(|f| f.error_code.clone())
    );
}

#[test]
fn validate_bytes_signature_errors_when_alg_missing() {
    let key: Arc<dyn SigningKey> = Arc::new(AlwaysTrueKey);
    let resolver: Arc<dyn SigningKeyResolver> = Arc::new(StaticKeyResolver { key });

    let v = validator_with(
        Some(resolver),
        vec![],
        |o| {
            o.detached_payload = Some(DetachedPayload::bytes(Arc::from(
                b"p".to_vec().into_boxed_slice(),
            )));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1_bytes(None, None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        Some(CoseSign1Validator::ERROR_CODE_NO_APPLICABLE_SIGNATURE_VALIDATOR.to_string()),
        result
            .signature
            .failures
            .first()
            .and_then(|f| f.error_code.clone())
    );
}

#[test]
fn validate_bytes_embedded_payload_signature_success_and_failure_paths() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), Some(-7));

    // success
    {
        let key: Arc<dyn SigningKey> = Arc::new(AlwaysTrueKey);
        let resolver: Arc<dyn SigningKeyResolver> = Arc::new(StaticKeyResolver { key });

        let v = validator_with(
            Some(resolver),
            vec![],
            |o| {
                o.trust_evaluation_options.bypass_trust = true;
            },
        );
        let result = v
            .validate_bytes(Arc::from(cose.clone().into_boxed_slice()))
            .unwrap();
        assert_eq!(ValidationResultKind::Success, result.signature.kind);
        assert_eq!(ValidationResultKind::Success, result.overall.kind);
    }

    // verification returns false
    {
        let key: Arc<dyn SigningKey> = Arc::new(AlwaysFalseKey);
        let resolver: Arc<dyn SigningKeyResolver> = Arc::new(StaticKeyResolver { key });

        let v = validator_with(
            Some(resolver),
            vec![],
            |o| {
                o.trust_evaluation_options.bypass_trust = true;
            },
        );
        let result = v
            .validate_bytes(Arc::from(cose.clone().into_boxed_slice()))
            .unwrap();
        assert_eq!(ValidationResultKind::Failure, result.signature.kind);
        assert_eq!(
            Some(CoseSign1Validator::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED.to_string()),
            result
                .signature
                .failures
                .first()
                .and_then(|f| f.error_code.clone())
        );
    }

    // verification errors
    {
        let key: Arc<dyn SigningKey> = Arc::new(ErrorKey);
        let resolver: Arc<dyn SigningKeyResolver> = Arc::new(StaticKeyResolver { key });

        let v = validator_with(
            Some(resolver),
            vec![],
            |o| {
                o.trust_evaluation_options.bypass_trust = true;
            },
        );
        let result = v
            .validate_bytes(Arc::from(cose.clone().into_boxed_slice()))
            .unwrap();
        assert_eq!(ValidationResultKind::Failure, result.signature.kind);
        assert_eq!(
            Some(CoseSign1Validator::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED.to_string()),
            result
                .signature
                .failures
                .first()
                .and_then(|f| f.error_code.clone())
        );
    }
}

#[test]
fn validate_bytes_streaming_path_uses_verify_reader_for_large_detached_payload() {
    let large = vec![0x41u8; (CoseSign1Validator::LARGE_STREAM_THRESHOLD + 1) as usize];
    let large_len = large.len() as u64;
    let provider_bytes = Arc::new(large);

    let provider = Arc::new(
        DetachedPayloadFnProvider::new({
            let provider_bytes = provider_bytes.clone();
            move || {
                Ok(Box::new(Cursor::new(provider_bytes.as_ref().to_vec())) as Box<dyn Read + Send>)
            }
        })
        .with_len_hint(large_len),
    );

    let key: Arc<dyn SigningKey> = Arc::new(StreamingTrueKey);
    let resolver: Arc<dyn SigningKeyResolver> = Arc::new(StaticKeyResolver { key });

    let v = validator_with(
        Some(resolver),
        vec![],
        |o| {
            o.detached_payload = Some(DetachedPayload::Provider(provider));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1_bytes(None, Some(-7));
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Success, result.signature.kind);
    assert_eq!(
        Some("StreamingTrue".to_string()),
        result
            .signature
            .metadata
            .get(CoseSign1Validator::METADATA_KEY_SELECTED_VALIDATOR)
            .cloned()
    );
}

#[test]
fn validate_bytes_post_signature_skip_honors_option() {
    struct FailValidator;

    impl PostSignatureValidator for FailValidator {
        fn validate(&self, _context: &PostSignatureValidationContext<'_>) -> ValidationResult {
            ValidationResult::failure_message("post", "nope", Some("X"))
        }
    }

    let cose = build_cose_sign1_bytes(Some(b"payload"), Some(-7));

    // not skipped => fails overall
    {
        let key: Arc<dyn SigningKey> = Arc::new(AlwaysTrueKey);
        let resolver: Arc<dyn SigningKeyResolver> = Arc::new(StaticKeyResolver { key });

        let v = validator_with(
            Some(resolver),
            vec![Arc::new(FailValidator)],
            |o| {
                o.skip_post_signature_validation = false;
                o.trust_evaluation_options.bypass_trust = true;
            },
        );

        let result = v
            .validate_bytes(Arc::from(cose.clone().into_boxed_slice()))
            .unwrap();
        assert_eq!(
            ValidationResultKind::Failure,
            result.post_signature_policy.kind
        );
        assert_eq!(ValidationResultKind::Failure, result.overall.kind);
    }

    // skipped => succeeds
    {
        let key: Arc<dyn SigningKey> = Arc::new(AlwaysTrueKey);
        let resolver: Arc<dyn SigningKeyResolver> = Arc::new(StaticKeyResolver { key });

        let v = validator_with(
            Some(resolver),
            vec![Arc::new(FailValidator)],
            |o| {
                o.skip_post_signature_validation = true;
                o.trust_evaluation_options.bypass_trust = true;
            },
        );

        let result = v
            .validate_bytes(Arc::from(cose.clone().into_boxed_slice()))
            .unwrap();
        assert_eq!(ValidationResultKind::Success, result.overall.kind);
    }
}

#[test]
fn validate_bytes_trust_denied_by_default_when_not_bypassed() {
    let key: Arc<dyn SigningKey> = Arc::new(AlwaysTrueKey);
    let resolver: Arc<dyn SigningKeyResolver> = Arc::new(StaticKeyResolver { key });

    // Empty trust plan denies by default when bypass_trust=false.
    let v = validator_with(
        Some(resolver),
        vec![],
        |_o| {},
    );

    let cose = build_cose_sign1_bytes(Some(b"payload"), Some(-7));
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.trust.kind);
    assert_eq!(ValidationResultKind::NotApplicable, result.signature.kind);
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}
