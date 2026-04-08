// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::error::PayloadError;
use cose_sign1_primitives::sig_structure::SizedRead;
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::policy::TrustPolicyBuilder;
use cose_sign1_validation_primitives::CoseSign1Message;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use std::io::Cursor;
use std::sync::Arc;

fn encode_protected_alg(alg: i64) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap(); // alg header
    enc.encode_i64(alg).unwrap();

    enc.into_bytes()
}

fn encode_empty_map_bytes() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_map(0).unwrap();

    enc.into_bytes()
}

fn build_cose_sign1_bytes(payload: Option<&[u8]>, alg: Option<i64>) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header bstr
    let protected = alg
        .map(encode_protected_alg)
        .unwrap_or_else(encode_empty_map_bytes);
    enc.encode_bstr(&protected).unwrap();

    // unprotected header map
    enc.encode_map(0).unwrap();

    // payload: bstr or null
    match payload {
        Some(p) => enc.encode_bstr(p).unwrap(),
        None => {
            // COSE detached payload is represented as CBOR null.
            enc.encode_null().unwrap();
        }
    }

    // signature (opaque bytes)
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

fn allow_all_trust_plan() -> cose_sign1_validation_primitives::plan::CompiledTrustPlan {
    // We bypass trust in most tests, so an empty policy is fine.
    TrustPolicyBuilder::new().build().compile()
}

fn validator_with(
    resolver: Option<Arc<dyn CoseKeyResolver>>,
    post_validators: Vec<Arc<dyn PostSignatureValidator>>,
    configure: impl FnOnce(&mut CoseSign1ValidationOptions),
) -> CoseSign1Validator {
    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();

    if let Some(resolver) = resolver {
        trust_packs.push(Arc::new(
            SimpleTrustPack::no_facts("test_signing_key_resolver").with_cose_key_resolver(resolver),
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
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    ));

    CoseSign1Validator::new(trust_packs).with_options(configure)
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

struct AlwaysTrueVerifier;
impl CryptoVerifier for AlwaysTrueVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

struct AlwaysFalseVerifier;
impl CryptoVerifier for AlwaysFalseVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(false)
    }
}

struct ErrorVerifier;
impl CryptoVerifier for ErrorVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Err(CryptoError::VerificationFailed("boom".to_string()))
    }
}

struct StreamingTrueVerifier;
impl CryptoVerifier for StreamingTrueVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        // If streaming isn't used, we want to fail this test.
        Ok(false)
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn verify_init(
        &self,
        _signature: &[u8],
    ) -> Result<Box<dyn crypto_primitives::VerifyingContext>, CryptoError> {
        Ok(Box::new(StreamingTrueContext))
    }
}

struct StreamingTrueContext;
impl crypto_primitives::VerifyingContext for StreamingTrueContext {
    fn update(&mut self, _chunk: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }

    fn finalize(self: Box<Self>) -> Result<bool, CryptoError> {
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
fn validate_bytes_resolution_fails_when_no_resolvers() {
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    )];

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1_bytes(Some(b"payload"), Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
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
    let key: Arc<dyn CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticKeyResolver { key });

    let v = validator_with(Some(resolver), vec![], |o| {
        o.detached_payload = None;
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1_bytes(None, Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        result
            .signature
            .failures
            .first()
            .and_then(|f| f.error_code.as_deref()),
        Some(CoseSign1Validator::ERROR_CODE_SIGNATURE_MISSING_PAYLOAD)
    );
}

#[test]
fn validate_bytes_signature_errors_when_alg_missing() {
    let key: Arc<dyn CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticKeyResolver { key });

    let v = validator_with(Some(resolver), vec![], |o| {
        o.detached_payload = Some(Payload::Bytes(b"p".to_vec()));
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1_bytes(None, None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        result
            .signature
            .failures
            .first()
            .and_then(|f| f.error_code.as_deref()),
        Some(CoseSign1Validator::ERROR_CODE_NO_APPLICABLE_SIGNATURE_VALIDATOR)
    );
}

#[test]
fn validate_bytes_embedded_payload_signature_success_and_failure_paths() {
    let cose = build_cose_sign1_bytes(Some(b"payload"), Some(-7));

    // success
    {
        let key: Arc<dyn CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
        let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticKeyResolver { key });

        let v = validator_with(Some(resolver), vec![], |o| {
            o.trust_evaluation_options.bypass_trust = true;
        });
        let result = v
            .validate_bytes(
                EverParseCborProvider,
                Arc::from(cose.clone().into_boxed_slice()),
            )
            .unwrap();
        assert_eq!(ValidationResultKind::Success, result.signature.kind);
        assert_eq!(ValidationResultKind::Success, result.overall.kind);
    }

    // verification returns false
    {
        let key: Arc<dyn CryptoVerifier> = Arc::new(AlwaysFalseVerifier);
        let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticKeyResolver { key });

        let v = validator_with(Some(resolver), vec![], |o| {
            o.trust_evaluation_options.bypass_trust = true;
        });
        let result = v
            .validate_bytes(
                EverParseCborProvider,
                Arc::from(cose.clone().into_boxed_slice()),
            )
            .unwrap();
        assert_eq!(ValidationResultKind::Failure, result.signature.kind);
        assert_eq!(
            result
                .signature
                .failures
                .first()
                .and_then(|f| f.error_code.as_deref()),
            Some(CoseSign1Validator::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED)
        );
    }

    // verification errors
    {
        let key: Arc<dyn CryptoVerifier> = Arc::new(ErrorVerifier);
        let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticKeyResolver { key });

        let v = validator_with(Some(resolver), vec![], |o| {
            o.trust_evaluation_options.bypass_trust = true;
        });
        let result = v
            .validate_bytes(
                EverParseCborProvider,
                Arc::from(cose.clone().into_boxed_slice()),
            )
            .unwrap();
        assert_eq!(ValidationResultKind::Failure, result.signature.kind);
        assert_eq!(
            result
                .signature
                .failures
                .first()
                .and_then(|f| f.error_code.as_deref()),
            Some(CoseSign1Validator::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED)
        );
    }
}

#[test]
fn validate_bytes_streaming_path_uses_verify_reader_for_large_detached_payload() {
    let large = vec![0x41u8; (CoseSign1Validator::LARGE_STREAM_THRESHOLD + 1) as usize];
    let large_len = large.len() as u64;
    let provider_bytes = Arc::new(large);

    struct LargePayloadProvider {
        data: Arc<Vec<u8>>,
        len: u64,
    }

    impl StreamingPayload for LargePayloadProvider {
        fn size(&self) -> u64 {
            self.len
        }
        fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
            Ok(Box::new(Cursor::new(self.data.as_ref().to_vec())) as Box<dyn SizedRead + Send>)
        }
    }

    let provider = LargePayloadProvider {
        data: provider_bytes.clone(),
        len: large_len,
    };

    let key: Arc<dyn CryptoVerifier> = Arc::new(StreamingTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticKeyResolver { key });

    let v = validator_with(Some(resolver), vec![], |o| {
        o.detached_payload = Some(Payload::Streaming(Box::new(provider)));
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1_bytes(None, Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Success, result.signature.kind);
    assert_eq!(
        Some("streaming".to_string()),
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
        let key: Arc<dyn CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
        let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticKeyResolver { key });

        let v = validator_with(Some(resolver), vec![Arc::new(FailValidator)], |o| {
            o.skip_post_signature_validation = false;
            o.trust_evaluation_options.bypass_trust = true;
        });

        let result = v
            .validate_bytes(
                EverParseCborProvider,
                Arc::from(cose.clone().into_boxed_slice()),
            )
            .unwrap();
        assert_eq!(
            ValidationResultKind::Failure,
            result.post_signature_policy.kind
        );
        assert_eq!(ValidationResultKind::Failure, result.overall.kind);
    }

    // skipped => succeeds
    {
        let key: Arc<dyn CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
        let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticKeyResolver { key });

        let v = validator_with(Some(resolver), vec![Arc::new(FailValidator)], |o| {
            o.skip_post_signature_validation = true;
            o.trust_evaluation_options.bypass_trust = true;
        });

        let result = v
            .validate_bytes(
                EverParseCborProvider,
                Arc::from(cose.clone().into_boxed_slice()),
            )
            .unwrap();
        assert_eq!(ValidationResultKind::Success, result.overall.kind);
    }
}

#[test]
fn validate_bytes_trust_denied_by_default_when_not_bypassed() {
    let key: Arc<dyn CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticKeyResolver { key });

    // Empty trust plan denies by default when bypass_trust=false.
    let v = validator_with(Some(resolver), vec![], |_o| {});

    let cose = build_cose_sign1_bytes(Some(b"payload"), Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.trust.kind);
    assert_eq!(ValidationResultKind::NotApplicable, result.signature.kind);
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}
