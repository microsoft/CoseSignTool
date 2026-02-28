// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_validation_primitives::{CoseHeaderLocation, CoseSign1Message};
use sha2::Digest;
use std::sync::Arc;

struct AlwaysTrueVerifier;

impl CryptoVerifier for AlwaysTrueVerifier {
    fn algorithm(&self) -> i64 { -7 }
    
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

struct AlwaysTrueKeyResolver;

impl CoseKeyResolver for AlwaysTrueKeyResolver {
    fn resolve(
        &self,
        _message: &CoseSign1Message,
        _options: &CoseSign1ValidationOptions,
    ) -> CoseKeyResolutionResult {
        CoseKeyResolutionResult::success(Arc::new(AlwaysTrueVerifier))
    }
}

fn build_protected_header(map_len: usize, entries: impl FnOnce(&mut cbor_primitives_everparse::EverParseEncoder)) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut hdr_enc = p.encoder();

    hdr_enc.encode_map(map_len).unwrap();
    entries(&mut hdr_enc);

    hdr_enc.into_bytes()
}

fn build_cose_sign1_with_unprotected(
    protected_header_bytes: &[u8],
    encode_unprotected: impl FnOnce(&mut cbor_primitives_everparse::EverParseEncoder),
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header: bstr(CBOR map)
    enc.encode_bstr(protected_header_bytes).unwrap();

    // unprotected header: caller-provided encoding (usually a map)
    encode_unprotected(&mut enc);

    // payload + signature
    match payload {
        Some(p) => enc.encode_bstr(p).unwrap(),
        None => enc.encode_null().unwrap(),
    }
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

fn validator_with_detached_payload_provider(
    provider: Box<dyn StreamingPayload>,
) -> CoseSign1Validator {
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_cose_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];

    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();

    CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = Some(Payload::Streaming(provider));
    })
}

fn validator_with_detached_payload(
    detached_payload: Option<Arc<[u8]>>,
    header_location: Option<CoseHeaderLocation>,
) -> CoseSign1Validator {
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_cose_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];

    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();

    let mut v = CoseSign1Validator::new(bundled);
    v = v.with_options(|o| {
        if let Some(p) = detached_payload.clone() {
            o.detached_payload = Some(Payload::Bytes(p.to_vec()));
        }
        if let Some(loc) = header_location {
            o.certificate_header_location = loc;
        }
    });
    v
}

#[test]
fn legacy_hash_extension_succeeds_when_detached_payload_matches() {
    let artifact = Arc::<[u8]>::from(b"hello world".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    // protected header: {1:-7, 3:"application/octet-stream+hash-sha256"}
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+hash-sha256".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn legacy_hash_extension_fails_when_detached_payload_mismatches() {
    let artifact = Arc::<[u8]>::from(b"hello world".to_vec().into_boxed_slice());
    let wrong_hash = sha2::Sha256::digest(b"different".as_slice()).to_vec();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+hash-sha256".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &wrong_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn cose_hash_v_succeeds_when_detached_payload_matches() {
    let artifact = Arc::<[u8]>::from(b"payload".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    // COSE_Hash_V CBOR array: [ -16, h'...' ]
    let p = EverParseCborProvider;
    let mut hv_enc = p.encoder();
    hv_enc.encode_array(2).unwrap();
    hv_enc.encode_i64(-16).unwrap();
    hv_enc.encode_bstr(expected_hash.as_slice()).unwrap();
    let hv_buf = hv_enc.into_bytes();

    // protected header: {1:-7, 3:"application/octet-stream+cose-hash-v"}
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+cose-hash-v".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &hv_buf);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn cose_hash_envelope_succeeds_when_detached_payload_matches() {
    let artifact = Arc::<[u8]>::from(b"artifact".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    // protected header: {1:-7, 258:-16, 259:"application/json"}
    let hdr = build_protected_header(3, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(258).unwrap();
        enc.encode_i64(-16).unwrap();
        enc.encode_i64(259).unwrap();
        enc.encode_bstr("application/json".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn indirect_signatures_are_treated_as_signature_only_when_no_detached_payload_is_provided() {
    // CoseHashEnvelope marker, but no detached payload provided.
    let payload_hash = sha2::Sha256::digest(b"does not matter".as_slice()).to_vec();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(258).unwrap();
        enc.encode_i64(-16).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &payload_hash);

    let v = validator_with_detached_payload(None, None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_valid());
    assert!(result.overall.is_valid());
}

fn build_cose_sign1(protected_header_bytes: &[u8], payload: &[u8]) -> Vec<u8> {
    build_cose_sign1_with_unprotected(protected_header_bytes, |enc| {
        enc.encode_map(0).unwrap();
    }, Some(payload))
}

struct ErroringProvider {
    open_error: String,
}

impl StreamingPayload for ErroringProvider {
    fn size(&self) -> u64 {
        0
    }

    fn open(&self) -> Result<Box<dyn cose_sign1_primitives::sig_structure::SizedRead + Send>, cose_sign1_primitives::error::PayloadError> {
        Err(cose_sign1_primitives::error::PayloadError::OpenFailed(self.open_error.clone()))
    }
}

struct ErroringReader;

impl std::io::Read for ErroringReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "boom",
        ))
    }
}

impl cose_sign1_primitives::sig_structure::SizedRead for ErroringReader {
    fn len(&self) -> std::io::Result<u64> {
        Ok(0)
    }
}

struct ReadErrorProvider;

impl StreamingPayload for ReadErrorProvider {
    fn size(&self) -> u64 {
        0
    }

    fn open(&self) -> Result<Box<dyn cose_sign1_primitives::sig_structure::SizedRead + Send>, cose_sign1_primitives::error::PayloadError> {
        Ok(Box::new(ErroringReader))
    }
}

#[test]
fn unprotected_content_type_is_only_honored_when_header_location_is_any() {
    let artifact = Arc::<[u8]>::from(b"hello".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    // protected: {1:-7}
    let hdr = build_protected_header(1, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
    });

    // unprotected: {3:"application/octet-stream+hash-sha256"}
    let cose = build_cose_sign1_with_unprotected(
        &hdr,
        |enc| {
            enc.encode_map(1).unwrap();
            enc.encode_i64(3).unwrap();
            enc.encode_bstr("application/octet-stream+hash-sha256".as_bytes())
                .unwrap();
        },
        Some(expected_hash.as_slice()),
    );

    // Default (Protected-only): should ignore unprotected Content-Type and treat as not-indirect.
    let v_protected = validator_with_detached_payload(Some(artifact.clone()), None);
    let result = v_protected
        .validate_bytes(EverParseCborProvider, Arc::from(cose.clone().into_boxed_slice()))
        .unwrap();
    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());

    // Any: should honor unprotected Content-Type and validate the hash.
    let v_any = validator_with_detached_payload(Some(artifact), Some(CoseHeaderLocation::Any));
    let result = v_any
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();
    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn legacy_hash_extension_fails_when_hash_algorithm_is_unsupported() {
    let artifact = Arc::<[u8]>::from(b"hello world".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    // protected header: {1:-7, 3:"application/octet-stream+hash-md5"}
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+hash-md5".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn cose_hash_v_fails_when_payload_is_not_a_valid_cose_hash_v() {
    let artifact = Arc::<[u8]>::from(b"payload".to_vec().into_boxed_slice());

    // protected header: {1:-7, 3:"application/octet-stream+cose-hash-v"}
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+cose-hash-v".as_bytes()).unwrap();
    });

    // payload: invalid CBOR (empty)
    let cose = build_cose_sign1(&hdr, &[]);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn cose_hash_envelope_fails_when_payload_hash_alg_is_in_unprotected_header() {
    let artifact = Arc::<[u8]>::from(b"artifact".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    // protected header: {1:-7, 258:-16}
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(258).unwrap();
        enc.encode_i64(-16).unwrap();
    });

    // unprotected header also (incorrectly) contains 258
    let cose = build_cose_sign1_with_unprotected(
        &hdr,
        |enc| {
            enc.encode_map(1).unwrap();
            enc.encode_i64(258).unwrap();
            enc.encode_i64(-16).unwrap();
        },
        Some(expected_hash.as_slice()),
    );

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn cose_hash_envelope_fails_when_payload_hash_alg_has_wrong_type() {
    let artifact = Arc::<[u8]>::from(b"artifact".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    // protected header: {1:-7, 258:h'01'} (wrong type for alg)
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(258).unwrap();
        enc.encode_bstr(b"\x01").unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn indirect_signature_fails_when_detached_payload_is_empty() {
    let empty = Arc::<[u8]>::from(Vec::<u8>::new().into_boxed_slice());

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+hash-sha256".as_bytes()).unwrap();
    });

    let hash = sha2::Sha256::digest(b"anything".as_slice()).to_vec();
    let cose = build_cose_sign1(&hdr, &hash);

    let v = validator_with_detached_payload(Some(empty), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn indirect_signature_fails_when_provider_open_fails() {
    let provider = Box::new(ErroringProvider {
        open_error: "open_failed".to_string(),
    });

    let expected_hash = sha2::Sha256::digest(b"hello".as_slice()).to_vec();
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+hash-sha256".as_bytes()).unwrap();
    });
    let cose = build_cose_sign1(&hdr, &expected_hash);

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_cose_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];
    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();
    let v = CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = Some(Payload::Streaming(provider));
    });

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn indirect_signature_fails_when_provider_reader_errors() {
    let provider = Box::new(ReadErrorProvider);

    let expected_hash = sha2::Sha256::digest(b"hello".as_slice()).to_vec();
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+hash-sha256".as_bytes()).unwrap();
    });
    let cose = build_cose_sign1(&hdr, &expected_hash);

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_cose_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];
    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();
    let v = CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = Some(Payload::Streaming(provider));
    });

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn envelope_hashes_with_sha384_via_provider_streaming() {
    let artifact = b"artifact".to_vec();
    let expected_hash = sha2::Sha384::digest(artifact.as_slice()).to_vec();

    // protected header: {1:-7, 258:-43}
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(258).unwrap();
        enc.encode_i64(-43).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let provider = Box::new(MemoryPayload::new(artifact));
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_cose_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];
    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();
    let v = CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = Some(Payload::Streaming(provider));
    });

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn indirect_signature_fails_when_embedded_payload_is_nil() {
    let artifact = Arc::<[u8]>::from(b"artifact".to_vec().into_boxed_slice());

    // CoseHashEnvelope marker (258:-16), but payload is nil.
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(258).unwrap();
        enc.encode_i64(-16).unwrap();
    });

    let cose = build_cose_sign1_with_unprotected(
        &hdr,
        |enc| {
            enc.encode_map(0).unwrap();
        },
        None,
    );

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn cose_hash_v_fails_when_hash_is_empty() {
    let artifact = Arc::<[u8]>::from(b"payload".to_vec().into_boxed_slice());

    // COSE_Hash_V payload: [ -16, h'' ]
    let p = EverParseCborProvider;
    let mut hv_enc = p.encoder();
    hv_enc.encode_array(2).unwrap();
    hv_enc.encode_i64(-16).unwrap();
    hv_enc.encode_bstr(&[]).unwrap();
    let hv_buf = hv_enc.into_bytes();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+cose-hash-v".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &hv_buf);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn cose_hash_v_fails_when_alg_is_unsupported() {
    let artifact = Arc::<[u8]>::from(b"payload".to_vec().into_boxed_slice());

    // COSE_Hash_V payload: [ -999, h'01' ]
    let p = EverParseCborProvider;
    let mut hv_enc = p.encoder();
    hv_enc.encode_array(2).unwrap();
    hv_enc.encode_i64(-999).unwrap();
    hv_enc.encode_bstr(b"\x01").unwrap();
    let hv_buf = hv_enc.into_bytes();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+cose-hash-v".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &hv_buf);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn cose_hash_envelope_fails_when_alg_is_unsupported() {
    let artifact = Arc::<[u8]>::from(b"artifact".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    // protected header: {1:-7, 258:-999}
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(258).unwrap();
        enc.encode_i64(-999).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn non_indirect_content_type_is_not_applicable() {
    let artifact = Arc::<[u8]>::from(b"hello".to_vec().into_boxed_slice());

    // protected header: {1:-7, 3:"application/json"} (no +hash-* / +cose-hash-v)
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/json".as_bytes()).unwrap();
    });

    // payload can be anything; this should not be treated as indirect.
    let cose = build_cose_sign1(&hdr, b"payload".as_slice());

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_valid());
    assert!(result.overall.is_valid());
}

#[test]
fn non_text_or_bytes_content_type_is_ignored() {
    let artifact = Arc::<[u8]>::from(b"hello".to_vec().into_boxed_slice());

    // protected header: {1:-7, 3:-1} (Content-Type label present but wrong type)
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_i64(-1).unwrap();
    });

    let cose = build_cose_sign1(&hdr, b"payload".as_slice());

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_valid());
    assert!(result.overall.is_valid());
}

#[test]
fn legacy_hash_extension_succeeds_for_sha384() {
    let artifact = Arc::<[u8]>::from(b"hello world".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha384::digest(artifact.as_ref()).to_vec();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+hash-sha384".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn envelope_hashes_with_sha512_via_provider_streaming() {
    let artifact = b"artifact".to_vec();
    let expected_hash = sha2::Sha512::digest(artifact.as_slice()).to_vec();

    // protected header: {1:-7, 258:-44}
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(258).unwrap();
        enc.encode_i64(-44).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let provider = Box::new(MemoryPayload::new(artifact));
    let v = validator_with_detached_payload_provider(provider);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn envelope_hashes_with_sha1_via_provider_streaming() {
    let artifact = b"artifact".to_vec();
    let expected_hash = sha1::Sha1::digest(artifact.as_slice()).to_vec();

    // protected header: {1:-7, 258:-14}
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(258).unwrap();
        enc.encode_i64(-14).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let provider = Box::new(MemoryPayload::new(artifact));
    let v = validator_with_detached_payload_provider(provider);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn legacy_hash_extension_succeeds_for_sha512() {
    let artifact = Arc::<[u8]>::from(b"hello world".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha512::digest(artifact.as_ref()).to_vec();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+hash-sha512".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn legacy_hash_extension_succeeds_for_sha1() {
    let artifact = Arc::<[u8]>::from(b"hello world".to_vec().into_boxed_slice());
    let expected_hash = sha1::Sha1::digest(artifact.as_ref()).to_vec();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+hash-sha1".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn legacy_hash_extension_hashes_with_sha256_via_provider_streaming() {
    let artifact = b"hello".to_vec();
    let expected_hash = sha2::Sha256::digest(artifact.as_slice()).to_vec();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+hash-sha256".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let provider = Box::new(MemoryPayload::new(artifact));
    let v = validator_with_detached_payload_provider(provider);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}
