// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use cose_sign1_validation_trust::CoseHeaderLocation;
use sha2::Digest;
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

struct AlwaysTrueKey;

impl SigningKey for AlwaysTrueKey {
    fn key_type(&self) -> &'static str {
        "AlwaysTrueKey"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Ok(true)
    }
}

struct AlwaysTrueKeyResolver;

impl SigningKeyResolver for AlwaysTrueKeyResolver {
    fn resolve(
        &self,
        _message: &CoseSign1<'_>,
        _options: &CoseSign1ValidationOptions,
    ) -> SigningKeyResolutionResult {
        SigningKeyResolutionResult::success(Arc::new(AlwaysTrueKey))
    }
}

fn build_protected_header(map_len: usize, entries: impl FnOnce(&mut Encoder<&mut [u8]>)) -> Vec<u8> {
    let mut hdr_buf = vec![0u8; 512];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());

    hdr_enc.map(map_len).unwrap();
    entries(&mut hdr_enc);

    let used = hdr_len - hdr_enc.0.len();
    hdr_buf.truncate(used);
    hdr_buf
}

fn build_cose_sign1_with_unprotected(
    protected_header_bytes: &[u8],
    encode_unprotected: impl FnOnce(&mut Encoder<&mut [u8]>),
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map)
    protected_header_bytes.encode(&mut enc).unwrap();

    // unprotected header: caller-provided encoding (usually a map)
    encode_unprotected(&mut enc);

    // payload + signature
    payload.encode(&mut enc).unwrap();
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn validator_with_detached_payload_provider(
    provider: Arc<dyn DetachedPayloadProvider>,
) -> CoseSign1Validator {
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_signing_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];

    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();

    CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::Provider(provider));
    })
}

fn validator_with_detached_payload(
    detached_payload: Option<Arc<[u8]>>,
    header_location: Option<CoseHeaderLocation>,
) -> CoseSign1Validator {
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_signing_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];

    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();

    let mut v = CoseSign1Validator::new(bundled);
    v = v.with_options(|o| {
        if let Some(p) = detached_payload.clone() {
            o.detached_payload = Some(DetachedPayload::bytes(p));
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
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+hash-sha256".as_bytes().encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn legacy_hash_extension_fails_when_detached_payload_mismatches() {
    let artifact = Arc::<[u8]>::from(b"hello world".to_vec().into_boxed_slice());
    let wrong_hash = sha2::Sha256::digest(b"different".as_slice()).to_vec();

    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+hash-sha256".as_bytes().encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &wrong_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
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
    let mut hv_buf = vec![0u8; 256];
    let hv_len = hv_buf.len();
    let mut hv_enc = Encoder(hv_buf.as_mut_slice());
    hv_enc.array(2).unwrap();
    (-16i64).encode(&mut hv_enc).unwrap();
    expected_hash.as_slice().encode(&mut hv_enc).unwrap();
    let used = hv_len - hv_enc.0.len();
    hv_buf.truncate(used);

    // protected header: {1:-7, 3:"application/octet-stream+cose-hash-v"}
    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+cose-hash-v".as_bytes().encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &hv_buf);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
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
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (258i64).encode(enc).unwrap();
        (-16i64).encode(enc).unwrap();
        (259i64).encode(enc).unwrap();
        "application/json".as_bytes().encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn indirect_signatures_are_treated_as_signature_only_when_no_detached_payload_is_provided() {
    // CoseHashEnvelope marker, but no detached payload provided.
    let payload_hash = sha2::Sha256::digest(b"does not matter".as_slice()).to_vec();

    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (258i64).encode(enc).unwrap();
        (-16i64).encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &payload_hash);

    let v = validator_with_detached_payload(None, None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_valid());
    assert!(result.overall.is_valid());
}

fn build_cose_sign1(protected_header_bytes: &[u8], payload: &[u8]) -> Vec<u8> {
    build_cose_sign1_with_unprotected(protected_header_bytes, |enc| {
        enc.map(0).unwrap();
    }, Some(payload))
}

struct ErroringProvider {
    open_error: String,
}

impl DetachedPayloadProvider for ErroringProvider {
    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, String> {
        Err(self.open_error.clone())
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

struct ReadErrorProvider;

impl DetachedPayloadProvider for ReadErrorProvider {
    fn open(&self) -> Result<Box<dyn std::io::Read + Send>, String> {
        Ok(Box::new(ErroringReader))
    }
}

#[test]
fn unprotected_content_type_is_only_honored_when_header_location_is_any() {
    let artifact = Arc::<[u8]>::from(b"hello".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    // protected: {1:-7}
    let hdr = build_protected_header(1, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
    });

    // unprotected: {3:"application/octet-stream+hash-sha256"}
    let cose = build_cose_sign1_with_unprotected(
        &hdr,
        |enc| {
            enc.map(1).unwrap();
            (3i64).encode(enc).unwrap();
            "application/octet-stream+hash-sha256"
                .as_bytes()
                .encode(enc)
                .unwrap();
        },
        Some(expected_hash.as_slice()),
    );

    // Default (Protected-only): should ignore unprotected Content-Type and treat as not-indirect.
    let v_protected = validator_with_detached_payload(Some(artifact.clone()), None);
    let result = v_protected
        .validate_bytes(Arc::from(cose.clone().into_boxed_slice()))
        .unwrap();
    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());

    // Any: should honor unprotected Content-Type and validate the hash.
    let v_any = validator_with_detached_payload(Some(artifact), Some(CoseHeaderLocation::Any));
    let result = v_any
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
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
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+hash-md5".as_bytes().encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
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
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+cose-hash-v".as_bytes().encode(enc).unwrap();
    });

    // payload: invalid CBOR (empty)
    let cose = build_cose_sign1(&hdr, &[]);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
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
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (258i64).encode(enc).unwrap();
        (-16i64).encode(enc).unwrap();
    });

    // unprotected header also (incorrectly) contains 258
    let cose = build_cose_sign1_with_unprotected(
        &hdr,
        |enc| {
            enc.map(1).unwrap();
            (258i64).encode(enc).unwrap();
            (-16i64).encode(enc).unwrap();
        },
        Some(expected_hash.as_slice()),
    );

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
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
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (258i64).encode(enc).unwrap();
        b"\x01".as_slice().encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn indirect_signature_fails_when_detached_payload_is_empty() {
    let empty = Arc::<[u8]>::from(Vec::<u8>::new().into_boxed_slice());

    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+hash-sha256".as_bytes().encode(enc).unwrap();
    });

    let hash = sha2::Sha256::digest(b"anything".as_slice()).to_vec();
    let cose = build_cose_sign1(&hdr, &hash);

    let v = validator_with_detached_payload(Some(empty), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn indirect_signature_fails_when_provider_open_fails() {
    let provider: Arc<dyn DetachedPayloadProvider> = Arc::new(ErroringProvider {
        open_error: "open_failed".to_string(),
    });

    let expected_hash = sha2::Sha256::digest(b"hello".as_slice()).to_vec();
    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+hash-sha256".as_bytes().encode(enc).unwrap();
    });
    let cose = build_cose_sign1(&hdr, &expected_hash);

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_signing_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];
    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();
    let v = CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::Provider(provider));
    });

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn indirect_signature_fails_when_provider_reader_errors() {
    let provider: Arc<dyn DetachedPayloadProvider> = Arc::new(ReadErrorProvider);

    let expected_hash = sha2::Sha256::digest(b"hello".as_slice()).to_vec();
    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+hash-sha256".as_bytes().encode(enc).unwrap();
    });
    let cose = build_cose_sign1(&hdr, &expected_hash);

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_signing_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];
    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();
    let v = CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::Provider(provider));
    });

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn envelope_hashes_with_sha384_via_provider_streaming() {
    struct BytesProvider(Arc<[u8]>);

    impl DetachedPayloadProvider for BytesProvider {
        fn open(&self) -> Result<Box<dyn std::io::Read + Send>, String> {
            Ok(Box::new(std::io::Cursor::new(self.0.as_ref().to_vec())))
        }
    }

    let artifact = Arc::<[u8]>::from(b"artifact".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha384::digest(artifact.as_ref()).to_vec();

    // protected header: {1:-7, 258:-43}
    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (258i64).encode(enc).unwrap();
        (-43i64).encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let provider: Arc<dyn DetachedPayloadProvider> = Arc::new(BytesProvider(artifact));
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_signing_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];
    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();
    let v = CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::Provider(provider));
    });

    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn indirect_signature_fails_when_embedded_payload_is_nil() {
    let artifact = Arc::<[u8]>::from(b"artifact".to_vec().into_boxed_slice());

    // CoseHashEnvelope marker (258:-16), but payload is nil.
    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (258i64).encode(enc).unwrap();
        (-16i64).encode(enc).unwrap();
    });

    let cose = build_cose_sign1_with_unprotected(
        &hdr,
        |enc| {
            enc.map(0).unwrap();
        },
        None,
    );

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn cose_hash_v_fails_when_hash_is_empty() {
    let artifact = Arc::<[u8]>::from(b"payload".to_vec().into_boxed_slice());

    // COSE_Hash_V payload: [ -16, h'' ]
    let mut hv_buf = vec![0u8; 64];
    let hv_len = hv_buf.len();
    let mut hv_enc = Encoder(hv_buf.as_mut_slice());
    hv_enc.array(2).unwrap();
    (-16i64).encode(&mut hv_enc).unwrap();
    (&[] as &[u8]).encode(&mut hv_enc).unwrap();
    let used = hv_len - hv_enc.0.len();
    hv_buf.truncate(used);

    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+cose-hash-v".as_bytes().encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &hv_buf);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

#[test]
fn cose_hash_v_fails_when_alg_is_unsupported() {
    let artifact = Arc::<[u8]>::from(b"payload".to_vec().into_boxed_slice());

    // COSE_Hash_V payload: [ -999, h'01' ]
    let mut hv_buf = vec![0u8; 64];
    let hv_len = hv_buf.len();
    let mut hv_enc = Encoder(hv_buf.as_mut_slice());
    hv_enc.array(2).unwrap();
    (-999i64).encode(&mut hv_enc).unwrap();
    b"\x01".as_slice().encode(&mut hv_enc).unwrap();
    let used = hv_len - hv_enc.0.len();
    hv_buf.truncate(used);

    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+cose-hash-v".as_bytes().encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &hv_buf);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
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
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (258i64).encode(enc).unwrap();
        (-999i64).encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
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
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/json".as_bytes().encode(enc).unwrap();
    });

    // payload can be anything; this should not be treated as indirect.
    let cose = build_cose_sign1(&hdr, b"payload".as_slice());

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
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
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        (-1i64).encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, b"payload".as_slice());

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
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
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+hash-sha384".as_bytes().encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn envelope_hashes_with_sha512_via_provider_streaming() {
    struct BytesProvider(Arc<[u8]>);

    impl DetachedPayloadProvider for BytesProvider {
        fn open(&self) -> Result<Box<dyn std::io::Read + Send>, String> {
            Ok(Box::new(std::io::Cursor::new(self.0.as_ref().to_vec())))
        }
    }

    let artifact = Arc::<[u8]>::from(b"artifact".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha512::digest(artifact.as_ref()).to_vec();

    // protected header: {1:-7, 258:-44}
    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (258i64).encode(enc).unwrap();
        (-44i64).encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let provider: Arc<dyn DetachedPayloadProvider> = Arc::new(BytesProvider(artifact));
    let v = validator_with_detached_payload_provider(provider);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn envelope_hashes_with_sha1_via_provider_streaming() {
    struct BytesProvider(Arc<[u8]>);

    impl DetachedPayloadProvider for BytesProvider {
        fn open(&self) -> Result<Box<dyn std::io::Read + Send>, String> {
            Ok(Box::new(std::io::Cursor::new(self.0.as_ref().to_vec())))
        }
    }

    let artifact = Arc::<[u8]>::from(b"artifact".to_vec().into_boxed_slice());
    let expected_hash = sha1::Sha1::digest(artifact.as_ref()).to_vec();

    // protected header: {1:-7, 258:-14}
    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (258i64).encode(enc).unwrap();
        (-14i64).encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let provider: Arc<dyn DetachedPayloadProvider> = Arc::new(BytesProvider(artifact));
    let v = validator_with_detached_payload_provider(provider);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn legacy_hash_extension_succeeds_for_sha512() {
    let artifact = Arc::<[u8]>::from(b"hello world".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha512::digest(artifact.as_ref()).to_vec();

    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+hash-sha512".as_bytes().encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn legacy_hash_extension_succeeds_for_sha1() {
    let artifact = Arc::<[u8]>::from(b"hello world".to_vec().into_boxed_slice());
    let expected_hash = sha1::Sha1::digest(artifact.as_ref()).to_vec();

    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+hash-sha1".as_bytes().encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let v = validator_with_detached_payload(Some(artifact), None);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

#[test]
fn legacy_hash_extension_hashes_with_sha256_via_provider_streaming() {
    struct BytesProvider(Arc<[u8]>);

    impl DetachedPayloadProvider for BytesProvider {
        fn open(&self) -> Result<Box<dyn std::io::Read + Send>, String> {
            Ok(Box::new(std::io::Cursor::new(self.0.as_ref().to_vec())))
        }
    }

    let artifact = Arc::<[u8]>::from(b"hello".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    let hdr = build_protected_header(2, |enc| {
        (1i64).encode(enc).unwrap();
        (-7i64).encode(enc).unwrap();
        (3i64).encode(enc).unwrap();
        "application/octet-stream+hash-sha256".as_bytes().encode(enc).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);

    let provider: Arc<dyn DetachedPayloadProvider> = Arc::new(BytesProvider(artifact));
    let v = validator_with_detached_payload_provider(provider);
    let result = v
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}
