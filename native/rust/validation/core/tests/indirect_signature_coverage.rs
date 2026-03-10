// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional tests for indirect_signature.rs targeting uncovered code paths:
//! - Content-type encoded as CBOR tstr (Text variant) rather than bstr
//! - parse_cose_hash_v with wrong array length
//! - CoseHashV with SHA384 / SHA512 / SHA1 algorithms
//! - CoseHashEnvelope with content-type as tstr in protected header
//! - Legacy hash with case-insensitive algorithm names

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_validation_primitives::CoseHeaderLocation;
use sha2::Digest;
use std::sync::Arc;

// ----- shared helpers (mirror the existing test file) -----

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
        _message: &cose_sign1_validation_primitives::CoseSign1Message,
        _options: &CoseSign1ValidationOptions,
    ) -> CoseKeyResolutionResult {
        CoseKeyResolutionResult::success(Arc::new(AlwaysTrueVerifier))
    }
}

fn build_validator(
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

    CoseSign1Validator::new(bundled).with_options(|o| {
        if let Some(p) = detached_payload {
            o.detached_payload = Some(Payload::Bytes(p.to_vec()));
        }
        if let Some(loc) = header_location {
            o.certificate_header_location = loc;
        }
    })
}

fn build_protected_header(
    map_len: usize,
    entries: impl FnOnce(&mut cbor_primitives_everparse::EverParseEncoder),
) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(map_len).unwrap();
    entries(&mut enc);
    enc.into_bytes()
}

fn build_cose_sign1(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    build_cose_sign1_ex(protected, |enc| { enc.encode_map(0).unwrap(); }, Some(payload))
}

fn build_cose_sign1_ex(
    protected: &[u8],
    encode_unprotected: impl FnOnce(&mut cbor_primitives_everparse::EverParseEncoder),
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected).unwrap();
    encode_unprotected(&mut enc);
    match payload {
        Some(p) => enc.encode_bstr(p).unwrap(),
        None => enc.encode_null().unwrap(),
    }
    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
}

// ----- tests -----

/// Cover `header_text_or_utf8_bytes` Text branch (line 79) by encoding
/// content-type as a CBOR text string (tstr) instead of bstr.
#[test]
fn legacy_hash_with_tstr_content_type_succeeds() {
    let artifact = Arc::<[u8]>::from(b"hello world".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    // Content-type encoded as tstr rather than bstr.
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_tstr("application/octet-stream+hash-sha256").unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);
    let v = build_validator(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

/// Cover `header_text_or_utf8_bytes` Text branch for CoseHashV detection.
#[test]
fn cose_hash_v_with_tstr_content_type_succeeds() {
    let artifact = Arc::<[u8]>::from(b"payload".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    let p = EverParseCborProvider;
    let mut hv_enc = p.encoder();
    hv_enc.encode_array(2).unwrap();
    hv_enc.encode_i64(-16).unwrap();
    hv_enc.encode_bstr(expected_hash.as_slice()).unwrap();
    let hv_buf = hv_enc.into_bytes();

    // Content-type as tstr.
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_tstr("application/octet-stream+cose-hash-v").unwrap();
    });

    let cose = build_cose_sign1(&hdr, &hv_buf);
    let v = build_validator(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

/// Cover `parse_cose_hash_v` wrong array length (line 207-208).
#[test]
fn cose_hash_v_fails_when_array_length_is_wrong() {
    let artifact = Arc::<[u8]>::from(b"payload".to_vec().into_boxed_slice());

    // COSE_Hash_V with 3 elements instead of 2.
    let p = EverParseCborProvider;
    let mut hv_enc = p.encoder();
    hv_enc.encode_array(3).unwrap();
    hv_enc.encode_i64(-16).unwrap();
    hv_enc.encode_bstr(b"\x01").unwrap();
    hv_enc.encode_i64(0).unwrap();
    let hv_buf = hv_enc.into_bytes();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+cose-hash-v".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &hv_buf);
    let v = build_validator(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

/// Cover `parse_cose_hash_v` with array length of 1 (too few elements).
#[test]
fn cose_hash_v_fails_when_array_has_one_element() {
    let artifact = Arc::<[u8]>::from(b"payload".to_vec().into_boxed_slice());

    let p = EverParseCborProvider;
    let mut hv_enc = p.encoder();
    hv_enc.encode_array(1).unwrap();
    hv_enc.encode_i64(-16).unwrap();
    let hv_buf = hv_enc.into_bytes();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+cose-hash-v".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &hv_buf);
    let v = build_validator(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_failure());
    assert!(result.overall.is_failure());
}

/// Cover CoseHashV with SHA384 algorithm (-43).
#[test]
fn cose_hash_v_succeeds_with_sha384() {
    let artifact = Arc::<[u8]>::from(b"payload".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha384::digest(artifact.as_ref()).to_vec();

    let p = EverParseCborProvider;
    let mut hv_enc = p.encoder();
    hv_enc.encode_array(2).unwrap();
    hv_enc.encode_i64(-43).unwrap();
    hv_enc.encode_bstr(expected_hash.as_slice()).unwrap();
    let hv_buf = hv_enc.into_bytes();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+cose-hash-v".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &hv_buf);
    let v = build_validator(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

/// Cover CoseHashV with SHA512 algorithm (-44).
#[test]
fn cose_hash_v_succeeds_with_sha512() {
    let artifact = Arc::<[u8]>::from(b"payload".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha512::digest(artifact.as_ref()).to_vec();

    let p = EverParseCborProvider;
    let mut hv_enc = p.encoder();
    hv_enc.encode_array(2).unwrap();
    hv_enc.encode_i64(-44).unwrap();
    hv_enc.encode_bstr(expected_hash.as_slice()).unwrap();
    let hv_buf = hv_enc.into_bytes();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+cose-hash-v".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &hv_buf);
    let v = build_validator(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

/// Cover CoseHashV with SHA1 algorithm (-14).
#[test]
#[cfg(feature = "legacy-sha1")]
fn cose_hash_v_succeeds_with_sha1() {
    let artifact = Arc::<[u8]>::from(b"payload".to_vec().into_boxed_slice());
    let expected_hash = sha1::Sha1::digest(artifact.as_ref()).to_vec();

    let p = EverParseCborProvider;
    let mut hv_enc = p.encoder();
    hv_enc.encode_array(2).unwrap();
    hv_enc.encode_i64(-14).unwrap();
    hv_enc.encode_bstr(expected_hash.as_slice()).unwrap();
    let hv_buf = hv_enc.into_bytes();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_bstr("application/octet-stream+cose-hash-v".as_bytes()).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &hv_buf);
    let v = build_validator(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

/// Cover unprotected header content-type fallback with tstr encoding
/// when header_location is Any (lines 252-257).
#[test]
fn unprotected_tstr_content_type_honored_when_header_location_is_any() {
    let artifact = Arc::<[u8]>::from(b"hello".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    // Protected: {1:-7} (no content-type, no hash envelope marker).
    let hdr = build_protected_header(1, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
    });

    // Unprotected: {3: tstr"application/octet-stream+hash-sha256"}.
    let cose = build_cose_sign1_ex(
        &hdr,
        |enc| {
            enc.encode_map(1).unwrap();
            enc.encode_i64(3).unwrap();
            enc.encode_tstr("application/octet-stream+hash-sha256").unwrap();
        },
        Some(expected_hash.as_slice()),
    );

    let v = build_validator(Some(artifact), Some(CoseHeaderLocation::Any));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

/// Cover case-insensitive regex matching for +cose-hash-v with mixed case.
#[test]
fn cose_hash_v_case_insensitive_content_type() {
    let artifact = Arc::<[u8]>::from(b"payload".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    let p = EverParseCborProvider;
    let mut hv_enc = p.encoder();
    hv_enc.encode_array(2).unwrap();
    hv_enc.encode_i64(-16).unwrap();
    hv_enc.encode_bstr(expected_hash.as_slice()).unwrap();
    let hv_buf = hv_enc.into_bytes();

    // Content-type with mixed case: +COSE-Hash-V
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_tstr("application/octet-stream+COSE-Hash-V").unwrap();
    });

    let cose = build_cose_sign1(&hdr, &hv_buf);
    let v = build_validator(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}

/// Cover case-insensitive regex matching for +hash-* with uppercase.
#[test]
fn legacy_hash_case_insensitive_content_type() {
    let artifact = Arc::<[u8]>::from(b"hello world".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        enc.encode_i64(3).unwrap();
        enc.encode_tstr("application/octet-stream+HASH-SHA256").unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);
    let v = build_validator(Some(artifact), None);
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.overall.is_valid());
    assert!(result.post_signature_policy.is_valid());
}
