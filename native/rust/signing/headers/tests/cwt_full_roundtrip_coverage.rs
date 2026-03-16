// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Full-field CWT claims round-trip coverage: exercises encode AND decode
//! for every standard claim field and every custom claim value type.

use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_headers::CwtClaims;
use cose_sign1_headers::cwt_claims::CwtClaimValue;

fn _init() -> EverParseCborProvider {
    EverParseCborProvider
}

#[test]
fn roundtrip_all_standard_claims() {
    let _p = _init();

    let claims = CwtClaims::new()
        .with_issuer("did:x509:test_issuer".to_string())
        .with_subject("test.subject.v1".to_string())
        .with_audience("https://audience.example.com".to_string())
        .with_expiration_time(1700000000)
        .with_not_before(1690000000)
        .with_issued_at(1695000000)
        .with_cwt_id(vec![0xDE, 0xAD, 0xBE, 0xEF]);

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(decoded.issuer.as_deref(), Some("did:x509:test_issuer"));
    assert_eq!(decoded.subject.as_deref(), Some("test.subject.v1"));
    assert_eq!(decoded.audience.as_deref(), Some("https://audience.example.com"));
    assert_eq!(decoded.expiration_time, Some(1700000000));
    assert_eq!(decoded.not_before, Some(1690000000));
    assert_eq!(decoded.issued_at, Some(1695000000));
    assert_eq!(decoded.cwt_id, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
}

#[test]
fn roundtrip_custom_text_claim() {
    let _p = _init();

    let mut claims = CwtClaims::new().with_issuer("iss".to_string());
    claims.custom_claims.insert(100, CwtClaimValue::Text("custom-text".to_string()));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(
        decoded.custom_claims.get(&100),
        Some(&CwtClaimValue::Text("custom-text".to_string()))
    );
}

#[test]
fn roundtrip_custom_integer_claim() {
    let _p = _init();

    let mut claims = CwtClaims::new();
    claims.custom_claims.insert(200, CwtClaimValue::Integer(42));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(
        decoded.custom_claims.get(&200),
        Some(&CwtClaimValue::Integer(42))
    );
}

#[test]
fn roundtrip_custom_bytes_claim() {
    let _p = _init();

    let mut claims = CwtClaims::new();
    claims.custom_claims.insert(300, CwtClaimValue::Bytes(vec![1, 2, 3]));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(
        decoded.custom_claims.get(&300),
        Some(&CwtClaimValue::Bytes(vec![1, 2, 3]))
    );
}

#[test]
fn roundtrip_custom_bool_claim() {
    let _p = _init();

    let mut claims = CwtClaims::new();
    claims.custom_claims.insert(400, CwtClaimValue::Bool(true));
    claims.custom_claims.insert(401, CwtClaimValue::Bool(false));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(decoded.custom_claims.get(&400), Some(&CwtClaimValue::Bool(true)));
    assert_eq!(decoded.custom_claims.get(&401), Some(&CwtClaimValue::Bool(false)));
}

#[test]
fn roundtrip_custom_float_claim_encode_error() {
    let _p = _init();

    let mut claims = CwtClaims::new();
    claims.custom_claims.insert(500, CwtClaimValue::Float(3.14));

    // Float encoding is not supported by the CBOR encoder
    let result = claims.to_cbor_bytes();
    assert!(result.is_err());
}

#[test]
fn roundtrip_all_custom_types_together() {
    let _p = _init();

    let mut claims = CwtClaims::new()
        .with_issuer("iss".to_string())
        .with_subject("sub".to_string())
        .with_audience("aud".to_string())
        .with_expiration_time(999)
        .with_not_before(100)
        .with_issued_at(500)
        .with_cwt_id(vec![0x01]);

    claims.custom_claims.insert(10, CwtClaimValue::Text("txt".to_string()));
    claims.custom_claims.insert(11, CwtClaimValue::Integer(-99));
    claims.custom_claims.insert(12, CwtClaimValue::Bytes(vec![0xFF]));
    claims.custom_claims.insert(13, CwtClaimValue::Bool(true));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(decoded.issuer.as_deref(), Some("iss"));
    assert_eq!(decoded.subject.as_deref(), Some("sub"));
    assert_eq!(decoded.audience.as_deref(), Some("aud"));
    assert_eq!(decoded.expiration_time, Some(999));
    assert_eq!(decoded.not_before, Some(100));
    assert_eq!(decoded.issued_at, Some(500));
    assert_eq!(decoded.cwt_id, Some(vec![0x01]));
    assert_eq!(decoded.custom_claims.len(), 4);
    assert_eq!(decoded.custom_claims.get(&10), Some(&CwtClaimValue::Text("txt".to_string())));
    assert_eq!(decoded.custom_claims.get(&11), Some(&CwtClaimValue::Integer(-99)));
    assert_eq!(decoded.custom_claims.get(&12), Some(&CwtClaimValue::Bytes(vec![0xFF])));
    assert_eq!(decoded.custom_claims.get(&13), Some(&CwtClaimValue::Bool(true)));
}

#[test]
fn roundtrip_subject_only() {
    let _p = _init();
    let claims = CwtClaims::new().with_subject("only-subject".to_string());
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.subject.as_deref(), Some("only-subject"));
    assert!(decoded.issuer.is_none());
}

#[test]
fn roundtrip_audience_only() {
    let _p = _init();
    let claims = CwtClaims::new().with_audience("only-audience".to_string());
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.audience.as_deref(), Some("only-audience"));
}

#[test]
fn roundtrip_cwt_id_only() {
    let _p = _init();
    let claims = CwtClaims::new().with_cwt_id(vec![0xCA, 0xFE]);
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.cwt_id, Some(vec![0xCA, 0xFE]));
}

#[test]
fn roundtrip_timestamps_only() {
    let _p = _init();
    let claims = CwtClaims::new()
        .with_expiration_time(2000000000)
        .with_not_before(1000000000)
        .with_issued_at(1500000000);
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.expiration_time, Some(2000000000));
    assert_eq!(decoded.not_before, Some(1000000000));
    assert_eq!(decoded.issued_at, Some(1500000000));
}
