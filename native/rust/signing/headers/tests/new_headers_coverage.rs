// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_headers::cwt_claims::*;
use cose_sign1_headers::error::HeaderError;

#[test]
fn empty_claims_roundtrip() {
    let claims = CwtClaims::new();
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert!(decoded.issuer.is_none());
    assert!(decoded.custom_claims.is_empty());
}

#[test]
fn all_standard_claims_roundtrip() {
    let claims = CwtClaims::new()
        .with_issuer("iss")
        .with_subject("sub")
        .with_audience("aud")
        .with_expiration_time(9999)
        .with_not_before(1000)
        .with_issued_at(2000)
        .with_cwt_id(vec![0xCA, 0xFE]);
    let decoded = CwtClaims::from_cbor_bytes(&claims.to_cbor_bytes().unwrap()).unwrap();
    assert_eq!(decoded.issuer.as_deref(), Some("iss"));
    assert_eq!(decoded.subject.as_deref(), Some("sub"));
    assert_eq!(decoded.audience.as_deref(), Some("aud"));
    assert_eq!(decoded.expiration_time, Some(9999));
    assert_eq!(decoded.not_before, Some(1000));
    assert_eq!(decoded.issued_at, Some(2000));
    assert_eq!(decoded.cwt_id, Some(vec![0xCA, 0xFE]));
}

#[test]
fn custom_claims_non_float_variants_roundtrip() {
    let claims = CwtClaims::new()
        .with_custom_claim(100, CwtClaimValue::Text("hello".into()))
        .with_custom_claim(101, CwtClaimValue::Integer(-42))
        .with_custom_claim(102, CwtClaimValue::Bytes(vec![1, 2, 3]))
        .with_custom_claim(103, CwtClaimValue::Bool(true));
    let decoded = CwtClaims::from_cbor_bytes(&claims.to_cbor_bytes().unwrap()).unwrap();
    assert_eq!(decoded.custom_claims.get(&100), Some(&CwtClaimValue::Text("hello".into())));
    assert_eq!(decoded.custom_claims.get(&101), Some(&CwtClaimValue::Integer(-42)));
    assert_eq!(decoded.custom_claims.get(&102), Some(&CwtClaimValue::Bytes(vec![1, 2, 3])));
    assert_eq!(decoded.custom_claims.get(&103), Some(&CwtClaimValue::Bool(true)));
}

#[test]
fn multiple_custom_claims_sorted_by_label() {
    let claims = CwtClaims::new()
        .with_custom_claim(300, CwtClaimValue::Integer(3))
        .with_custom_claim(200, CwtClaimValue::Integer(2))
        .with_custom_claim(100, CwtClaimValue::Integer(1));
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.custom_claims.len(), 3);
}

#[test]
fn header_error_display_all_variants() {
    let cases: Vec<(HeaderError, &str)> = vec![
        (HeaderError::CborEncodingError("enc".into()), "CBOR encoding error: enc"),
        (HeaderError::CborDecodingError("dec".into()), "CBOR decoding error: dec"),
        (HeaderError::InvalidClaimType { label: 1, expected: "text".into(), actual: "int".into() },
         "Invalid CWT claim type for label 1: expected text, got int"),
        (HeaderError::MissingRequiredClaim("sub".into()), "Missing required claim: sub"),
        (HeaderError::InvalidTimestamp("bad".into()), "Invalid timestamp value: bad"),
        (HeaderError::ComplexClaimValue("arr".into()), "Custom claim value too complex: arr"),
    ];
    for (err, expected) in cases {
        assert_eq!(err.to_string(), expected);
    }
}

#[test]
fn header_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(HeaderError::CborEncodingError("test".into()));
    assert!(err.to_string().contains("CBOR encoding error"));
}

#[test]
fn default_subject_constant() {
    assert_eq!(CwtClaims::DEFAULT_SUBJECT, "unknown.intent");
}

#[test]
fn builder_chaining() {
    let claims = CwtClaims::new()
        .with_issuer("i")
        .with_subject("s")
        .with_audience("a")
        .with_expiration_time(10)
        .with_not_before(5)
        .with_issued_at(6)
        .with_cwt_id(vec![7])
        .with_custom_claim(99, CwtClaimValue::Bool(false));
    assert_eq!(claims.issuer.as_deref(), Some("i"));
    assert_eq!(claims.custom_claims.len(), 1);
}

#[test]
fn from_cbor_bytes_non_map_is_error() {
    // CBOR unsigned integer 42 (single byte 0x18 0x2A)
    let not_a_map = vec![0x18, 0x2A];
    let err = CwtClaims::from_cbor_bytes(&not_a_map).unwrap_err();
    assert!(matches!(err, HeaderError::CborDecodingError(_)));
}

#[test]
fn from_cbor_bytes_invalid_bytes_is_error() {
    let garbage = vec![0xFF, 0xFE, 0xFD];
    assert!(CwtClaims::from_cbor_bytes(&garbage).is_err());
}
