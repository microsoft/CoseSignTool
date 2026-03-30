// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for CwtClaims builder, serialization, and deserialization.
//!
//! Targets uncovered lines in cwt_claims.rs:
//! - Builder methods (with_issuer, with_subject, with_audience, etc.)
//! - Serialization of all standard claim types
//! - Serialization of custom claims (Text, Integer, Bytes, Bool, Float)
//! - Deserialization round-trip
//! - Deserialization error paths (non-map input, non-integer label)
//! - Custom claim type decoding (all variants)

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_headers::{CwtClaimValue, CwtClaims};

// =========================================================================
// Builder method coverage
// =========================================================================

#[test]
fn builder_with_issuer() {
    let claims = CwtClaims::new().with_issuer("test-issuer");
    assert_eq!(claims.issuer.as_deref(), Some("test-issuer"));
}

#[test]
fn builder_with_subject() {
    let claims = CwtClaims::new().with_subject("test-subject");
    assert_eq!(claims.subject.as_deref(), Some("test-subject"));
}

#[test]
fn builder_with_audience() {
    let claims = CwtClaims::new().with_audience("test-audience");
    assert_eq!(claims.audience.as_deref(), Some("test-audience"));
}

#[test]
fn builder_with_expiration_time() {
    let claims = CwtClaims::new().with_expiration_time(1700000000);
    assert_eq!(claims.expiration_time, Some(1700000000));
}

#[test]
fn builder_with_not_before() {
    let claims = CwtClaims::new().with_not_before(1600000000);
    assert_eq!(claims.not_before, Some(1600000000));
}

#[test]
fn builder_with_issued_at() {
    let claims = CwtClaims::new().with_issued_at(1650000000);
    assert_eq!(claims.issued_at, Some(1650000000));
}

#[test]
fn builder_with_cwt_id() {
    let cti = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let claims = CwtClaims::new().with_cwt_id(cti.clone());
    assert_eq!(claims.cwt_id, Some(cti));
}

#[test]
fn builder_with_custom_claim_text() {
    let claims =
        CwtClaims::new().with_custom_claim(100, CwtClaimValue::Text("custom-value".to_string()));
    assert_eq!(
        claims.custom_claims.get(&100),
        Some(&CwtClaimValue::Text("custom-value".to_string()))
    );
}

#[test]
fn builder_with_custom_claim_integer() {
    let claims = CwtClaims::new().with_custom_claim(101, CwtClaimValue::Integer(42));
    assert_eq!(
        claims.custom_claims.get(&101),
        Some(&CwtClaimValue::Integer(42))
    );
}

#[test]
fn builder_with_custom_claim_bytes() {
    let claims = CwtClaims::new().with_custom_claim(102, CwtClaimValue::Bytes(vec![1, 2, 3]));
    assert_eq!(
        claims.custom_claims.get(&102),
        Some(&CwtClaimValue::Bytes(vec![1, 2, 3]))
    );
}

#[test]
fn builder_with_custom_claim_bool() {
    let claims = CwtClaims::new().with_custom_claim(103, CwtClaimValue::Bool(true));
    assert_eq!(
        claims.custom_claims.get(&103),
        Some(&CwtClaimValue::Bool(true))
    );
}

#[test]
fn builder_with_custom_claim_float() {
    let claims = CwtClaims::new().with_custom_claim(104, CwtClaimValue::Float(3.14));
    assert_eq!(
        claims.custom_claims.get(&104),
        Some(&CwtClaimValue::Float(3.14))
    );
}

#[test]
fn builder_chained() {
    let claims = CwtClaims::new()
        .with_issuer("iss")
        .with_subject("sub")
        .with_audience("aud")
        .with_expiration_time(2000000000)
        .with_not_before(1000000000)
        .with_issued_at(1500000000)
        .with_cwt_id(vec![0x01, 0x02])
        .with_custom_claim(200, CwtClaimValue::Text("extra".to_string()));

    assert_eq!(claims.issuer.as_deref(), Some("iss"));
    assert_eq!(claims.subject.as_deref(), Some("sub"));
    assert_eq!(claims.audience.as_deref(), Some("aud"));
    assert_eq!(claims.expiration_time, Some(2000000000));
    assert_eq!(claims.not_before, Some(1000000000));
    assert_eq!(claims.issued_at, Some(1500000000));
    assert_eq!(claims.cwt_id, Some(vec![0x01, 0x02]));
    assert!(claims.custom_claims.contains_key(&200));
}

// =========================================================================
// Serialization coverage (all standard fields + custom claims)
// =========================================================================

#[test]
fn serialize_all_standard_claims() {
    let claims = CwtClaims::new()
        .with_issuer("test-issuer")
        .with_subject("test-subject")
        .with_audience("test-audience")
        .with_expiration_time(2000000000)
        .with_not_before(1000000000)
        .with_issued_at(1500000000)
        .with_cwt_id(vec![0xCA, 0xFE]);

    let bytes = claims.to_cbor_bytes().unwrap();
    assert!(!bytes.is_empty());

    // Round-trip
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.issuer.as_deref(), Some("test-issuer"));
    assert_eq!(decoded.subject.as_deref(), Some("test-subject"));
    assert_eq!(decoded.audience.as_deref(), Some("test-audience"));
    assert_eq!(decoded.expiration_time, Some(2000000000));
    assert_eq!(decoded.not_before, Some(1000000000));
    assert_eq!(decoded.issued_at, Some(1500000000));
    assert_eq!(decoded.cwt_id, Some(vec![0xCA, 0xFE]));
}

#[test]
fn serialize_empty_claims() {
    let claims = CwtClaims::new();
    let bytes = claims.to_cbor_bytes().unwrap();
    assert!(!bytes.is_empty());

    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert!(decoded.issuer.is_none());
    assert!(decoded.subject.is_none());
    assert!(decoded.audience.is_none());
    assert!(decoded.expiration_time.is_none());
    assert!(decoded.not_before.is_none());
    assert!(decoded.issued_at.is_none());
    assert!(decoded.cwt_id.is_none());
    assert!(decoded.custom_claims.is_empty());
}

#[test]
fn serialize_custom_text_claim_roundtrip() {
    let claims = CwtClaims::new().with_custom_claim(100, CwtClaimValue::Text("hello".to_string()));
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(
        decoded.custom_claims.get(&100),
        Some(&CwtClaimValue::Text("hello".to_string()))
    );
}

#[test]
fn serialize_custom_integer_claim_roundtrip() {
    let claims = CwtClaims::new().with_custom_claim(101, CwtClaimValue::Integer(-42));
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(
        decoded.custom_claims.get(&101),
        Some(&CwtClaimValue::Integer(-42))
    );
}

#[test]
fn serialize_custom_bytes_claim_roundtrip() {
    let claims = CwtClaims::new().with_custom_claim(102, CwtClaimValue::Bytes(vec![0xDE, 0xAD]));
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(
        decoded.custom_claims.get(&102),
        Some(&CwtClaimValue::Bytes(vec![0xDE, 0xAD]))
    );
}

#[test]
fn serialize_custom_bool_claim_roundtrip() {
    let claims = CwtClaims::new().with_custom_claim(103, CwtClaimValue::Bool(false));
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(
        decoded.custom_claims.get(&103),
        Some(&CwtClaimValue::Bool(false))
    );
}

#[test]
fn serialize_custom_float_claim_errors() {
    // EverParse CBOR provider doesn't support float encoding
    let claims = CwtClaims::new().with_custom_claim(104, CwtClaimValue::Float(2.718));
    let result = claims.to_cbor_bytes();
    assert!(result.is_err(), "Float encoding should fail with EverParse");
}

#[test]
fn serialize_multiple_custom_claims_sorted() {
    // Custom claims should be sorted by label for deterministic encoding
    let claims = CwtClaims::new()
        .with_custom_claim(300, CwtClaimValue::Text("third".to_string()))
        .with_custom_claim(100, CwtClaimValue::Integer(1))
        .with_custom_claim(200, CwtClaimValue::Bool(true));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.custom_claims.len(), 3);
    assert_eq!(
        decoded.custom_claims.get(&100),
        Some(&CwtClaimValue::Integer(1))
    );
    assert_eq!(
        decoded.custom_claims.get(&200),
        Some(&CwtClaimValue::Bool(true))
    );
    assert_eq!(
        decoded.custom_claims.get(&300),
        Some(&CwtClaimValue::Text("third".to_string()))
    );
}

// =========================================================================
// Deserialization error paths
// =========================================================================

#[test]
fn deserialize_non_map_input() {
    // CBOR integer instead of map
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_i64(42).unwrap();
    let bytes = enc.as_bytes().to_vec();

    let result = CwtClaims::from_cbor_bytes(&bytes);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("Expected CBOR map"));
}

#[test]
fn deserialize_non_integer_label() {
    // Map with text string label instead of integer
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("not-an-int").unwrap();
    enc.encode_tstr("value").unwrap();
    let bytes = enc.as_bytes().to_vec();

    let result = CwtClaims::from_cbor_bytes(&bytes);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("must be integer"));
}

#[test]
fn deserialize_empty_bytes() {
    let result = CwtClaims::from_cbor_bytes(&[]);
    assert!(result.is_err());
}

// =========================================================================
// Default subject constant
// =========================================================================

#[test]
fn default_subject_constant() {
    assert_eq!(CwtClaims::DEFAULT_SUBJECT, "unknown.intent");
}

// =========================================================================
// CwtClaimValue Debug/Clone/PartialEq
// =========================================================================

#[test]
fn claim_value_debug_and_clone() {
    let values = vec![
        CwtClaimValue::Text("hello".to_string()),
        CwtClaimValue::Integer(42),
        CwtClaimValue::Bytes(vec![1, 2]),
        CwtClaimValue::Bool(true),
        CwtClaimValue::Float(1.5),
    ];

    for v in &values {
        let cloned = v.clone();
        assert_eq!(&cloned, v);
        let debug = format!("{:?}", v);
        assert!(!debug.is_empty());
    }
}

#[test]
fn claim_value_inequality() {
    assert_ne!(
        CwtClaimValue::Text("a".to_string()),
        CwtClaimValue::Text("b".to_string())
    );
    assert_ne!(CwtClaimValue::Integer(1), CwtClaimValue::Integer(2));
    assert_ne!(CwtClaimValue::Bool(true), CwtClaimValue::Bool(false));
}

// =========================================================================
// CwtClaims Default and Debug
// =========================================================================

#[test]
fn cwt_claims_default() {
    let claims = CwtClaims::default();
    assert!(claims.issuer.is_none());
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn cwt_claims_debug() {
    let claims = CwtClaims::new().with_issuer("debug-test");
    let debug = format!("{:?}", claims);
    assert!(debug.contains("debug-test"));
}

#[test]
fn cwt_claims_clone() {
    let claims = CwtClaims::new()
        .with_issuer("clone-test")
        .with_custom_claim(50, CwtClaimValue::Integer(99));
    let cloned = claims.clone();
    assert_eq!(cloned.issuer, claims.issuer);
    assert_eq!(cloned.custom_claims, claims.custom_claims);
}

// =========================================================================
// Mixed standard + custom claims roundtrip
// =========================================================================

#[test]
fn full_roundtrip_standard_and_custom() {
    let claims = CwtClaims::new()
        .with_issuer("full-test-issuer")
        .with_subject("full-test-subject")
        .with_audience("full-test-audience")
        .with_expiration_time(9999999999)
        .with_not_before(1000000000)
        .with_issued_at(1500000000)
        .with_cwt_id(vec![0x01, 0x02, 0x03, 0x04])
        .with_custom_claim(100, CwtClaimValue::Text("extra-text".to_string()))
        .with_custom_claim(101, CwtClaimValue::Integer(-100))
        .with_custom_claim(102, CwtClaimValue::Bytes(vec![0xFF]))
        .with_custom_claim(103, CwtClaimValue::Bool(true));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(decoded.issuer.as_deref(), Some("full-test-issuer"));
    assert_eq!(decoded.subject.as_deref(), Some("full-test-subject"));
    assert_eq!(decoded.audience.as_deref(), Some("full-test-audience"));
    assert_eq!(decoded.expiration_time, Some(9999999999));
    assert_eq!(decoded.not_before, Some(1000000000));
    assert_eq!(decoded.issued_at, Some(1500000000));
    assert_eq!(decoded.cwt_id, Some(vec![0x01, 0x02, 0x03, 0x04]));
    assert_eq!(decoded.custom_claims.len(), 4);
}
