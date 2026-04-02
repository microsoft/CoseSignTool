// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for CWT claims — exercises ALL claim value types
//! and round-trip encoding/decoding paths.

use cbor_primitives::CborEncoder;
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_headers::{CwtClaimValue, CwtClaims};

// ========================================================================
// Round-trip: ALL standard claims populated
// ========================================================================

#[test]
fn round_trip_all_standard_claims() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("test-issuer".into());
    claims.subject = Some("test-subject".into());
    claims.audience = Some("test-audience".into());
    claims.expiration_time = Some(1700000000);
    claims.not_before = Some(1600000000);
    claims.issued_at = Some(1650000000);
    claims.cwt_id = Some(vec![0x01, 0x02, 0x03]);

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(decoded.issuer, claims.issuer);
    assert_eq!(decoded.subject, claims.subject);
    assert_eq!(decoded.audience, claims.audience);
    assert_eq!(decoded.expiration_time, claims.expiration_time);
    assert_eq!(decoded.not_before, claims.not_before);
    assert_eq!(decoded.issued_at, claims.issued_at);
    assert_eq!(decoded.cwt_id, claims.cwt_id);
}

#[test]
fn round_trip_full_claims_struct_equality() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("acme-corp".into());
    claims.subject = Some("device-42".into());
    claims.audience = Some("api.example.com".into());
    claims.expiration_time = Some(1800000000);
    claims.not_before = Some(1700000000);
    claims.issued_at = Some(1750000000);
    claims.cwt_id = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    claims
        .custom_claims
        .insert(100, CwtClaimValue::Text("custom-text".into()));
    claims
        .custom_claims
        .insert(200, CwtClaimValue::Integer(-999));
    claims
        .custom_claims
        .insert(300, CwtClaimValue::Bytes(vec![0x01, 0x02, 0x03]));
    claims.custom_claims.insert(400, CwtClaimValue::Bool(true));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    // PartialEq-based whole-struct assertion
    assert_eq!(
        decoded, claims,
        "Full CWT claims roundtrip must be lossless"
    );
}

// ========================================================================
// Round-trip: custom claims of every value type
// ========================================================================

#[test]
fn round_trip_custom_text_claim() {
    let mut claims = CwtClaims::new();
    claims
        .custom_claims
        .insert(100, CwtClaimValue::Text("hello".into()));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(
        decoded.custom_claims.get(&100),
        Some(&CwtClaimValue::Text("hello".into()))
    );
}

#[test]
fn round_trip_custom_integer_claim() {
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
fn round_trip_custom_bytes_claim() {
    let mut claims = CwtClaims::new();
    claims
        .custom_claims
        .insert(300, CwtClaimValue::Bytes(vec![0xAA, 0xBB]));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(
        decoded.custom_claims.get(&300),
        Some(&CwtClaimValue::Bytes(vec![0xAA, 0xBB]))
    );
}

#[test]
fn round_trip_custom_bool_claim() {
    let mut claims = CwtClaims::new();
    claims.custom_claims.insert(400, CwtClaimValue::Bool(true));
    claims.custom_claims.insert(401, CwtClaimValue::Bool(false));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(
        decoded.custom_claims.get(&400),
        Some(&CwtClaimValue::Bool(true))
    );
    assert_eq!(
        decoded.custom_claims.get(&401),
        Some(&CwtClaimValue::Bool(false))
    );
}

#[test]
fn encode_custom_float_claim_unsupported() {
    // Float encoding is not supported by the CBOR provider — verify it errors cleanly
    let mut claims = CwtClaims::new();
    claims.custom_claims.insert(500, CwtClaimValue::Float(3.14));
    let result = claims.to_cbor_bytes();
    assert!(result.is_err());
}

#[test]
fn round_trip_multiple_custom_claims() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("iss".into());
    claims
        .custom_claims
        .insert(10, CwtClaimValue::Text("ten".into()));
    claims.custom_claims.insert(20, CwtClaimValue::Integer(20));
    claims
        .custom_claims
        .insert(30, CwtClaimValue::Bytes(vec![0x30]));
    claims.custom_claims.insert(40, CwtClaimValue::Bool(true));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(decoded.issuer.as_deref(), Some("iss"));
    assert_eq!(decoded.custom_claims.len(), 4);
}

// ========================================================================
// Decode: custom claim with array value (skip path)
// ========================================================================

#[test]
fn decode_custom_claim_with_array_skips() {
    // Build CBOR map with a custom claim whose value is an array
    // The decoder should skip it gracefully
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(2).unwrap();
    // Standard claim: issuer
    enc.encode_i64(1).unwrap();
    enc.encode_tstr("test-iss").unwrap();
    // Custom claim with array value (label 999)
    enc.encode_i64(999).unwrap();
    enc.encode_array(2).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(2).unwrap();
    let bytes = enc.into_bytes();

    let claims = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(claims.issuer.as_deref(), Some("test-iss"));
    // The array custom claim should be skipped
    assert!(!claims.custom_claims.contains_key(&999));
}

#[test]
fn decode_custom_claim_with_map_skips() {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(2).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_tstr("test-iss").unwrap();
    // Custom claim with map value (label 888)
    enc.encode_i64(888).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("key").unwrap();
    enc.encode_tstr("val").unwrap();
    let bytes = enc.into_bytes();

    let claims = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(claims.issuer.as_deref(), Some("test-iss"));
    assert!(!claims.custom_claims.contains_key(&888));
}

// ========================================================================
// Decode: error cases
// ========================================================================

#[test]
fn decode_non_map() {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(0).unwrap();
    let bytes = enc.into_bytes();
    let err = CwtClaims::from_cbor_bytes(&bytes);
    assert!(err.is_err());
}

#[test]
fn decode_non_integer_label() {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("string-label").unwrap(); // labels must be integers
    enc.encode_tstr("value").unwrap();
    let bytes = enc.into_bytes();
    let err = CwtClaims::from_cbor_bytes(&bytes);
    assert!(err.is_err());
}

#[test]
fn decode_empty_map() {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(0).unwrap();
    let bytes = enc.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert!(claims.issuer.is_none());
}

// ========================================================================
// Encode: empty claims
// ========================================================================

#[test]
fn encode_empty_claims() {
    let claims = CwtClaims::new();
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert!(decoded.issuer.is_none());
    assert!(decoded.custom_claims.is_empty());
}

// ========================================================================
// Encode: negative custom label
// ========================================================================

#[test]
fn round_trip_negative_label_custom_claim() {
    let mut claims = CwtClaims::new();
    claims
        .custom_claims
        .insert(-100, CwtClaimValue::Text("negative".into()));
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(
        decoded.custom_claims.get(&-100),
        Some(&CwtClaimValue::Text("negative".into()))
    );
}

// ========================================================================
// Builder methods (with_ pattern)
// ========================================================================

#[test]
fn builder_with_issuer() {
    let claims = CwtClaims::new().with_issuer("my-issuer".to_string());
    assert_eq!(claims.issuer.as_deref(), Some("my-issuer"));
}

#[test]
fn builder_with_subject() {
    let claims = CwtClaims::new().with_subject("my-subject".to_string());
    assert_eq!(claims.subject.as_deref(), Some("my-subject"));
}
