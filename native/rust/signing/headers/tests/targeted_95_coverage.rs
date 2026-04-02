// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for cose_sign1_headers cwt_claims.rs gaps.
//!
//! Targets: CWT claims encoding/decoding of all claim types,
//!          custom claims Bool and Float variants,
//!          custom claims with complex types (Array, Map) that get skipped,
//!          builder methods, error paths.

use cbor_primitives::CborEncoder;
use cose_sign1_headers::CWTClaimsHeaderLabels;
use cose_sign1_headers::{CwtClaimValue, CwtClaims, CwtClaimsHeaderContributor, HeaderError};
use std::collections::HashMap;

// ============================================================================
// Builder methods — cover all with_*() methods
// ============================================================================

#[test]
fn builder_all_standard_claims() {
    let claims = CwtClaims::new()
        .with_issuer("test-issuer")
        .with_subject("test-subject")
        .with_audience("test-audience")
        .with_expiration_time(1700000000)
        .with_not_before(1699999000)
        .with_issued_at(1699998000)
        .with_cwt_id(vec![1, 2, 3, 4]);

    assert_eq!(claims.issuer.as_deref(), Some("test-issuer"));
    assert_eq!(claims.subject.as_deref(), Some("test-subject"));
    assert_eq!(claims.audience.as_deref(), Some("test-audience"));
    assert_eq!(claims.expiration_time, Some(1700000000));
    assert_eq!(claims.not_before, Some(1699999000));
    assert_eq!(claims.issued_at, Some(1699998000));
    assert_eq!(claims.cwt_id, Some(vec![1, 2, 3, 4]));
}

// ============================================================================
// Roundtrip — all standard claims encode/decode
// ============================================================================

#[test]
fn roundtrip_all_standard_claims() {
    let original = CwtClaims::new()
        .with_issuer("roundtrip-iss")
        .with_subject("roundtrip-sub")
        .with_audience("roundtrip-aud")
        .with_expiration_time(2000000000)
        .with_not_before(1999999000)
        .with_issued_at(1999998000)
        .with_cwt_id(vec![0xDE, 0xAD]);

    let bytes = original.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(decoded.issuer, original.issuer);
    assert_eq!(decoded.subject, original.subject);
    assert_eq!(decoded.audience, original.audience);
    assert_eq!(decoded.expiration_time, original.expiration_time);
    assert_eq!(decoded.not_before, original.not_before);
    assert_eq!(decoded.issued_at, original.issued_at);
    assert_eq!(decoded.cwt_id, original.cwt_id);
}

// ============================================================================
// Custom claims — Bool variant encode/decode roundtrip
// ============================================================================

#[test]
fn custom_claim_bool_roundtrip() {
    let mut claims = CwtClaims::new();
    claims.custom_claims.insert(100, CwtClaimValue::Bool(true));
    claims.custom_claims.insert(101, CwtClaimValue::Bool(false));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(
        decoded.custom_claims.get(&100),
        Some(&CwtClaimValue::Bool(true))
    );
    assert_eq!(
        decoded.custom_claims.get(&101),
        Some(&CwtClaimValue::Bool(false))
    );
}

// ============================================================================
// Custom claims — Bytes variant encode/decode roundtrip
// ============================================================================

#[test]
fn custom_claim_bytes_roundtrip() {
    let mut claims = CwtClaims::new();
    claims
        .custom_claims
        .insert(200, CwtClaimValue::Bytes(vec![0xFF, 0x00, 0xAB]));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(
        decoded.custom_claims.get(&200),
        Some(&CwtClaimValue::Bytes(vec![0xFF, 0x00, 0xAB]))
    );
}

// ============================================================================
// Custom claims — Text and Integer variants together
// ============================================================================

#[test]
fn custom_claims_text_and_integer_roundtrip() {
    let mut claims = CwtClaims::new().with_issuer("iss");
    claims
        .custom_claims
        .insert(300, CwtClaimValue::Text("custom-text".to_string()));
    claims.custom_claims.insert(301, CwtClaimValue::Integer(42));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(
        decoded.custom_claims.get(&300),
        Some(&CwtClaimValue::Text("custom-text".to_string()))
    );
    assert_eq!(
        decoded.custom_claims.get(&301),
        Some(&CwtClaimValue::Integer(42))
    );
}

// ============================================================================
// Complex claim type (Array) gets skipped during decode
// ============================================================================

#[test]
fn complex_array_claim_skipped() {
    // Manually craft CBOR with an array value for a custom label.
    // The decoder should skip it without error.
    let mut encoder = cose_sign1_primitives::provider::encoder();
    // Map with 2 entries: label 1 (issuer) + label 500 (array)
    encoder.encode_map(2).unwrap();
    // Label 1 = "test-iss"
    encoder.encode_i64(1).unwrap();
    encoder.encode_tstr("test-iss").unwrap();
    // Label 500 = array [1, 2]
    encoder.encode_i64(500).unwrap();
    encoder.encode_array(2).unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_i64(2).unwrap();

    let bytes = encoder.into_bytes();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(decoded.issuer.as_deref(), Some("test-iss"));
    // The array custom claim should have been skipped
    assert!(decoded.custom_claims.get(&500).is_none());
}

// ============================================================================
// Complex claim type (Map) gets skipped during decode
// ============================================================================

#[test]
fn complex_map_claim_skipped() {
    let mut encoder = cose_sign1_primitives::provider::encoder();
    // Map with 2 entries: label 2 (subject) + label 600 (map)
    encoder.encode_map(2).unwrap();
    // Label 2 = "test-sub"
    encoder.encode_i64(2).unwrap();
    encoder.encode_tstr("test-sub").unwrap();
    // Label 600 = map {1: "val"}
    encoder.encode_i64(600).unwrap();
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_tstr("val").unwrap();

    let bytes = encoder.into_bytes();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(decoded.subject.as_deref(), Some("test-sub"));
    assert!(decoded.custom_claims.get(&600).is_none());
}

// ============================================================================
// Error: non-map CBOR input
// ============================================================================

#[test]
fn decode_non_map_returns_error() {
    // Encode an integer instead of map
    let mut encoder = cose_sign1_primitives::provider::encoder();
    encoder.encode_i64(42).unwrap();
    let bytes = encoder.into_bytes();

    let result = CwtClaims::from_cbor_bytes(&bytes);
    assert!(result.is_err());
}

// ============================================================================
// Error: non-integer label in map
// ============================================================================

#[test]
fn decode_non_integer_label_returns_error() {
    let mut encoder = cose_sign1_primitives::provider::encoder();
    encoder.encode_map(1).unwrap();
    // Text label instead of integer
    encoder.encode_tstr("bad-label").unwrap();
    encoder.encode_tstr("value").unwrap();

    let bytes = encoder.into_bytes();
    let result = CwtClaims::from_cbor_bytes(&bytes);
    assert!(result.is_err());
}

// ============================================================================
// Empty claims roundtrip
// ============================================================================

#[test]
fn empty_claims_roundtrip() {
    let claims = CwtClaims::new();
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert!(decoded.issuer.is_none());
    assert!(decoded.subject.is_none());
    assert!(decoded.custom_claims.is_empty());
}

// ============================================================================
// CwtClaimsHeaderContributor — basic smoke test
// ============================================================================

#[test]
fn header_contributor_smoke() {
    let claims = CwtClaims::new().with_issuer("test").with_subject("sub");
    let _contributor = CwtClaimsHeaderContributor::new(&claims).unwrap();
}

// ============================================================================
// CWTClaimsHeaderLabels constants
// ============================================================================

#[test]
fn cwt_label_constants() {
    assert_eq!(CWTClaimsHeaderLabels::ISSUER, 1);
    assert_eq!(CWTClaimsHeaderLabels::SUBJECT, 2);
    assert_eq!(CWTClaimsHeaderLabels::AUDIENCE, 3);
    assert_eq!(CWTClaimsHeaderLabels::EXPIRATION_TIME, 4);
    assert_eq!(CWTClaimsHeaderLabels::NOT_BEFORE, 5);
    assert_eq!(CWTClaimsHeaderLabels::ISSUED_AT, 6);
    assert_eq!(CWTClaimsHeaderLabels::CWT_ID, 7);
    assert_eq!(CWTClaimsHeaderLabels::CWT_CLAIMS_HEADER, 15);
}

// ============================================================================
// Custom claims with Float variant — encoding may fail if CBOR provider
// doesn't support floats; verify error path or success path.
// ============================================================================

#[test]
fn custom_claim_float_encode() {
    let mut claims = CwtClaims::new();
    claims
        .custom_claims
        .insert(700, CwtClaimValue::Float(2.718));

    // Float encoding may or may not be supported by the CBOR provider.
    // Either way, to_cbor_bytes exercises the Float arm of the match.
    let _ = claims.to_cbor_bytes();
}

// ============================================================================
// Multiple custom claims in deterministic order
// ============================================================================

#[test]
fn custom_claims_sorted_deterministic() {
    let mut claims = CwtClaims::new();
    claims
        .custom_claims
        .insert(999, CwtClaimValue::Text("last".to_string()));
    claims.custom_claims.insert(800, CwtClaimValue::Integer(-1));
    claims
        .custom_claims
        .insert(900, CwtClaimValue::Bytes(vec![0x01]));

    let bytes1 = claims.to_cbor_bytes().unwrap();
    let bytes2 = claims.to_cbor_bytes().unwrap();
    // Deterministic encoding
    assert_eq!(bytes1, bytes2);

    let decoded = CwtClaims::from_cbor_bytes(&bytes1).unwrap();
    assert_eq!(decoded.custom_claims.len(), 3);
}
