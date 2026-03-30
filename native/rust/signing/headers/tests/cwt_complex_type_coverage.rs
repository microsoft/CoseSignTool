// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests targeting the complex type skipping fallback chains in
//! CwtClaims::from_cbor_bytes — array/map element decoding with
//! mixed types (text, bytes, bool) and empty collections.

use cose_sign1_headers::cwt_claims::CwtClaims;
use cbor_primitives::CborEncoder;

/// Helper: create a CBOR encoder via the provider.
fn encoder() -> cbor_primitives_everparse::EverParseEncoder {
    cbor_primitives_everparse::EverParseEncoder::new()
}

// ---------------------------------------------------------------------------
// Array element type fallbacks (covers lines 293-299)
// ---------------------------------------------------------------------------

#[test]
fn array_with_text_elements_skipped() {
    // Map { 100: ["hello", "world"] }
    let mut enc = encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(100).unwrap();
    enc.encode_array(2).unwrap();
    enc.encode_tstr("hello").unwrap();
    enc.encode_tstr("world").unwrap();

    let cbor = enc.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&cbor).expect("should succeed");
    // Array claim should be skipped (not storable as CwtClaimValue)
    assert!(
        claims.custom_claims.is_empty(),
        "array claims should be skipped"
    );
}

#[test]
fn array_with_bytes_elements_skipped() {
    // Map { 101: [h'AABB', h'CCDD'] }
    let mut enc = encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(101).unwrap();
    enc.encode_array(2).unwrap();
    enc.encode_bstr(&[0xAA, 0xBB]).unwrap();
    enc.encode_bstr(&[0xCC, 0xDD]).unwrap();

    let cbor = enc.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&cbor).expect("should succeed");
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn array_with_bool_elements_skipped() {
    // Map { 102: [true, false, true] }
    let mut enc = encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(102).unwrap();
    enc.encode_array(3).unwrap();
    enc.encode_bool(true).unwrap();
    enc.encode_bool(false).unwrap();
    enc.encode_bool(true).unwrap();

    let cbor = enc.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&cbor).expect("should succeed");
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn array_with_mixed_int_text_bytes_bool() {
    // Map { 103: [42, "text", h'FF', true] }
    let mut enc = encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(103).unwrap();
    enc.encode_array(4).unwrap();
    enc.encode_i64(42).unwrap();
    enc.encode_tstr("text").unwrap();
    enc.encode_bstr(&[0xFF]).unwrap();
    enc.encode_bool(true).unwrap();

    let cbor = enc.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&cbor).expect("should succeed");
    assert!(claims.custom_claims.is_empty());
}

// ---------------------------------------------------------------------------
// Map key-value fallback chains (covers lines 308-315)
// ---------------------------------------------------------------------------

#[test]
fn map_with_text_keys_and_text_values_skipped() {
    // Map { 104: { "key1": "val1", "key2": "val2" } }
    let mut enc = encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(104).unwrap();
    enc.encode_map(2).unwrap();
    enc.encode_tstr("key1").unwrap();
    enc.encode_tstr("val1").unwrap();
    enc.encode_tstr("key2").unwrap();
    enc.encode_tstr("val2").unwrap();

    let cbor = enc.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&cbor).expect("should succeed");
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn map_with_text_keys_and_bytes_values_skipped() {
    // Map { 105: { "k": h'AABB' } }
    let mut enc = encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(105).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("k").unwrap();
    enc.encode_bstr(&[0xAA, 0xBB]).unwrap();

    let cbor = enc.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&cbor).expect("should succeed");
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn map_with_text_keys_and_bool_values_skipped() {
    // Map { 106: { "flag": true } }
    let mut enc = encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(106).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("flag").unwrap();
    enc.encode_bool(true).unwrap();

    let cbor = enc.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&cbor).expect("should succeed");
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn map_with_int_keys_and_mixed_values_skipped() {
    // Map { 107: { 1: "text", 2: h'FF', 3: true } }
    let mut enc = encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(107).unwrap();
    enc.encode_map(3).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_tstr("text").unwrap();
    enc.encode_i64(2).unwrap();
    enc.encode_bstr(&[0xFF]).unwrap();
    enc.encode_i64(3).unwrap();
    enc.encode_bool(true).unwrap();

    let cbor = enc.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&cbor).expect("should succeed");
    assert!(claims.custom_claims.is_empty());
}

// ---------------------------------------------------------------------------
// Empty array/map edge cases (covers len=0 branches)
// ---------------------------------------------------------------------------

#[test]
fn empty_array_claim_skipped() {
    // Map { 108: [] }
    let mut enc = encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(108).unwrap();
    enc.encode_array(0).unwrap();

    let cbor = enc.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&cbor).expect("should succeed");
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn empty_map_claim_skipped() {
    // Map { 109: {} }
    let mut enc = encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(109).unwrap();
    enc.encode_map(0).unwrap();

    let cbor = enc.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&cbor).expect("should succeed");
    assert!(claims.custom_claims.is_empty());
}

// ---------------------------------------------------------------------------
// Mixed: standard claims + one array custom claim
// ---------------------------------------------------------------------------

#[test]
fn standard_claims_with_array_custom_parsed() {
    // Map { 1: "issuer", 100: [42] }
    let mut enc = encoder();
    enc.encode_map(2).unwrap();

    // iss = "issuer"
    enc.encode_i64(1).unwrap();
    enc.encode_tstr("issuer").unwrap();

    // label 100 = array [42]
    enc.encode_i64(100).unwrap();
    enc.encode_array(1).unwrap();
    enc.encode_i64(42).unwrap();

    let cbor = enc.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&cbor).expect("should succeed");
    assert_eq!(claims.issuer.as_deref(), Some("issuer"));
    // array custom claim is skipped
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn standard_claims_with_map_custom_parsed() {
    // Map { 2: "subject", 101: {1: 2} }
    let mut enc = encoder();
    enc.encode_map(2).unwrap();

    // sub = "subject"
    enc.encode_i64(2).unwrap();
    enc.encode_tstr("subject").unwrap();

    // label 101 = map {1: 2}
    enc.encode_i64(101).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(2).unwrap();

    let cbor = enc.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&cbor).expect("should succeed");
    assert_eq!(claims.subject.as_deref(), Some("subject"));
    assert!(claims.custom_claims.is_empty());
}
