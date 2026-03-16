// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for CwtClaims encode/decode paths.
//!
//! Covers uncovered lines in `cwt_claims.rs`:
//! - Lines 96–179: `to_cbor_bytes()` encode path for every optional field + custom claims
//! - Lines 200–317: `from_cbor_bytes()` decode path including custom claim type dispatch
//!
//! Strategy: build claims with ALL fields populated (including Float custom claims),
//! round-trip through CBOR, and verify decoded values match originals.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_headers::{CwtClaimValue, CwtClaims, CWTClaimsHeaderLabels};

// ---------------------------------------------------------------------------
// Round-trip: every standard field + every custom claim type
// ---------------------------------------------------------------------------

/// Exercises lines 95–179 (encode) and 199–281 (decode) by populating
/// ALL optional standard fields AND one custom claim of each variant.
#[test]
fn roundtrip_all_standard_fields_and_custom_claim_types() {
    let original = CwtClaims::new()
        .with_issuer("https://issuer.example")
        .with_subject("subject@example")
        .with_audience("https://audience.example")
        .with_expiration_time(1_700_000_000)
        .with_not_before(1_699_000_000)
        .with_issued_at(1_698_500_000)
        .with_cwt_id(vec![0xCA, 0xFE, 0xBA, 0xBE])
        // Custom claims — one per CwtClaimValue variant (Float excluded: EverParse doesn't support it)
        .with_custom_claim(100, CwtClaimValue::Text("custom-text".into()))
        .with_custom_claim(101, CwtClaimValue::Integer(9999))
        .with_custom_claim(102, CwtClaimValue::Bytes(vec![0x01, 0x02, 0x03]))
        .with_custom_claim(103, CwtClaimValue::Bool(true));

    let bytes = original.to_cbor_bytes().expect("encode should succeed");
    let decoded = CwtClaims::from_cbor_bytes(&bytes).expect("decode should succeed");

    // Standard fields
    assert_eq!(decoded.issuer.as_deref(), Some("https://issuer.example"));
    assert_eq!(decoded.subject.as_deref(), Some("subject@example"));
    assert_eq!(decoded.audience.as_deref(), Some("https://audience.example"));
    assert_eq!(decoded.expiration_time, Some(1_700_000_000));
    assert_eq!(decoded.not_before, Some(1_699_000_000));
    assert_eq!(decoded.issued_at, Some(1_698_500_000));
    assert_eq!(decoded.cwt_id, Some(vec![0xCA, 0xFE, 0xBA, 0xBE]));

    // Custom claims
    assert_eq!(
        decoded.custom_claims.get(&100),
        Some(&CwtClaimValue::Text("custom-text".into()))
    );
    assert_eq!(
        decoded.custom_claims.get(&101),
        Some(&CwtClaimValue::Integer(9999))
    );
    assert_eq!(
        decoded.custom_claims.get(&102),
        Some(&CwtClaimValue::Bytes(vec![0x01, 0x02, 0x03]))
    );
    assert_eq!(
        decoded.custom_claims.get(&103),
        Some(&CwtClaimValue::Bool(true))
    );
}

// ---------------------------------------------------------------------------
// Decode: non-integer label triggers error (line 216–219)
// ---------------------------------------------------------------------------

/// Manually craft a CBOR map whose key is a text string instead of integer
/// to trigger the "CWT claim label must be integer" error branch.
#[test]
fn decode_rejects_text_label_in_cwt_map() {
    let provider = EverParseCborProvider::default();
    let mut enc = provider.encoder();

    // Map with 1 entry: key = tstr "bad", value = int 0
    enc.encode_map(1).unwrap();
    enc.encode_tstr("bad").unwrap();
    enc.encode_i64(0).unwrap();
    let bad_bytes = enc.into_bytes();

    let err = CwtClaims::from_cbor_bytes(&bad_bytes).unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("must be integer"),
        "unexpected error message: {}",
        msg
    );
}

// ---------------------------------------------------------------------------
// Decode: non-map top-level value (line 193–196)
// ---------------------------------------------------------------------------

/// Feed a CBOR array instead of a map to trigger the "Expected CBOR map" error.
#[test]
fn decode_rejects_non_map_top_level() {
    let provider = EverParseCborProvider::default();
    let mut enc = provider.encoder();

    enc.encode_array(0).unwrap();
    let bad_bytes = enc.into_bytes();

    let err = CwtClaims::from_cbor_bytes(&bad_bytes).unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("Expected CBOR map"),
        "unexpected error message: {}",
        msg
    );
}

// ---------------------------------------------------------------------------
// Decode: custom claim with complex types that are skipped (array / map)
// ---------------------------------------------------------------------------

/// Build CBOR with a custom claim whose value is an array — exercises the
/// skip-array path (lines 287–301).
#[test]
fn decode_skips_array_valued_custom_claim() {
    let provider = EverParseCborProvider::default();
    let mut enc = provider.encoder();

    // Map with 2 entries:
    //   label 1 (iss) => tstr "ok"
    //   label 200      => array [1, 2]
    enc.encode_map(2).unwrap();

    // Entry 1: standard issuer
    enc.encode_i64(CWTClaimsHeaderLabels::ISSUER).unwrap();
    enc.encode_tstr("ok").unwrap();

    // Entry 2: array-valued custom claim (should be skipped)
    enc.encode_i64(200).unwrap();
    enc.encode_array(2).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(2).unwrap();

    let bytes = enc.into_bytes();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).expect("should skip array claim");

    assert_eq!(decoded.issuer.as_deref(), Some("ok"));
    // The array claim should NOT appear in custom_claims
    assert!(decoded.custom_claims.get(&200).is_none());
}

/// Build CBOR with a custom claim whose value is a map — exercises the
/// skip-map path (lines 303–317).
#[test]
fn decode_skips_map_valued_custom_claim() {
    let provider = EverParseCborProvider::default();
    let mut enc = provider.encoder();

    // Map with 2 entries:
    //   label 2 (sub) => tstr "sub"
    //   label 300     => map { 10: "x" }
    enc.encode_map(2).unwrap();

    // Entry 1: standard subject
    enc.encode_i64(CWTClaimsHeaderLabels::SUBJECT).unwrap();
    enc.encode_tstr("sub").unwrap();

    // Entry 2: map-valued custom claim (should be skipped)
    enc.encode_i64(300).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_i64(10).unwrap();
    enc.encode_tstr("x").unwrap();

    let bytes = enc.into_bytes();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).expect("should skip map claim");

    assert_eq!(decoded.subject.as_deref(), Some("sub"));
    assert!(decoded.custom_claims.get(&300).is_none());
}

// ---------------------------------------------------------------------------
// Round-trip: only issuer populated to test partial encode (lines 99–103)
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_issuer_only() {
    let claims = CwtClaims::new().with_issuer("solo-issuer");
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(decoded.issuer.as_deref(), Some("solo-issuer"));
    assert!(decoded.subject.is_none());
    assert!(decoded.audience.is_none());
    assert!(decoded.expiration_time.is_none());
    assert!(decoded.not_before.is_none());
    assert!(decoded.issued_at.is_none());
    assert!(decoded.cwt_id.is_none());
}

// ---------------------------------------------------------------------------
// Round-trip: only audience populated (lines 113–117)
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_audience_only() {
    let claims = CwtClaims::new().with_audience("aud-only");
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(decoded.audience.as_deref(), Some("aud-only"));
    assert!(decoded.issuer.is_none());
}

// ---------------------------------------------------------------------------
// Round-trip: only time fields populated (lines 120–145)
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_time_fields_only() {
    let claims = CwtClaims::new()
        .with_expiration_time(i64::MAX)
        .with_not_before(i64::MIN)
        .with_issued_at(0);

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(decoded.expiration_time, Some(i64::MAX));
    assert_eq!(decoded.not_before, Some(i64::MIN));
    assert_eq!(decoded.issued_at, Some(0));
}

// ---------------------------------------------------------------------------
// Round-trip: only cwt_id populated (lines 141–145)
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_cwt_id_only() {
    let claims = CwtClaims::new().with_cwt_id(vec![0xFF; 128]);
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(decoded.cwt_id, Some(vec![0xFF; 128]));
}

// Note: Float encode/decode not tested because EverParse CBOR provider
// does not support floating-point encoding.

// ---------------------------------------------------------------------------
// Round-trip: Bool(false) custom claim (line 170–172, 273–276)
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_bool_false_custom_claim() {
    let claims = CwtClaims::new()
        .with_custom_claim(600, CwtClaimValue::Bool(false));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(
        decoded.custom_claims.get(&600),
        Some(&CwtClaimValue::Bool(false))
    );
}

// ---------------------------------------------------------------------------
// Encode → decode multiple custom claims in sorted order (lines 148–179)
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_multiple_sorted_custom_claims() {
    let claims = CwtClaims::new()
        .with_custom_claim(999, CwtClaimValue::Integer(-1))
        .with_custom_claim(50, CwtClaimValue::Text("first".into()))
        .with_custom_claim(500, CwtClaimValue::Bytes(vec![0xAA]));

    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(decoded.custom_claims.len(), 3);
    assert_eq!(
        decoded.custom_claims.get(&50),
        Some(&CwtClaimValue::Text("first".into()))
    );
    assert_eq!(
        decoded.custom_claims.get(&500),
        Some(&CwtClaimValue::Bytes(vec![0xAA]))
    );
    assert_eq!(
        decoded.custom_claims.get(&999),
        Some(&CwtClaimValue::Integer(-1))
    );
}
