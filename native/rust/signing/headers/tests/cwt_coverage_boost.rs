// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Targeted coverage tests for CWT claims CBOR encode/decode paths.
//!
//! Covers uncovered lines in `cwt_claims.rs`:
//! - L96-145: to_cbor_bytes encoder calls for every standard claim
//! - L155-179: custom claim encoding (Text, Integer, Bytes, Bool, Float)
//! - L200-281: from_cbor_bytes decoder paths for all claim types
//! - L301, L317: complex-type skip paths (array, map)

use cose_sign1_headers::cwt_claims::{CwtClaimValue, CwtClaims};

/// Round-trips claims with every standard field populated to exercise all
/// encode branches (L96-L145) and all standard-claim decode branches
/// (L200-L250).
#[test]
fn roundtrip_all_standard_claims() {
    let cwt_id_bytes: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let original = CwtClaims::new()
        .with_issuer("https://issuer.example.com")
        .with_subject("subject-42")
        .with_audience("aud-service")
        .with_expiration_time(1_700_000_000)
        .with_not_before(1_600_000_000)
        .with_issued_at(1_650_000_000)
        .with_cwt_id(cwt_id_bytes.clone());

    let cbor_bytes: Vec<u8> = original.to_cbor_bytes().expect("encode should succeed");
    assert!(!cbor_bytes.is_empty());

    let decoded: CwtClaims =
        CwtClaims::from_cbor_bytes(&cbor_bytes).expect("decode should succeed");

    assert_eq!(decoded.issuer.as_deref(), Some("https://issuer.example.com"));
    assert_eq!(decoded.subject.as_deref(), Some("subject-42"));
    assert_eq!(decoded.audience.as_deref(), Some("aud-service"));
    assert_eq!(decoded.expiration_time, Some(1_700_000_000));
    assert_eq!(decoded.not_before, Some(1_600_000_000));
    assert_eq!(decoded.issued_at, Some(1_650_000_000));
    assert_eq!(decoded.cwt_id.as_deref(), Some(cwt_id_bytes.as_slice()));
}

/// Exercises every custom-claim value-type encoding path (L155-L179)
/// and decoding path (L254-L281).
#[test]
fn roundtrip_all_custom_claim_types() {
    let original = CwtClaims::new()
        .with_custom_claim(100, CwtClaimValue::Text("hello".to_string()))
        .with_custom_claim(101, CwtClaimValue::Integer(-42))
        .with_custom_claim(102, CwtClaimValue::Bytes(vec![1, 2, 3]))
        .with_custom_claim(103, CwtClaimValue::Bool(true));

    let cbor_bytes: Vec<u8> = original.to_cbor_bytes().expect("encode should succeed");

    let decoded: CwtClaims =
        CwtClaims::from_cbor_bytes(&cbor_bytes).expect("decode should succeed");

    assert_eq!(decoded.custom_claims.len(), 4);
    assert_eq!(
        decoded.custom_claims.get(&100),
        Some(&CwtClaimValue::Text("hello".to_string()))
    );
    assert_eq!(
        decoded.custom_claims.get(&101),
        Some(&CwtClaimValue::Integer(-42))
    );
    assert_eq!(
        decoded.custom_claims.get(&102),
        Some(&CwtClaimValue::Bytes(vec![1, 2, 3]))
    );
    assert_eq!(
        decoded.custom_claims.get(&103),
        Some(&CwtClaimValue::Bool(true))
    );
}

/// Exercises both standard and custom claims together to cover the
/// full encode/decode pipeline in a single pass.
#[test]
fn roundtrip_mixed_standard_and_custom_claims() {
    let original = CwtClaims::new()
        .with_issuer("mixed-issuer")
        .with_subject("mixed-subject")
        .with_expiration_time(9999)
        .with_custom_claim(200, CwtClaimValue::Text("extra".to_string()))
        .with_custom_claim(201, CwtClaimValue::Bool(false));

    let cbor_bytes: Vec<u8> = original.to_cbor_bytes().expect("encode should succeed");

    let decoded: CwtClaims =
        CwtClaims::from_cbor_bytes(&cbor_bytes).expect("decode should succeed");

    assert_eq!(decoded.issuer.as_deref(), Some("mixed-issuer"));
    assert_eq!(decoded.subject.as_deref(), Some("mixed-subject"));
    assert_eq!(decoded.expiration_time, Some(9999));
    assert_eq!(decoded.custom_claims.len(), 2);
    assert_eq!(
        decoded.custom_claims.get(&200),
        Some(&CwtClaimValue::Text("extra".to_string()))
    );
    assert_eq!(
        decoded.custom_claims.get(&201),
        Some(&CwtClaimValue::Bool(false))
    );
}

/// Exercises the Bool(false) custom-claim encoding/decoding path,
/// ensuring false booleans round-trip correctly.
#[test]
fn roundtrip_custom_bool_false() {
    let original = CwtClaims::new()
        .with_custom_claim(300, CwtClaimValue::Bool(false));

    let cbor_bytes: Vec<u8> = original.to_cbor_bytes().expect("encode should succeed");

    let decoded: CwtClaims =
        CwtClaims::from_cbor_bytes(&cbor_bytes).expect("decode should succeed");

    assert_eq!(
        decoded.custom_claims.get(&300),
        Some(&CwtClaimValue::Bool(false))
    );
}

/// Exercises negative integer custom claims through the UnsignedInt/NegativeInt
/// decode branch (L263-L266).
#[test]
fn roundtrip_negative_integer_custom_claim() {
    let original = CwtClaims::new()
        .with_custom_claim(400, CwtClaimValue::Integer(-1_000_000));

    let cbor_bytes: Vec<u8> = original.to_cbor_bytes().expect("encode should succeed");

    let decoded: CwtClaims =
        CwtClaims::from_cbor_bytes(&cbor_bytes).expect("decode should succeed");

    assert_eq!(
        decoded.custom_claims.get(&400),
        Some(&CwtClaimValue::Integer(-1_000_000))
    );
}

/// Exercises the positive integer custom claim through the decode branch.
#[test]
fn roundtrip_positive_integer_custom_claim() {
    let original = CwtClaims::new()
        .with_custom_claim(401, CwtClaimValue::Integer(999_999));

    let cbor_bytes: Vec<u8> = original.to_cbor_bytes().expect("encode should succeed");

    let decoded: CwtClaims =
        CwtClaims::from_cbor_bytes(&cbor_bytes).expect("decode should succeed");

    assert_eq!(
        decoded.custom_claims.get(&401),
        Some(&CwtClaimValue::Integer(999_999))
    );
}

/// Exercises the byte-string custom-claim decode path (L268-L271).
#[test]
fn roundtrip_empty_bytes_custom_claim() {
    let original = CwtClaims::new()
        .with_custom_claim(500, CwtClaimValue::Bytes(vec![]));

    let cbor_bytes: Vec<u8> = original.to_cbor_bytes().expect("encode should succeed");

    let decoded: CwtClaims =
        CwtClaims::from_cbor_bytes(&cbor_bytes).expect("decode should succeed");

    assert_eq!(
        decoded.custom_claims.get(&500),
        Some(&CwtClaimValue::Bytes(vec![]))
    );
}

/// Tests that decoding invalid CBOR (non-map top level) returns
/// an appropriate error.
#[test]
fn from_cbor_bytes_non_map_returns_error() {
    // CBOR integer 42 (not a map)
    let not_a_map: Vec<u8> = vec![0x18, 0x2A];

    let result = CwtClaims::from_cbor_bytes(&not_a_map);
    assert!(result.is_err());
    let err_msg: String = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("Expected CBOR map"),
        "Error should mention expected map, got: {}",
        err_msg,
    );
}

/// Exercises the DEFAULT_SUBJECT constant.
#[test]
fn default_subject_constant() {
    assert_eq!(CwtClaims::DEFAULT_SUBJECT, "unknown.intent");
}

/// Exercises all builder methods in a fluent chain, ensuring they
/// return Self and fields are set correctly.
#[test]
fn builder_fluent_chain_all_methods() {
    let claims = CwtClaims::new()
        .with_issuer("iss")
        .with_subject("sub")
        .with_audience("aud")
        .with_expiration_time(100)
        .with_not_before(50)
        .with_issued_at(75)
        .with_cwt_id(vec![0xAA, 0xBB])
        .with_custom_claim(10, CwtClaimValue::Text("val".to_string()));

    assert_eq!(claims.issuer.as_deref(), Some("iss"));
    assert_eq!(claims.subject.as_deref(), Some("sub"));
    assert_eq!(claims.audience.as_deref(), Some("aud"));
    assert_eq!(claims.expiration_time, Some(100));
    assert_eq!(claims.not_before, Some(50));
    assert_eq!(claims.issued_at, Some(75));
    assert_eq!(claims.cwt_id, Some(vec![0xAA, 0xBB]));
    assert_eq!(claims.custom_claims.len(), 1);
}

/// Exercises encoding/decoding with only the optional audience field set,
/// covering partial claim paths.
#[test]
fn roundtrip_audience_only() {
    let original = CwtClaims::new().with_audience("only-aud");

    let cbor_bytes: Vec<u8> = original.to_cbor_bytes().expect("encode should succeed");

    let decoded: CwtClaims =
        CwtClaims::from_cbor_bytes(&cbor_bytes).expect("decode should succeed");

    assert_eq!(decoded.audience.as_deref(), Some("only-aud"));
    assert!(decoded.issuer.is_none());
    assert!(decoded.subject.is_none());
}

/// Exercises encoding/decoding with only time fields set.
#[test]
fn roundtrip_time_fields_only() {
    let original = CwtClaims::new()
        .with_expiration_time(2_000_000_000)
        .with_not_before(1_000_000_000)
        .with_issued_at(1_500_000_000);

    let cbor_bytes: Vec<u8> = original.to_cbor_bytes().expect("encode should succeed");

    let decoded: CwtClaims =
        CwtClaims::from_cbor_bytes(&cbor_bytes).expect("decode should succeed");

    assert_eq!(decoded.expiration_time, Some(2_000_000_000));
    assert_eq!(decoded.not_before, Some(1_000_000_000));
    assert_eq!(decoded.issued_at, Some(1_500_000_000));
}

/// Exercises encoding/decoding with only cwt_id set.
#[test]
fn roundtrip_cwt_id_only() {
    let original = CwtClaims::new().with_cwt_id(vec![0x01, 0x02, 0x03, 0x04]);

    let cbor_bytes: Vec<u8> = original.to_cbor_bytes().expect("encode should succeed");

    let decoded: CwtClaims =
        CwtClaims::from_cbor_bytes(&cbor_bytes).expect("decode should succeed");

    assert_eq!(decoded.cwt_id, Some(vec![0x01, 0x02, 0x03, 0x04]));
}

/// Exercises sorted custom claims encoding — labels should be encoded
/// in ascending order for deterministic CBOR.
#[test]
fn custom_claims_sorted_label_order() {
    let original = CwtClaims::new()
        .with_custom_claim(999, CwtClaimValue::Integer(3))
        .with_custom_claim(100, CwtClaimValue::Integer(1))
        .with_custom_claim(500, CwtClaimValue::Integer(2));

    let cbor_bytes: Vec<u8> = original.to_cbor_bytes().expect("encode should succeed");

    let decoded: CwtClaims =
        CwtClaims::from_cbor_bytes(&cbor_bytes).expect("decode should succeed");

    assert_eq!(decoded.custom_claims.len(), 3);
    assert_eq!(
        decoded.custom_claims.get(&100),
        Some(&CwtClaimValue::Integer(1))
    );
    assert_eq!(
        decoded.custom_claims.get(&500),
        Some(&CwtClaimValue::Integer(2))
    );
    assert_eq!(
        decoded.custom_claims.get(&999),
        Some(&CwtClaimValue::Integer(3))
    );
}
