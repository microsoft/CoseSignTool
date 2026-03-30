// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests targeting the complex CBOR skip logic in CwtClaims deserialization.
//!
//! Specifically targets array skipping logic in custom claims.
//! Note: Map skipping tests are complex and may not be reachable in practice.

use cbor_primitives::CborEncoder;
use cose_sign1_headers::cwt_claims::{CwtClaimValue, CwtClaims};
use cose_sign1_headers::cwt_claims_labels::CWTClaimsHeaderLabels;

/// Test deserialization skipping array values in custom claims.
#[test]
fn test_custom_claim_skip_array() {
    let mut encoder = cose_sign1_primitives::provider::encoder();

    // Create a map with 2 claims: one array (which should be skipped) and one text (which should be kept)
    encoder.encode_map(2).unwrap();

    // First claim: array (should be skipped)
    encoder.encode_i64(100).unwrap();
    encoder.encode_array(3).unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_i64(2).unwrap();
    encoder.encode_i64(3).unwrap();

    // Second claim: text (should be kept)
    encoder.encode_i64(101).unwrap();
    encoder.encode_tstr("test_value").unwrap();

    let bytes = encoder.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    // The array should have been skipped, only the text claim should remain
    assert_eq!(claims.custom_claims.len(), 1);
    assert!(
        matches!(claims.custom_claims.get(&101), Some(CwtClaimValue::Text(s)) if s == "test_value")
    );
}

/// Test deserialization skipping array with mixed types.
#[test]
fn test_custom_claim_skip_array_mixed_types() {
    let mut encoder = cose_sign1_primitives::provider::encoder();

    encoder.encode_map(1).unwrap();
    encoder.encode_i64(100).unwrap();
    encoder.encode_array(4).unwrap();
    encoder.encode_i64(42).unwrap(); // int
    encoder.encode_tstr("hello").unwrap(); // text
    encoder.encode_bstr(&[1, 2, 3]).unwrap(); // bytes
    encoder.encode_bool(true).unwrap(); // bool

    let bytes = encoder.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    // Array should be skipped, no custom claims should remain
    assert_eq!(claims.custom_claims.len(), 0);
}

/// Test all standard claims together.
#[test]
fn test_all_standard_claims() {
    let mut encoder = cose_sign1_primitives::provider::encoder();

    // Create a comprehensive set of claims
    encoder.encode_map(7).unwrap();

    // Standard claims
    encoder.encode_i64(CWTClaimsHeaderLabels::ISSUER).unwrap();
    encoder.encode_tstr("test-issuer").unwrap();

    encoder.encode_i64(CWTClaimsHeaderLabels::SUBJECT).unwrap();
    encoder.encode_tstr("test-subject").unwrap();

    encoder.encode_i64(CWTClaimsHeaderLabels::AUDIENCE).unwrap();
    encoder.encode_tstr("test-audience").unwrap();

    encoder
        .encode_i64(CWTClaimsHeaderLabels::EXPIRATION_TIME)
        .unwrap();
    encoder.encode_i64(1000000).unwrap();

    encoder
        .encode_i64(CWTClaimsHeaderLabels::NOT_BEFORE)
        .unwrap();
    encoder.encode_i64(500000).unwrap();

    encoder
        .encode_i64(CWTClaimsHeaderLabels::ISSUED_AT)
        .unwrap();
    encoder.encode_i64(600000).unwrap();

    encoder.encode_i64(CWTClaimsHeaderLabels::CWT_ID).unwrap();
    encoder.encode_bstr(&[1, 2, 3, 4]).unwrap();

    let bytes = encoder.into_bytes();
    let claims = CwtClaims::from_cbor_bytes(&bytes).unwrap();

    assert_eq!(claims.issuer, Some("test-issuer".to_string()));
    assert_eq!(claims.subject, Some("test-subject".to_string()));
    assert_eq!(claims.audience, Some("test-audience".to_string()));
    assert_eq!(claims.expiration_time, Some(1000000));
    assert_eq!(claims.not_before, Some(500000));
    assert_eq!(claims.issued_at, Some(600000));
    assert_eq!(claims.cwt_id, Some(vec![1, 2, 3, 4]));
}
