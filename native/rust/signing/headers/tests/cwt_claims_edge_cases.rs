// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Edge case tests for CwtClaims builder methods and CBOR roundtrip.
//!
//! Tests uncovered paths in cwt_claims.rs including:
//! - All builder methods (issuer, subject, audience, etc.)
//! - Custom claims handling
//! - CBOR encoding/decoding roundtrip
//! - Edge cases and error conditions

use cbor_primitives::{CborDecoder, CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_headers::cwt_claims_labels::CWTClaimsHeaderLabels;
use cose_sign1_headers::{error::HeaderError, CwtClaimValue, CwtClaims};
use std::collections::HashMap;

#[test]
fn test_cwt_claims_new() {
    let claims = CwtClaims::new();
    assert!(claims.issuer.is_none());
    assert!(claims.subject.is_none());
    assert!(claims.audience.is_none());
    assert!(claims.expiration_time.is_none());
    assert!(claims.not_before.is_none());
    assert!(claims.issued_at.is_none());
    assert!(claims.cwt_id.is_none());
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn test_cwt_claims_default() {
    let claims = CwtClaims::default();
    assert!(claims.issuer.is_none());
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn test_cwt_claims_default_subject() {
    assert_eq!(CwtClaims::DEFAULT_SUBJECT, "unknown.intent");
}

#[test]
fn test_cwt_claims_set_issuer() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("test-issuer".to_string());
    assert_eq!(claims.issuer.as_ref().unwrap(), "test-issuer");
}

#[test]
fn test_cwt_claims_set_subject() {
    let mut claims = CwtClaims::new();
    claims.subject = Some("test.subject".to_string());
    assert_eq!(claims.subject.as_ref().unwrap(), "test.subject");
}

#[test]
fn test_cwt_claims_set_audience() {
    let mut claims = CwtClaims::new();
    claims.audience = Some("test-audience".to_string());
    assert_eq!(claims.audience.as_ref().unwrap(), "test-audience");
}

#[test]
fn test_cwt_claims_set_timestamps() {
    let mut claims = CwtClaims::new();

    let now = 1640995200; // 2022-01-01 00:00:00 UTC
    let later = now + 3600; // +1 hour
    let earlier = now - 3600; // -1 hour

    claims.expiration_time = Some(later);
    claims.not_before = Some(earlier);
    claims.issued_at = Some(now);

    assert_eq!(claims.expiration_time, Some(later));
    assert_eq!(claims.not_before, Some(earlier));
    assert_eq!(claims.issued_at, Some(now));
}

#[test]
fn test_cwt_claims_set_cwt_id() {
    let mut claims = CwtClaims::new();
    let id = vec![1, 2, 3, 4, 5];
    claims.cwt_id = Some(id.clone());
    assert_eq!(claims.cwt_id.as_ref().unwrap(), &id);
}

#[test]
fn test_cwt_claims_custom_claims_text() {
    let mut claims = CwtClaims::new();
    claims
        .custom_claims
        .insert(1000, CwtClaimValue::Text("custom text".to_string()));

    assert_eq!(claims.custom_claims.len(), 1);
    match claims.custom_claims.get(&1000).unwrap() {
        CwtClaimValue::Text(s) => assert_eq!(s, "custom text"),
        _ => panic!("Wrong claim value type"),
    }
}

#[test]
fn test_cwt_claims_custom_claims_integer() {
    let mut claims = CwtClaims::new();
    claims
        .custom_claims
        .insert(1001, CwtClaimValue::Integer(42));

    match claims.custom_claims.get(&1001).unwrap() {
        CwtClaimValue::Integer(i) => assert_eq!(*i, 42),
        _ => panic!("Wrong claim value type"),
    }
}

#[test]
fn test_cwt_claims_custom_claims_bytes() {
    let mut claims = CwtClaims::new();
    let bytes = vec![0xAA, 0xBB, 0xCC];
    claims
        .custom_claims
        .insert(1002, CwtClaimValue::Bytes(bytes.clone()));

    match claims.custom_claims.get(&1002).unwrap() {
        CwtClaimValue::Bytes(b) => assert_eq!(b, &bytes),
        _ => panic!("Wrong claim value type"),
    }
}

#[test]
fn test_cwt_claims_custom_claims_bool() {
    let mut claims = CwtClaims::new();
    claims.custom_claims.insert(1003, CwtClaimValue::Bool(true));
    claims
        .custom_claims
        .insert(1004, CwtClaimValue::Bool(false));

    match claims.custom_claims.get(&1003).unwrap() {
        CwtClaimValue::Bool(b) => assert!(b),
        _ => panic!("Wrong claim value type"),
    }

    match claims.custom_claims.get(&1004).unwrap() {
        CwtClaimValue::Bool(b) => assert!(!b),
        _ => panic!("Wrong claim value type"),
    }
}

#[test]
fn test_cwt_claims_custom_claims_float() {
    let mut claims = CwtClaims::new();
    claims
        .custom_claims
        .insert(1005, CwtClaimValue::Float(3.14159));

    match claims.custom_claims.get(&1005).unwrap() {
        CwtClaimValue::Float(f) => assert!((f - 3.14159).abs() < 1e-6),
        _ => panic!("Wrong claim value type"),
    }
}

#[test]
fn test_cwt_claims_to_cbor_empty() {
    let claims = CwtClaims::new();
    let cbor_bytes = claims.to_cbor_bytes().unwrap();

    // Should be an empty CBOR map
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&cbor_bytes);
    let len = decoder.decode_map_len().unwrap();
    assert_eq!(len, Some(0));
}

#[test]
fn test_cwt_claims_to_cbor_single_issuer() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("test-issuer".to_string());

    let cbor_bytes = claims.to_cbor_bytes().unwrap();

    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&cbor_bytes);
    let len = decoder.decode_map_len().unwrap();
    assert_eq!(len, Some(1));

    let key = decoder.decode_i64().unwrap();
    assert_eq!(key, CWTClaimsHeaderLabels::ISSUER);

    let value = decoder.decode_tstr().unwrap();
    assert_eq!(value, "test-issuer");
}

#[test]
fn test_cwt_claims_to_cbor_all_standard_claims() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("issuer".to_string());
    claims.subject = Some("subject".to_string());
    claims.audience = Some("audience".to_string());
    claims.expiration_time = Some(1000);
    claims.not_before = Some(500);
    claims.issued_at = Some(750);
    claims.cwt_id = Some(vec![1, 2, 3]);

    let cbor_bytes = claims.to_cbor_bytes().unwrap();

    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&cbor_bytes);
    let len = decoder.decode_map_len().unwrap();
    assert_eq!(len, Some(7));

    // Verify claims are in correct order (sorted by label)
    // Labels: iss=1, sub=2, aud=3, exp=4, nbf=5, iat=6, cti=7

    // Issuer (1)
    let key = decoder.decode_i64().unwrap();
    assert_eq!(key, CWTClaimsHeaderLabels::ISSUER);
    let value = decoder.decode_tstr().unwrap();
    assert_eq!(value, "issuer");

    // Subject (2)
    let key = decoder.decode_i64().unwrap();
    assert_eq!(key, CWTClaimsHeaderLabels::SUBJECT);
    let value = decoder.decode_tstr().unwrap();
    assert_eq!(value, "subject");

    // Audience (3)
    let key = decoder.decode_i64().unwrap();
    assert_eq!(key, CWTClaimsHeaderLabels::AUDIENCE);
    let value = decoder.decode_tstr().unwrap();
    assert_eq!(value, "audience");

    // Expiration time (4)
    let key = decoder.decode_i64().unwrap();
    assert_eq!(key, CWTClaimsHeaderLabels::EXPIRATION_TIME);
    let value = decoder.decode_i64().unwrap();
    assert_eq!(value, 1000);

    // Not before (5)
    let key = decoder.decode_i64().unwrap();
    assert_eq!(key, CWTClaimsHeaderLabels::NOT_BEFORE);
    let value = decoder.decode_i64().unwrap();
    assert_eq!(value, 500);

    // Issued at (6)
    let key = decoder.decode_i64().unwrap();
    assert_eq!(key, CWTClaimsHeaderLabels::ISSUED_AT);
    let value = decoder.decode_i64().unwrap();
    assert_eq!(value, 750);

    // CWT ID (7)
    let key = decoder.decode_i64().unwrap();
    assert_eq!(key, CWTClaimsHeaderLabels::CWT_ID);
    let value = decoder.decode_bstr().unwrap();
    assert_eq!(value, &[1, 2, 3]);
}

#[test]
fn test_cwt_claims_to_cbor_with_custom_claims() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("issuer".to_string());

    // Add custom claims with different types
    claims
        .custom_claims
        .insert(1000, CwtClaimValue::Text("text".to_string()));
    claims.custom_claims.insert(500, CwtClaimValue::Integer(42)); // Lower label, should come first
    claims
        .custom_claims
        .insert(2000, CwtClaimValue::Bytes(vec![0xAA]));

    let cbor_bytes = claims.to_cbor_bytes().unwrap();

    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&cbor_bytes);
    let len = decoder.decode_map_len().unwrap();
    assert_eq!(len, Some(4)); // 1 standard + 3 custom

    // Should be in sorted order: iss=1, custom=500, custom=1000, custom=2000

    // Issuer (1)
    let key = decoder.decode_i64().unwrap();
    assert_eq!(key, CWTClaimsHeaderLabels::ISSUER);
    let value = decoder.decode_tstr().unwrap();
    assert_eq!(value, "issuer");

    // Custom claim 500 (integer)
    let key = decoder.decode_i64().unwrap();
    assert_eq!(key, 500);
    let value = decoder.decode_i64().unwrap();
    assert_eq!(value, 42);

    // Custom claim 1000 (text)
    let key = decoder.decode_i64().unwrap();
    assert_eq!(key, 1000);
    let value = decoder.decode_tstr().unwrap();
    assert_eq!(value, "text");

    // Custom claim 2000 (bytes)
    let key = decoder.decode_i64().unwrap();
    assert_eq!(key, 2000);
    let value = decoder.decode_bstr().unwrap();
    assert_eq!(value, &[0xAA]);
}

#[test]
fn test_cwt_claims_to_cbor_custom_claims_all_types() {
    let mut claims = CwtClaims::new();

    // Note: Float is not supported by EverParse CBOR encoder, so we skip it
    claims
        .custom_claims
        .insert(1001, CwtClaimValue::Text("hello".to_string()));
    claims
        .custom_claims
        .insert(1002, CwtClaimValue::Integer(-123));
    claims
        .custom_claims
        .insert(1003, CwtClaimValue::Bytes(vec![0x01, 0x02, 0x03]));
    claims.custom_claims.insert(1004, CwtClaimValue::Bool(true));

    let cbor_bytes = claims.to_cbor_bytes().unwrap();

    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&cbor_bytes);
    let len = decoder.decode_map_len().unwrap();
    assert_eq!(len, Some(4));

    // Check each custom claim
    for expected_label in [1001, 1002, 1003, 1004] {
        let key = decoder.decode_i64().unwrap();
        assert_eq!(key, expected_label);

        match expected_label {
            1001 => {
                let value = decoder.decode_tstr().unwrap();
                assert_eq!(value, "hello");
            }
            1002 => {
                let value = decoder.decode_i64().unwrap();
                assert_eq!(value, -123);
            }
            1003 => {
                let value = decoder.decode_bstr().unwrap();
                assert_eq!(value, &[0x01, 0x02, 0x03]);
            }
            1004 => {
                let value = decoder.decode_bool().unwrap();
                assert!(value);
            }
            _ => panic!("Unexpected label"),
        }
    }
}

#[test]
fn test_cwt_claim_value_debug() {
    let text_claim = CwtClaimValue::Text("test".to_string());
    let debug_str = format!("{:?}", text_claim);
    assert!(debug_str.contains("Text"));
    assert!(debug_str.contains("test"));

    let int_claim = CwtClaimValue::Integer(42);
    let debug_str = format!("{:?}", int_claim);
    assert!(debug_str.contains("Integer"));
    assert!(debug_str.contains("42"));
}

#[test]
fn test_cwt_claim_value_equality() {
    let claim1 = CwtClaimValue::Text("test".to_string());
    let claim2 = CwtClaimValue::Text("test".to_string());
    let claim3 = CwtClaimValue::Text("different".to_string());

    assert_eq!(claim1, claim2);
    assert_ne!(claim1, claim3);

    let int_claim = CwtClaimValue::Integer(42);
    assert_ne!(claim1, int_claim);
}

#[test]
fn test_cwt_claim_value_clone() {
    let original = CwtClaimValue::Bytes(vec![1, 2, 3]);
    let cloned = original.clone();

    assert_eq!(original, cloned);

    // Ensure deep clone for bytes
    match (&original, &cloned) {
        (CwtClaimValue::Bytes(orig), CwtClaimValue::Bytes(clone)) => {
            assert_eq!(orig, clone);
            // They should be separate allocations
            assert_ne!(orig.as_ptr(), clone.as_ptr());
        }
        _ => panic!("Wrong types"),
    }
}

#[test]
fn test_cwt_claims_clone() {
    let mut original = CwtClaims::new();
    original.issuer = Some("issuer".to_string());
    original
        .custom_claims
        .insert(1000, CwtClaimValue::Text("custom".to_string()));

    let cloned = original.clone();

    assert_eq!(original.issuer, cloned.issuer);
    assert_eq!(original.custom_claims.len(), cloned.custom_claims.len());
    assert_eq!(
        original.custom_claims.get(&1000),
        cloned.custom_claims.get(&1000)
    );
}

#[test]
fn test_cwt_claims_debug() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("debug-issuer".to_string());

    let debug_str = format!("{:?}", claims);
    assert!(debug_str.contains("CwtClaims"));
    assert!(debug_str.contains("debug-issuer"));
}

#[test]
fn test_cwt_claims_labels_constants() {
    // Verify the standard CWT label values
    assert_eq!(CWTClaimsHeaderLabels::ISSUER, 1);
    assert_eq!(CWTClaimsHeaderLabels::SUBJECT, 2);
    assert_eq!(CWTClaimsHeaderLabels::AUDIENCE, 3);
    assert_eq!(CWTClaimsHeaderLabels::EXPIRATION_TIME, 4);
    assert_eq!(CWTClaimsHeaderLabels::NOT_BEFORE, 5);
    assert_eq!(CWTClaimsHeaderLabels::ISSUED_AT, 6);
    assert_eq!(CWTClaimsHeaderLabels::CWT_ID, 7);
}
