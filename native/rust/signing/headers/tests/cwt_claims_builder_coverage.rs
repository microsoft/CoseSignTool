// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for CwtClaims builder methods.
//!
//! These tests target the uncovered builder method paths and CBOR roundtrip edge cases
//! to improve coverage in cwt_claims.rs

use cbor_primitives::CborProvider;
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_headers::{CwtClaimValue, CwtClaims};

#[test]
fn test_builder_with_issuer_string() {
    let claims = CwtClaims::new().with_issuer("https://test.issuer.com");
    assert_eq!(claims.issuer, Some("https://test.issuer.com".to_string()));
}

#[test]
fn test_builder_with_issuer_owned_string() {
    let issuer = "https://owned.issuer.com".to_string();
    let claims = CwtClaims::new().with_issuer(issuer.clone());
    assert_eq!(claims.issuer, Some(issuer));
}

#[test]
fn test_builder_with_subject_string() {
    let claims = CwtClaims::new().with_subject("test.subject");
    assert_eq!(claims.subject, Some("test.subject".to_string()));
}

#[test]
fn test_builder_with_subject_owned_string() {
    let subject = "owned.subject".to_string();
    let claims = CwtClaims::new().with_subject(subject.clone());
    assert_eq!(claims.subject, Some(subject));
}

#[test]
fn test_builder_with_audience_string() {
    let claims = CwtClaims::new().with_audience("test-audience");
    assert_eq!(claims.audience, Some("test-audience".to_string()));
}

#[test]
fn test_builder_with_audience_owned_string() {
    let audience = "owned-audience".to_string();
    let claims = CwtClaims::new().with_audience(audience.clone());
    assert_eq!(claims.audience, Some(audience));
}

#[test]
fn test_builder_with_expiration_time() {
    let exp_time = 1672531200; // 2023-01-01 00:00:00 UTC
    let claims = CwtClaims::new().with_expiration_time(exp_time);
    assert_eq!(claims.expiration_time, Some(exp_time));
}

#[test]
fn test_builder_with_not_before() {
    let nbf_time = 1640995200; // 2022-01-01 00:00:00 UTC
    let claims = CwtClaims::new().with_not_before(nbf_time);
    assert_eq!(claims.not_before, Some(nbf_time));
}

#[test]
fn test_builder_with_issued_at() {
    let iat_time = 1656633600; // 2022-07-01 00:00:00 UTC
    let claims = CwtClaims::new().with_issued_at(iat_time);
    assert_eq!(claims.issued_at, Some(iat_time));
}

#[test]
fn test_builder_with_cwt_id() {
    let cti = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let claims = CwtClaims::new().with_cwt_id(cti.clone());
    assert_eq!(claims.cwt_id, Some(cti));
}

#[test]
fn test_builder_with_empty_cwt_id() {
    let claims = CwtClaims::new().with_cwt_id(vec![]);
    assert_eq!(claims.cwt_id, Some(vec![]));
}

#[test]
fn test_builder_with_custom_claim_text() {
    let text_value = CwtClaimValue::Text("custom text".to_string());
    let claims = CwtClaims::new().with_custom_claim(1000, text_value.clone());
    assert_eq!(claims.custom_claims.get(&1000), Some(&text_value));
}

#[test]
fn test_builder_with_custom_claim_integer() {
    let int_value = CwtClaimValue::Integer(999);
    let claims = CwtClaims::new().with_custom_claim(1001, int_value.clone());
    assert_eq!(claims.custom_claims.get(&1001), Some(&int_value));
}

#[test]
fn test_builder_with_custom_claim_bytes() {
    let bytes_value = CwtClaimValue::Bytes(vec![1, 2, 3, 4, 5]);
    let claims = CwtClaims::new().with_custom_claim(1002, bytes_value.clone());
    assert_eq!(claims.custom_claims.get(&1002), Some(&bytes_value));
}

#[test]
fn test_builder_with_custom_claim_bool() {
    let bool_value = CwtClaimValue::Bool(true);
    let claims = CwtClaims::new().with_custom_claim(1003, bool_value.clone());
    assert_eq!(claims.custom_claims.get(&1003), Some(&bool_value));
}

#[test]
fn test_builder_with_custom_claim_float() {
    let float_value = CwtClaimValue::Float(3.14159);
    let claims = CwtClaims::new().with_custom_claim(1004, float_value.clone());
    assert_eq!(claims.custom_claims.get(&1004), Some(&float_value));
}

#[test]
fn test_builder_chaining() {
    let claims = CwtClaims::new()
        .with_issuer("chain.issuer")
        .with_subject("chain.subject")
        .with_audience("chain.audience")
        .with_expiration_time(1000)
        .with_not_before(500)
        .with_issued_at(750)
        .with_cwt_id(vec![1, 2, 3])
        .with_custom_claim(1000, CwtClaimValue::Text("chained".to_string()));

    assert_eq!(claims.issuer, Some("chain.issuer".to_string()));
    assert_eq!(claims.subject, Some("chain.subject".to_string()));
    assert_eq!(claims.audience, Some("chain.audience".to_string()));
    assert_eq!(claims.expiration_time, Some(1000));
    assert_eq!(claims.not_before, Some(500));
    assert_eq!(claims.issued_at, Some(750));
    assert_eq!(claims.cwt_id, Some(vec![1, 2, 3]));
    assert_eq!(
        claims.custom_claims.get(&1000),
        Some(&CwtClaimValue::Text("chained".to_string()))
    );
}

#[test]
fn test_builder_overwrite_values() {
    let claims = CwtClaims::new()
        .with_issuer("first-issuer")
        .with_issuer("second-issuer")
        .with_custom_claim(100, CwtClaimValue::Integer(1))
        .with_custom_claim(100, CwtClaimValue::Integer(2)); // Should overwrite

    assert_eq!(claims.issuer, Some("second-issuer".to_string()));
    assert_eq!(
        claims.custom_claims.get(&100),
        Some(&CwtClaimValue::Integer(2))
    );
}

#[test]
fn test_negative_timestamp_values() {
    let claims = CwtClaims::new()
        .with_expiration_time(-1000)
        .with_not_before(-2000)
        .with_issued_at(-1500);

    assert_eq!(claims.expiration_time, Some(-1000));
    assert_eq!(claims.not_before, Some(-2000));
    assert_eq!(claims.issued_at, Some(-1500));
}

#[test]
fn test_negative_custom_claim_labels() {
    let claims = CwtClaims::new()
        .with_custom_claim(-100, CwtClaimValue::Text("negative label".to_string()))
        .with_custom_claim(-1, CwtClaimValue::Integer(42));

    assert_eq!(
        claims.custom_claims.get(&-100),
        Some(&CwtClaimValue::Text("negative label".to_string()))
    );
    assert_eq!(
        claims.custom_claims.get(&-1),
        Some(&CwtClaimValue::Integer(42))
    );
}

#[test]
fn test_large_custom_claim_labels() {
    let large_label = i64::MAX;
    let claims = CwtClaims::new()
        .with_custom_claim(large_label, CwtClaimValue::Text("max label".to_string()));

    assert_eq!(
        claims.custom_claims.get(&large_label),
        Some(&CwtClaimValue::Text("max label".to_string()))
    );
}

#[test]
fn test_unicode_string_values() {
    let claims = CwtClaims::new()
        .with_issuer("🏢 Unicode Issuer 中文")
        .with_subject("👤 Unicode Subject العربية")
        .with_audience("🎯 Unicode Audience русский")
        .with_custom_claim(
            1000,
            CwtClaimValue::Text("🌍 Unicode Custom Claim हिन्दी".to_string()),
        );

    assert_eq!(claims.issuer, Some("🏢 Unicode Issuer 中文".to_string()));
    assert_eq!(
        claims.subject,
        Some("👤 Unicode Subject العربية".to_string())
    );
    assert_eq!(
        claims.audience,
        Some("🎯 Unicode Audience русский".to_string())
    );
    assert_eq!(
        claims.custom_claims.get(&1000),
        Some(&CwtClaimValue::Text(
            "🌍 Unicode Custom Claim हिन्दी".to_string()
        ))
    );
}

#[test]
fn test_empty_string_values() {
    let claims = CwtClaims::new()
        .with_issuer("")
        .with_subject("")
        .with_audience("")
        .with_custom_claim(1000, CwtClaimValue::Text("".to_string()));

    assert_eq!(claims.issuer, Some("".to_string()));
    assert_eq!(claims.subject, Some("".to_string()));
    assert_eq!(claims.audience, Some("".to_string()));
    assert_eq!(
        claims.custom_claims.get(&1000),
        Some(&CwtClaimValue::Text("".to_string()))
    );
}

#[test]
fn test_zero_timestamp_values() {
    let claims = CwtClaims::new()
        .with_expiration_time(0)
        .with_not_before(0)
        .with_issued_at(0);

    assert_eq!(claims.expiration_time, Some(0));
    assert_eq!(claims.not_before, Some(0));
    assert_eq!(claims.issued_at, Some(0));
}

#[test]
fn test_maximum_timestamp_values() {
    let claims = CwtClaims::new()
        .with_expiration_time(i64::MAX)
        .with_not_before(i64::MAX)
        .with_issued_at(i64::MAX);

    assert_eq!(claims.expiration_time, Some(i64::MAX));
    assert_eq!(claims.not_before, Some(i64::MAX));
    assert_eq!(claims.issued_at, Some(i64::MAX));
}

#[test]
fn test_minimum_timestamp_values() {
    let claims = CwtClaims::new()
        .with_expiration_time(i64::MIN)
        .with_not_before(i64::MIN)
        .with_issued_at(i64::MIN);

    assert_eq!(claims.expiration_time, Some(i64::MIN));
    assert_eq!(claims.not_before, Some(i64::MIN));
    assert_eq!(claims.issued_at, Some(i64::MIN));
}

#[test]
fn test_roundtrip_with_builder_methods() {
    let original = CwtClaims::new()
        .with_issuer("roundtrip-issuer")
        .with_subject("roundtrip-subject")
        .with_audience("roundtrip-audience")
        .with_expiration_time(1234567890)
        .with_not_before(1234567800)
        .with_issued_at(1234567850)
        .with_cwt_id(vec![0xAA, 0xBB, 0xCC, 0xDD])
        .with_custom_claim(1000, CwtClaimValue::Text("roundtrip".to_string()))
        .with_custom_claim(1001, CwtClaimValue::Integer(-999))
        .with_custom_claim(1002, CwtClaimValue::Bytes(vec![0x01, 0x02, 0x03]))
        .with_custom_claim(1003, CwtClaimValue::Bool(false));

    let cbor_bytes = original.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&cbor_bytes).unwrap();

    assert_eq!(decoded.issuer, original.issuer);
    assert_eq!(decoded.subject, original.subject);
    assert_eq!(decoded.audience, original.audience);
    assert_eq!(decoded.expiration_time, original.expiration_time);
    assert_eq!(decoded.not_before, original.not_before);
    assert_eq!(decoded.issued_at, original.issued_at);
    assert_eq!(decoded.cwt_id, original.cwt_id);
    assert_eq!(decoded.custom_claims, original.custom_claims);
}
