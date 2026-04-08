// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for CwtClaims focusing on missed lines:
//! encoding custom claim types, decoding complex skip paths,
//! Debug/Clone/Display coverage, and error paths.

use cose_sign1_headers::{CWTClaimsHeaderLabels, CwtClaimValue, CwtClaims, HeaderError};

// ---------------------------------------------------------------------------
// CwtClaims::new() and Default
// ---------------------------------------------------------------------------

#[test]
fn new_returns_all_none_fields() {
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
fn default_is_identical_to_new() {
    let from_new = CwtClaims::new();
    let from_default = CwtClaims::default();
    assert_eq!(from_new.issuer, from_default.issuer);
    assert_eq!(from_new.subject, from_default.subject);
    assert_eq!(from_new.audience, from_default.audience);
    assert_eq!(from_new.expiration_time, from_default.expiration_time);
    assert_eq!(from_new.not_before, from_default.not_before);
    assert_eq!(from_new.issued_at, from_default.issued_at);
    assert_eq!(from_new.cwt_id, from_default.cwt_id);
    assert_eq!(
        from_new.custom_claims.len(),
        from_default.custom_claims.len()
    );
}

// ---------------------------------------------------------------------------
// Encode empty claims (all None) => should produce an empty CBOR map
// ---------------------------------------------------------------------------

#[test]
fn encode_empty_claims_produces_empty_map() {
    let claims = CwtClaims::new();
    let bytes = claims.to_cbor_bytes().expect("empty claims should encode");
    // CBOR empty map is 0xa0
    assert_eq!(bytes, vec![0xa0]);
}

// ---------------------------------------------------------------------------
// Encode with every standard claim + every custom claim type populated
// ---------------------------------------------------------------------------

#[test]
fn encode_decode_all_standard_and_custom_claim_types() {
    let claims = CwtClaims::new()
        .with_issuer("iss")
        .with_subject("sub")
        .with_audience("aud")
        .with_expiration_time(1_700_000_000)
        .with_not_before(1_699_999_000)
        .with_issued_at(1_699_999_500)
        .with_cwt_id(vec![0xCA, 0xFE])
        .with_custom_claim(100, CwtClaimValue::Text("txt".to_string()))
        .with_custom_claim(101, CwtClaimValue::Integer(42))
        .with_custom_claim(102, CwtClaimValue::Bytes(vec![0xDE, 0xAD]))
        .with_custom_claim(103, CwtClaimValue::Bool(true))
        .with_custom_claim(104, CwtClaimValue::Bool(false));

    let bytes = claims.to_cbor_bytes().expect("encoding should succeed");
    let decoded = CwtClaims::from_cbor_bytes(&bytes).expect("decoding should succeed");

    assert_eq!(decoded.issuer.as_deref(), Some("iss"));
    assert_eq!(decoded.subject.as_deref(), Some("sub"));
    assert_eq!(decoded.audience.as_deref(), Some("aud"));
    assert_eq!(decoded.expiration_time, Some(1_700_000_000));
    assert_eq!(decoded.not_before, Some(1_699_999_000));
    assert_eq!(decoded.issued_at, Some(1_699_999_500));
    assert_eq!(decoded.cwt_id, Some(vec![0xCA, 0xFE]));
    assert_eq!(
        decoded.custom_claims.get(&100),
        Some(&CwtClaimValue::Text("txt".to_string()))
    );
    assert_eq!(
        decoded.custom_claims.get(&101),
        Some(&CwtClaimValue::Integer(42))
    );
    assert_eq!(
        decoded.custom_claims.get(&102),
        Some(&CwtClaimValue::Bytes(vec![0xDE, 0xAD]))
    );
    assert_eq!(
        decoded.custom_claims.get(&103),
        Some(&CwtClaimValue::Bool(true))
    );
    assert_eq!(
        decoded.custom_claims.get(&104),
        Some(&CwtClaimValue::Bool(false))
    );
}

// ---------------------------------------------------------------------------
// Encoding with negative custom claim labels
// ---------------------------------------------------------------------------

#[test]
fn encode_decode_negative_custom_label() {
    let claims = CwtClaims::new().with_custom_claim(-50, CwtClaimValue::Integer(-999));
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(
        decoded.custom_claims.get(&-50),
        Some(&CwtClaimValue::Integer(-999))
    );
}

// ---------------------------------------------------------------------------
// Custom claims sorting — deterministic encoding regardless of insert order
// ---------------------------------------------------------------------------

#[test]
fn custom_claims_encoded_in_sorted_label_order() {
    let a = CwtClaims::new()
        .with_custom_claim(300, CwtClaimValue::Integer(3))
        .with_custom_claim(100, CwtClaimValue::Integer(1))
        .with_custom_claim(200, CwtClaimValue::Integer(2));

    let b = CwtClaims::new()
        .with_custom_claim(100, CwtClaimValue::Integer(1))
        .with_custom_claim(200, CwtClaimValue::Integer(2))
        .with_custom_claim(300, CwtClaimValue::Integer(3));

    assert_eq!(a.to_cbor_bytes().unwrap(), b.to_cbor_bytes().unwrap());
}

// ---------------------------------------------------------------------------
// Decode error: invalid CBOR (not a map)
// ---------------------------------------------------------------------------

#[test]
fn decode_error_not_a_map() {
    // CBOR unsigned int 42
    let bad = vec![0x18, 0x2a];
    let err = CwtClaims::from_cbor_bytes(&bad).unwrap_err();
    match err {
        HeaderError::CborDecodingError(msg) => assert!(msg.contains("Expected CBOR map")),
        other => panic!("unexpected error: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Decode error: indefinite-length map
// ---------------------------------------------------------------------------

#[test]
fn decode_error_indefinite_length_map() {
    let indefinite = vec![
        0xbf, // map (indefinite)
        0x01, 0x63, 0x66, 0x6f, 0x6f, // 1: "foo"
        0xff, // break
    ];
    let err = CwtClaims::from_cbor_bytes(&indefinite).unwrap_err();
    match err {
        HeaderError::CborDecodingError(msg) => {
            assert!(msg.contains("Indefinite-length maps not supported"));
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Decode error: text-string label instead of integer
// ---------------------------------------------------------------------------

#[test]
fn decode_error_text_string_label() {
    // map(1) with text key "x" -> int 1
    let bad = vec![0xa1, 0x61, 0x78, 0x01];
    let err = CwtClaims::from_cbor_bytes(&bad).unwrap_err();
    match err {
        HeaderError::CborDecodingError(msg) => {
            assert!(msg.contains("CWT claim label must be integer"));
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Decode error: truncated CBOR
// ---------------------------------------------------------------------------

#[test]
fn decode_error_truncated_cbor() {
    let truncated = vec![0xa1, 0x01]; // map(1) key=1 but no value
    assert!(CwtClaims::from_cbor_bytes(&truncated).is_err());
}

#[test]
fn decode_error_empty_data() {
    assert!(CwtClaims::from_cbor_bytes(&[]).is_err());
}

// ---------------------------------------------------------------------------
// Decode: array custom claim value is skipped (covers skip-array path)
// ---------------------------------------------------------------------------

#[test]
fn decode_skips_array_value_with_text_elements() {
    // map(1) { 100: ["hello", "world"] }
    let cbor = vec![
        0xa1, // map(1)
        0x18, 0x64, // unsigned(100)
        0x82, // array(2)
        0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f, // "hello"
        0x65, 0x77, 0x6f, 0x72, 0x6c, 0x64, // "world"
    ];
    let claims = CwtClaims::from_cbor_bytes(&cbor).unwrap();
    assert!(claims.custom_claims.is_empty(), "array should be skipped");
}

#[test]
fn decode_skips_array_value_with_bstr_elements() {
    // map(1) { 100: [h'AABB', h'CCDD'] }
    let cbor = vec![
        0xa1, // map(1)
        0x18, 0x64, // unsigned(100)
        0x82, // array(2)
        0x42, 0xAA, 0xBB, // bytes(2) AABB
        0x42, 0xCC, 0xDD, // bytes(2) CCDD
    ];
    let claims = CwtClaims::from_cbor_bytes(&cbor).unwrap();
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn decode_skips_array_with_bool_elements() {
    // map(1) { 100: [true, false] }
    let cbor = vec![
        0xa1, // map(1)
        0x18, 0x64, // unsigned(100)
        0x82, // array(2)
        0xf5, // true
        0xf4, // false
    ];
    let claims = CwtClaims::from_cbor_bytes(&cbor).unwrap();
    assert!(claims.custom_claims.is_empty());
}

// ---------------------------------------------------------------------------
// Decode: map custom claim value is skipped (covers skip-map path)
// ---------------------------------------------------------------------------

#[test]
fn decode_skips_map_value_with_text_string_key() {
    // map(1) { 100: {"key": 42} }
    let cbor = vec![
        0xa1, // map(1)
        0x18, 0x64, // unsigned(100)
        0xa1, // map(1)
        0x63, 0x6b, 0x65, 0x79, // "key"
        0x18, 0x2a, // unsigned(42)
    ];
    let claims = CwtClaims::from_cbor_bytes(&cbor).unwrap();
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn decode_skips_map_value_with_bstr_value() {
    // map(1) { 100: {1: h'BEEF'} }
    let cbor = vec![
        0xa1, // map(1)
        0x18, 0x64, // unsigned(100)
        0xa1, // map(1)
        0x01, // key: 1
        0x42, 0xBE, 0xEF, // bytes(2) BEEF
    ];
    let claims = CwtClaims::from_cbor_bytes(&cbor).unwrap();
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn decode_skips_map_value_with_bool_value() {
    // map(1) { 100: {1: true} }
    let cbor = vec![
        0xa1, // map(1)
        0x18, 0x64, // unsigned(100)
        0xa1, // map(1)
        0x01, // key: 1
        0xf5, // true
    ];
    let claims = CwtClaims::from_cbor_bytes(&cbor).unwrap();
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn decode_skips_map_value_with_text_value() {
    // map(1) { 100: {1: "val"} }
    let cbor = vec![
        0xa1, // map(1)
        0x18, 0x64, // unsigned(100)
        0xa1, // map(1)
        0x01, // key: 1
        0x63, 0x76, 0x61, 0x6c, // "val"
    ];
    let claims = CwtClaims::from_cbor_bytes(&cbor).unwrap();
    assert!(claims.custom_claims.is_empty());
}

// ---------------------------------------------------------------------------
// Decode: tagged custom claim => error (unsupported complex type)
// ---------------------------------------------------------------------------

#[test]
fn decode_error_unsupported_tagged_value() {
    // map(1) { 100: tag(1) 0 }
    let cbor = vec![
        0xa1, // map(1)
        0x18, 0x64, // unsigned(100)
        0xc1, // tag(1)
        0x00, // unsigned(0)
    ];
    let err = CwtClaims::from_cbor_bytes(&cbor).unwrap_err();
    match err {
        HeaderError::CborDecodingError(msg) => {
            assert!(msg.contains("Unsupported CWT claim value type"));
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Decode: mixed standard + custom claims + skipped complex values
// ---------------------------------------------------------------------------

#[test]
fn decode_mixed_standard_simple_custom_and_skipped_complex() {
    // map(4) { 1: "iss", 2: "sub", 100: 42, 101: [1] }
    let cbor = vec![
        0xa4, // map(4)
        0x01, // key: 1 (issuer)
        0x63, 0x69, 0x73, 0x73, // "iss"
        0x02, // key: 2 (subject)
        0x63, 0x73, 0x75, 0x62, // "sub"
        0x18, 0x64, // key: 100
        0x18, 0x2a, // unsigned(42)
        0x18, 0x65, // key: 101
        0x81, // array(1)
        0x01, // unsigned(1)
    ];
    let claims = CwtClaims::from_cbor_bytes(&cbor).unwrap();
    assert_eq!(claims.issuer.as_deref(), Some("iss"));
    assert_eq!(claims.subject.as_deref(), Some("sub"));
    assert_eq!(
        claims.custom_claims.get(&100),
        Some(&CwtClaimValue::Integer(42))
    );
    // label 101 (array) should have been skipped
    assert!(!claims.custom_claims.contains_key(&101));
}

// ---------------------------------------------------------------------------
// Float encoding is unsupported (EverParse limitation)
// ---------------------------------------------------------------------------

#[test]
fn encode_float_custom_claim_fails() {
    let claims = CwtClaims::new().with_custom_claim(200, CwtClaimValue::Float(3.14));
    let err = claims.to_cbor_bytes().unwrap_err();
    match err {
        HeaderError::CborEncodingError(msg) => {
            assert!(msg.contains("floating-point"));
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// CwtClaimValue — Debug output for every variant
// ---------------------------------------------------------------------------

#[test]
fn cwt_claim_value_debug_text() {
    let v = CwtClaimValue::Text("hello".to_string());
    let dbg = format!("{:?}", v);
    assert!(dbg.contains("Text"));
    assert!(dbg.contains("hello"));
}

#[test]
fn cwt_claim_value_debug_integer() {
    let v = CwtClaimValue::Integer(-7);
    let dbg = format!("{:?}", v);
    assert!(dbg.contains("Integer"));
    assert!(dbg.contains("-7"));
}

#[test]
fn cwt_claim_value_debug_bytes() {
    let v = CwtClaimValue::Bytes(vec![0xAA, 0xBB]);
    let dbg = format!("{:?}", v);
    assert!(dbg.contains("Bytes"));
}

#[test]
fn cwt_claim_value_debug_bool() {
    let v = CwtClaimValue::Bool(false);
    let dbg = format!("{:?}", v);
    assert!(dbg.contains("Bool"));
    assert!(dbg.contains("false"));
}

#[test]
fn cwt_claim_value_debug_float() {
    let v = CwtClaimValue::Float(2.718);
    let dbg = format!("{:?}", v);
    assert!(dbg.contains("Float"));
}

// ---------------------------------------------------------------------------
// CwtClaimValue — Clone + PartialEq
// ---------------------------------------------------------------------------

#[test]
fn cwt_claim_value_clone_equality() {
    let values: Vec<CwtClaimValue> = vec![
        CwtClaimValue::Text("t".to_string()),
        CwtClaimValue::Integer(0),
        CwtClaimValue::Bytes(vec![]),
        CwtClaimValue::Bool(true),
        CwtClaimValue::Float(0.0),
    ];
    for v in &values {
        assert_eq!(v, &v.clone());
    }
}

#[test]
fn cwt_claim_value_inequality_across_variants() {
    let text = CwtClaimValue::Text("a".to_string());
    let int = CwtClaimValue::Integer(1);
    let bytes = CwtClaimValue::Bytes(vec![1]);
    let b = CwtClaimValue::Bool(true);
    let f = CwtClaimValue::Float(1.0);
    assert_ne!(text, int);
    assert_ne!(int, bytes);
    assert_ne!(bytes, b);
    assert_ne!(b, f);
}

// ---------------------------------------------------------------------------
// CwtClaims — Debug output
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_debug_includes_field_names() {
    let claims = CwtClaims::new()
        .with_issuer("dbg-iss")
        .with_custom_claim(50, CwtClaimValue::Bool(true));
    let dbg = format!("{:?}", claims);
    assert!(dbg.contains("issuer"));
    assert!(dbg.contains("dbg-iss"));
    assert!(dbg.contains("custom_claims"));
}

// ---------------------------------------------------------------------------
// CwtClaims — Clone
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_clone_preserves_all_fields() {
    let claims = CwtClaims::new()
        .with_issuer("clone-iss")
        .with_subject("clone-sub")
        .with_audience("clone-aud")
        .with_expiration_time(123)
        .with_not_before(100)
        .with_issued_at(110)
        .with_cwt_id(vec![1, 2])
        .with_custom_claim(99, CwtClaimValue::Integer(7));

    let cloned = claims.clone();
    assert_eq!(cloned.issuer, claims.issuer);
    assert_eq!(cloned.subject, claims.subject);
    assert_eq!(cloned.audience, claims.audience);
    assert_eq!(cloned.expiration_time, claims.expiration_time);
    assert_eq!(cloned.not_before, claims.not_before);
    assert_eq!(cloned.issued_at, claims.issued_at);
    assert_eq!(cloned.cwt_id, claims.cwt_id);
    assert_eq!(cloned.custom_claims, claims.custom_claims);
}

// ---------------------------------------------------------------------------
// Builder setters and getters via direct field access
// ---------------------------------------------------------------------------

#[test]
fn direct_field_set_and_roundtrip() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("direct-iss".to_string());
    claims.subject = Some("direct-sub".to_string());
    claims.audience = Some("direct-aud".to_string());
    claims.expiration_time = Some(999);
    claims.not_before = Some(888);
    claims.issued_at = Some(777);
    claims.cwt_id = Some(vec![0xFF]);
    claims
        .custom_claims
        .insert(10, CwtClaimValue::Text("x".to_string()));

    let bytes = claims.to_cbor_bytes().unwrap();
    let d = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    assert_eq!(d.issuer.as_deref(), Some("direct-iss"));
    assert_eq!(d.subject.as_deref(), Some("direct-sub"));
    assert_eq!(d.audience.as_deref(), Some("direct-aud"));
    assert_eq!(d.expiration_time, Some(999));
    assert_eq!(d.not_before, Some(888));
    assert_eq!(d.issued_at, Some(777));
    assert_eq!(d.cwt_id, Some(vec![0xFF]));
    assert_eq!(
        d.custom_claims.get(&10),
        Some(&CwtClaimValue::Text("x".to_string()))
    );
}

// ---------------------------------------------------------------------------
// Individual builder method tests (for branch coverage of each with_* )
// ---------------------------------------------------------------------------

#[test]
fn builder_with_issuer_only() {
    let c = CwtClaims::new().with_issuer("i");
    let d = CwtClaims::from_cbor_bytes(&c.to_cbor_bytes().unwrap()).unwrap();
    assert_eq!(d.issuer.as_deref(), Some("i"));
    assert!(d.subject.is_none());
}

#[test]
fn builder_with_subject_only() {
    let c = CwtClaims::new().with_subject("s");
    let d = CwtClaims::from_cbor_bytes(&c.to_cbor_bytes().unwrap()).unwrap();
    assert_eq!(d.subject.as_deref(), Some("s"));
    assert!(d.issuer.is_none());
}

#[test]
fn builder_with_audience_only() {
    let c = CwtClaims::new().with_audience("a");
    let d = CwtClaims::from_cbor_bytes(&c.to_cbor_bytes().unwrap()).unwrap();
    assert_eq!(d.audience.as_deref(), Some("a"));
}

#[test]
fn builder_with_expiration_time_only() {
    let c = CwtClaims::new().with_expiration_time(42);
    let d = CwtClaims::from_cbor_bytes(&c.to_cbor_bytes().unwrap()).unwrap();
    assert_eq!(d.expiration_time, Some(42));
}

#[test]
fn builder_with_not_before_only() {
    let c = CwtClaims::new().with_not_before(10);
    let d = CwtClaims::from_cbor_bytes(&c.to_cbor_bytes().unwrap()).unwrap();
    assert_eq!(d.not_before, Some(10));
}

#[test]
fn builder_with_issued_at_only() {
    let c = CwtClaims::new().with_issued_at(20);
    let d = CwtClaims::from_cbor_bytes(&c.to_cbor_bytes().unwrap()).unwrap();
    assert_eq!(d.issued_at, Some(20));
}

#[test]
fn builder_with_cwt_id_only() {
    let c = CwtClaims::new().with_cwt_id(vec![0x01, 0x02]);
    let d = CwtClaims::from_cbor_bytes(&c.to_cbor_bytes().unwrap()).unwrap();
    assert_eq!(d.cwt_id, Some(vec![0x01, 0x02]));
}

#[test]
fn builder_with_custom_claim_only() {
    let c = CwtClaims::new().with_custom_claim(50, CwtClaimValue::Bool(true));
    let d = CwtClaims::from_cbor_bytes(&c.to_cbor_bytes().unwrap()).unwrap();
    assert_eq!(d.custom_claims.get(&50), Some(&CwtClaimValue::Bool(true)));
}

// ---------------------------------------------------------------------------
// DEFAULT_SUBJECT constant
// ---------------------------------------------------------------------------

#[test]
fn default_subject_constant() {
    assert_eq!(CwtClaims::DEFAULT_SUBJECT, "unknown.intent");
}

// ---------------------------------------------------------------------------
// CWTClaimsHeaderLabels constants
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_header_labels_values() {
    assert_eq!(CWTClaimsHeaderLabels::ISSUER, 1);
    assert_eq!(CWTClaimsHeaderLabels::SUBJECT, 2);
    assert_eq!(CWTClaimsHeaderLabels::AUDIENCE, 3);
    assert_eq!(CWTClaimsHeaderLabels::EXPIRATION_TIME, 4);
    assert_eq!(CWTClaimsHeaderLabels::NOT_BEFORE, 5);
    assert_eq!(CWTClaimsHeaderLabels::ISSUED_AT, 6);
    assert_eq!(CWTClaimsHeaderLabels::CWT_ID, 7);
    assert_eq!(CWTClaimsHeaderLabels::CWT_CLAIMS_HEADER, 15);
}

// ---------------------------------------------------------------------------
// Large positive / negative timestamps
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_large_positive_timestamp() {
    let c = CwtClaims::new().with_expiration_time(i64::MAX);
    let d = CwtClaims::from_cbor_bytes(&c.to_cbor_bytes().unwrap()).unwrap();
    assert_eq!(d.expiration_time, Some(i64::MAX));
}

#[test]
fn roundtrip_large_negative_timestamp() {
    let c = CwtClaims::new().with_not_before(i64::MIN);
    let d = CwtClaims::from_cbor_bytes(&c.to_cbor_bytes().unwrap()).unwrap();
    assert_eq!(d.not_before, Some(i64::MIN));
}

// ---------------------------------------------------------------------------
// HeaderError Display coverage
// ---------------------------------------------------------------------------

#[test]
fn header_error_display_cbor_encoding() {
    let e = HeaderError::CborEncodingError("test-enc".into());
    let msg = format!("{}", e);
    assert!(msg.contains("CBOR encoding error"));
    assert!(msg.contains("test-enc"));
}

#[test]
fn header_error_display_cbor_decoding() {
    let e = HeaderError::CborDecodingError("test-dec".into());
    let msg = format!("{}", e);
    assert!(msg.contains("CBOR decoding error"));
    assert!(msg.contains("test-dec"));
}

#[test]
fn header_error_display_invalid_claim_type() {
    let e = HeaderError::InvalidClaimType {
        label: 1,
        expected: "text".into(),
        actual: "integer".into(),
    };
    let msg = format!("{}", e);
    assert!(msg.contains("Invalid CWT claim type"));
    assert!(msg.contains("label 1"));
}

#[test]
fn header_error_display_missing_required_claim() {
    let e = HeaderError::MissingRequiredClaim("subject".into());
    let msg = format!("{}", e);
    assert!(msg.contains("Missing required claim"));
    assert!(msg.contains("subject"));
}

#[test]
fn header_error_display_invalid_timestamp() {
    let e = HeaderError::InvalidTimestamp("negative".into());
    let msg = format!("{}", e);
    assert!(msg.contains("Invalid timestamp"));
}

#[test]
fn header_error_display_complex_claim_value() {
    let e = HeaderError::ComplexClaimValue("nested".into());
    let msg = format!("{}", e);
    assert!(msg.contains("Custom claim value too complex"));
}

#[test]
fn header_error_is_std_error() {
    let e = HeaderError::CborEncodingError("x".into());
    let _: &dyn std::error::Error = &e;
}

// ---------------------------------------------------------------------------
// Overwriting custom claims via builder
// ---------------------------------------------------------------------------

#[test]
fn overwrite_custom_claim_keeps_last_value() {
    let c = CwtClaims::new()
        .with_custom_claim(10, CwtClaimValue::Integer(1))
        .with_custom_claim(10, CwtClaimValue::Integer(2));
    assert_eq!(c.custom_claims.len(), 1);
    assert_eq!(c.custom_claims.get(&10), Some(&CwtClaimValue::Integer(2)));
}

// ---------------------------------------------------------------------------
// Multiple custom claims of same type
// ---------------------------------------------------------------------------

#[test]
fn multiple_text_custom_claims_roundtrip() {
    let c = CwtClaims::new()
        .with_custom_claim(50, CwtClaimValue::Text("a".to_string()))
        .with_custom_claim(51, CwtClaimValue::Text("b".to_string()))
        .with_custom_claim(52, CwtClaimValue::Text("c".to_string()));
    let d = CwtClaims::from_cbor_bytes(&c.to_cbor_bytes().unwrap()).unwrap();
    assert_eq!(d.custom_claims.len(), 3);
}

// ---------------------------------------------------------------------------
// Decode: map(2) with skipped complex + real simple claim
// ---------------------------------------------------------------------------

#[test]
fn decode_skips_map_value_preserves_subsequent_simple() {
    // map(2) { 100: {1: 2}, 101: 42 }
    let cbor = vec![
        0xa2, // map(2)
        0x18, 0x64, // key: 100
        0xa1, // map(1)
        0x01, 0x02, // {1: 2}
        0x18, 0x65, // key: 101
        0x18, 0x2a, // unsigned(42)
    ];
    let claims = CwtClaims::from_cbor_bytes(&cbor).unwrap();
    assert!(!claims.custom_claims.contains_key(&100));
    assert_eq!(
        claims.custom_claims.get(&101),
        Some(&CwtClaimValue::Integer(42))
    );
}

// ---------------------------------------------------------------------------
// Decode: array skip followed by simple claim
// ---------------------------------------------------------------------------

#[test]
fn decode_skips_array_preserves_subsequent_simple() {
    // map(2) { 100: [1,2], 101: "hi" }
    let cbor = vec![
        0xa2, // map(2)
        0x18, 0x64, // key: 100
        0x82, 0x01, 0x02, // array(2) [1,2]
        0x18, 0x65, // key: 101
        0x62, 0x68, 0x69, // "hi"
    ];
    let claims = CwtClaims::from_cbor_bytes(&cbor).unwrap();
    assert!(!claims.custom_claims.contains_key(&100));
    assert_eq!(
        claims.custom_claims.get(&101),
        Some(&CwtClaimValue::Text("hi".to_string()))
    );
}
