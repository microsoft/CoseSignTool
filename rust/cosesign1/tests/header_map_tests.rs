// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for header map decoding and accessors.
//!
//! These tests primarily exercise `HeaderMap` decoding behavior and typed
//! accessors (`get_i64`, `get_bytes`, `get_array`) through the public parsing
//! API.

mod common;

use common::*;
use minicbor::data::Tag;

/// Rejects unsupported key/value types inside header maps.
#[test]
fn header_map_rejects_unsupported_key_and_value_types() {
    // Unsupported key type (bytes) inside protected header map.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.map(1).unwrap();
    enc.bytes(b"k").unwrap();
    enc.i64(1).unwrap();
    let protected = enc.into_writer();

    let msg = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let err = cosesign1::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("unsupported header key type"));

    // Unsupported value type (tag) inside protected header map.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.map(1).unwrap();
    enc.i64(1).unwrap();
    enc.tag(Tag::new(1)).unwrap();
    enc.null().unwrap();
    let protected = enc.into_writer();

    let msg = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let err = cosesign1::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("unsupported header value type"));
}

/// Exercises parsed view accessors and `HeaderMap` helper methods.
#[test]
fn parsed_view_and_header_map_helpers_are_exercised() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der);
    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);

    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();
    let view = msg.parsed.signature1_sig_structure_view();
    assert_eq!(
        view.context,
        cosesign1_abstractions::SIG_STRUCTURE_CONTEXT_SIGNATURE1
    );

    // Exercise header-map accessors and clear().
    assert_eq!(msg.parsed.protected_headers.get_i64(1), Some(-7));
    assert!(msg.parsed.unprotected_headers.get_array(33).is_some());
    let mut hm = msg.parsed.unprotected_headers.clone();
    hm.clear();
    assert!(hm.map().is_empty());
}

/// Ensures typed getters return `None` for wrong underlying value types.
#[test]
fn header_map_getters_return_none_for_wrong_value_types() {
    let protected = encode_protected_header_bytes(&[(
        1,
        TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64),
    )]);
    let unprotected = vec![(TestCborKey::Int(42), TestCborValue::Text("not-an-int-or-bytes-or-array"))];
    let cose = encode_cose_sign1(false, &protected, &unprotected, Some(b"hello"), &[0u8; 64]);
    let parsed = cosesign1::parse_cose_sign1(&cose).unwrap();

    assert!(parsed.unprotected_headers.get_i64(42).is_none());
    assert!(parsed.unprotected_headers.get_bytes(42).is_none());
    assert!(parsed.unprotected_headers.get_array(42).is_none());
}

/// Allows `null` values and rejects unsupported header value types (float).
#[test]
fn header_map_decodes_null_and_rejects_unsupported_value_types() {
    // Null value in unprotected headers should decode.
    let protected = encode_protected_header_bytes(&[]);
    let unprotected = vec![(TestCborKey::Int(9), TestCborValue::Null)];
    let cose = encode_cose_sign1(false, &protected, &unprotected, Some(b"hello"), &[0u8; 1]);
    let parsed = cosesign1::parse_cose_sign1(&cose).unwrap();
    assert!(matches!(
        parsed
            .unprotected_headers
            .map()
            .get(&cosesign1_abstractions::HeaderKey::Int(9)),
        Some(cosesign1_abstractions::HeaderValue::Null)
    ));

    // Unsupported header value type: float.
    let protected = encode_protected_header_bytes(&[]);
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(1).unwrap();
    enc.i64(1).unwrap();
    enc.f64(1.0).unwrap();
    enc.bytes(b"hello").unwrap();
    enc.bytes(&[0u8; 1]).unwrap();
    let bad = enc.into_writer();
    assert!(cosesign1::parse_cose_sign1(&bad).is_err());
}

/// Rejects indefinite-length CBOR maps/arrays in headers.
#[test]
fn header_map_rejects_indefinite_length_maps_and_arrays() {
    // Unprotected headers as an indefinite-length map should be rejected.
    let cose = vec![
        0x84, // array(4)
        0x41, 0xA0, // protected: bstr(1) containing empty map (0xA0)
        0xBF, 0xFF, // unprotected: map(*) ... break
        0x40, // payload: empty bstr
        0x40, // signature: empty bstr
    ];
    assert!(cosesign1::parse_cose_sign1(&cose).is_err());

    // Indefinite-length array nested as a header value should be rejected.
    let cose = vec![
        0x84, // array(4)
        0x41, 0xA0, // protected
        0xA1, // map(1)
        0x01, // key: 1
        0x9F, 0xFF, // value: array(*) ... break
        0x40, // payload
        0x40, // signature
    ];
    assert!(cosesign1::parse_cose_sign1(&cose).is_err());
}

/// Rejects unsupported CBOR key types in header maps.
#[test]
fn header_map_rejects_unsupported_key_types() {
    // Unprotected header map with a boolean key (unsupported).
    let cose = vec![
        0x84, // array(4)
        0x41, 0xA0, // protected
        0xA1, // map(1)
        0xF5, // key: true
        0x01, // value: 1
        0x40, // payload
        0x40, // signature
    ];
    assert!(cosesign1::parse_cose_sign1(&cose).is_err());
}
