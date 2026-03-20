// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for CoseSign1Message — targets remaining uncovered lines.
//!
//! Focuses on:
//! - encode() round-trip (tagged and untagged)
//! - Unprotected header decoding for various value types
//! - decode_header_value for NegativeInt, ByteString, TextString, Array, Map,
//!   Tag, Bool, Null, Undefined paths
//! - decode_payload null vs bstr paths
//! - verify_detached, verify_detached_read, verify_streaming
//! - Protected header accessor methods

use std::sync::Arc;

use cbor_primitives::{CborDecoder, CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::algorithms::COSE_SIGN1_TAG;
use cose_sign1_primitives::headers::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::{MemoryPayload, ProtectedHeader, StreamingPayload};
use crypto_primitives::{CryptoError, CryptoVerifier, VerifyingContext};

// ---------------------------------------------------------------------------
// Stub verifier for testing verify methods without real crypto
// ---------------------------------------------------------------------------

struct AlwaysTrueVerifier;

impl CryptoVerifier for AlwaysTrueVerifier {
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn supports_streaming(&self) -> bool {
        false
    }
    fn verify_init(&self, _sig: &[u8]) -> Result<Box<dyn VerifyingContext>, CryptoError> {
        unimplemented!()
    }
}

struct AlwaysFalseVerifier;

impl CryptoVerifier for AlwaysFalseVerifier {
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(false)
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn supports_streaming(&self) -> bool {
        false
    }
    fn verify_init(&self, _sig: &[u8]) -> Result<Box<dyn VerifyingContext>, CryptoError> {
        unimplemented!()
    }
}

// ---------------------------------------------------------------------------
// Helper: build a minimal COSE_Sign1 message from components
// ---------------------------------------------------------------------------

fn build_cose_sign1(
    tagged: bool,
    protected_cbor: &[u8],
    unprotected_cbor: &[u8],
    payload: Option<&[u8]>,
    signature: &[u8],
) -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();

    if tagged {
        enc.encode_tag(COSE_SIGN1_TAG).unwrap();
    }

    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected_cbor).unwrap();
    enc.encode_raw(unprotected_cbor).unwrap();

    match payload {
        Some(p) => enc.encode_bstr(p).unwrap(),
        None => enc.encode_null().unwrap(),
    }

    enc.encode_bstr(signature).unwrap();
    enc.into_bytes()
}

fn empty_map_cbor() -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(0).unwrap();
    enc.into_bytes()
}

// ===========================================================================
// encode() round-trip — tagged (lines 378, 384-411)
// ===========================================================================

#[test]
fn encode_tagged_roundtrip() {
    let protected_bytes = {
        let mut map = CoseHeaderMap::new();
        map.set_alg(-7);
        map.encode().unwrap()
    };
    let unprotected = empty_map_cbor();
    let payload = b"hello";
    let sig = b"fake_sig";

    let raw = build_cose_sign1(true, &protected_bytes, &unprotected, Some(payload), sig);
    let msg = CoseSign1Message::parse(&raw).unwrap();

    let encoded = msg.encode(true).unwrap();
    let reparsed = CoseSign1Message::parse(&encoded).unwrap();
    assert_eq!(reparsed.alg(), Some(-7));
    assert_eq!(reparsed.payload(), Some(payload.as_slice()));
    assert_eq!(reparsed.signature(), sig);
}

#[test]
fn encode_untagged_roundtrip() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), None, b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    assert!(msg.is_detached());

    let encoded = msg.encode(false).unwrap();
    let reparsed = CoseSign1Message::parse(&encoded).unwrap();
    assert!(reparsed.is_detached());
    assert_eq!(reparsed.signature(), b"s");
}

#[test]
fn encode_with_null_payload() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), None, b"sig");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    assert!(msg.payload().is_none());

    let encoded = msg.encode(false).unwrap();
    let reparsed = CoseSign1Message::parse(&encoded).unwrap();
    assert!(reparsed.payload().is_none());
}

// ===========================================================================
// Unprotected header decoding with rich value types (lines 441-506+)
// ===========================================================================

fn build_unprotected_map_cbor(
    entries: Vec<(
        i64,
        Box<dyn Fn(&mut <EverParseCborProvider as CborProvider>::Encoder)>,
    )>,
) -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(entries.len()).unwrap();
    for (label, encode_fn) in &entries {
        enc.encode_i64(*label).unwrap();
        encode_fn(&mut enc);
    }
    enc.into_bytes()
}

#[test]
fn unprotected_header_negative_int_value() {
    let unp = build_unprotected_map_cbor(vec![(
        10,
        Box::new(|e: &mut _| {
            CborEncoder::encode_i64(e, -99).unwrap();
        }),
    )]);
    let raw = build_cose_sign1(false, &[], &unp, Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Int(-99))
    );
}

#[test]
fn unprotected_header_bytes_value() {
    let unp = build_unprotected_map_cbor(vec![(
        20,
        Box::new(|e: &mut _| {
            CborEncoder::encode_bstr(e, &[0xAB, 0xCD]).unwrap();
        }),
    )]);
    let raw = build_cose_sign1(false, &[], &unp, Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(20)),
        Some(&CoseHeaderValue::Bytes(vec![0xAB, 0xCD].into()))
    );
}

#[test]
fn unprotected_header_text_value() {
    let unp = build_unprotected_map_cbor(vec![(
        30,
        Box::new(|e: &mut _| {
            CborEncoder::encode_tstr(e, "txt").unwrap();
        }),
    )]);
    let raw = build_cose_sign1(false, &[], &unp, Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(30)),
        Some(&CoseHeaderValue::Text("txt".to_string().into()))
    );
}

#[test]
fn unprotected_header_array_value() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(40).unwrap();
    enc.encode_array(2).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(2).unwrap();
    let unp = enc.into_bytes();

    let raw = build_cose_sign1(false, &[], &unp, Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    if let Some(CoseHeaderValue::Array(arr)) =
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(40))
    {
        assert_eq!(arr.len(), 2);
    } else {
        panic!("expected Array");
    }
}

#[test]
fn unprotected_header_map_value() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(50).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(2).unwrap();
    let unp = enc.into_bytes();

    let raw = build_cose_sign1(false, &[], &unp, Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    if let Some(CoseHeaderValue::Map(pairs)) =
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(50))
    {
        assert_eq!(pairs.len(), 1);
    } else {
        panic!("expected Map");
    }
}

#[test]
fn unprotected_header_tagged_value() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(60).unwrap();
    enc.encode_tag(18).unwrap();
    enc.encode_bstr(&[0xFF]).unwrap();
    let unp = enc.into_bytes();

    let raw = build_cose_sign1(false, &[], &unp, Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    if let Some(CoseHeaderValue::Tagged(tag, inner)) =
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(60))
    {
        assert_eq!(*tag, 18);
        assert_eq!(**inner, CoseHeaderValue::Bytes(vec![0xFF].into()));
    } else {
        panic!("expected Tagged");
    }
}

#[test]
fn unprotected_header_bool_value() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(70).unwrap();
    enc.encode_bool(true).unwrap();
    let unp = enc.into_bytes();

    let raw = build_cose_sign1(false, &[], &unp, Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(70)),
        Some(&CoseHeaderValue::Bool(true))
    );
}

#[test]
fn unprotected_header_null_value() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(80).unwrap();
    enc.encode_null().unwrap();
    let unp = enc.into_bytes();

    let raw = build_cose_sign1(false, &[], &unp, Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(80)),
        Some(&CoseHeaderValue::Null)
    );
}

#[test]
fn unprotected_header_undefined_value() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(90).unwrap();
    enc.encode_undefined().unwrap();
    let unp = enc.into_bytes();

    let raw = build_cose_sign1(false, &[], &unp, Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(90)),
        Some(&CoseHeaderValue::Undefined)
    );
}

#[test]
fn unprotected_header_text_label() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("custom").unwrap();
    enc.encode_i64(42).unwrap();
    let unp = enc.into_bytes();

    let raw = build_cose_sign1(false, &[], &unp, Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    assert_eq!(
        msg.unprotected_headers()
            .get(&CoseHeaderLabel::Text("custom".to_string())),
        Some(&CoseHeaderValue::Int(42))
    );
}

// ===========================================================================
// decode_payload paths (lines 620-637)
// ===========================================================================

#[test]
fn decode_payload_null() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), None, b"sig");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    assert!(msg.payload().is_none());
    assert!(msg.is_detached());
}

#[test]
fn decode_payload_bstr() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), Some(b"data"), b"sig");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    assert_eq!(msg.payload(), Some(b"data".as_slice()));
    assert!(!msg.is_detached());
}

// ===========================================================================
// verify_detached (line 222)
// ===========================================================================

#[test]
fn verify_detached_true() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), None, b"sig");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    let result = msg.verify_detached(&AlwaysTrueVerifier, b"payload", None);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn verify_detached_false() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), None, b"sig");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    let result = msg.verify_detached(&AlwaysFalseVerifier, b"payload", None);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

// ===========================================================================
// verify_detached_read (line 293)
// ===========================================================================

#[test]
fn verify_detached_read_ok() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), None, b"sig");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    let mut cursor = std::io::Cursor::new(b"payload");
    let result = msg.verify_detached_read(&AlwaysTrueVerifier, &mut cursor, None);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

// ===========================================================================
// verify with embedded payload (line 202)
// ===========================================================================

#[test]
fn verify_embedded_payload_ok() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), Some(b"payload"), b"sig");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    let result = msg.verify(&AlwaysTrueVerifier, None);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn verify_embedded_payload_missing() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), None, b"sig");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    let result = msg.verify(&AlwaysTrueVerifier, None);
    assert!(result.is_err());
}

// ===========================================================================
// verify_streaming (line 310)
// ===========================================================================

#[test]
fn verify_streaming_ok() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), None, b"sig");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    let payload: Arc<dyn StreamingPayload> = Arc::new(MemoryPayload::new(b"payload".to_vec()));
    let result = msg.verify_streaming(&AlwaysTrueVerifier, payload, None);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

// ===========================================================================
// protected_headers() accessor (line 130-132 — the accessor methods)
// ===========================================================================

#[test]
fn protected_headers_accessor() {
    let protected = {
        let mut map = CoseHeaderMap::new();
        map.set_alg(-7);
        map.encode().unwrap()
    };
    let raw = build_cose_sign1(false, &protected, &empty_map_cbor(), Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();

    let ph = msg.protected_headers();
    assert_eq!(ph.alg(), Some(-7));
    assert!(!msg.protected_header_bytes().is_empty());
}

// ===========================================================================
// sig_structure_bytes (lines 353-363)
// ===========================================================================

#[test]
fn sig_structure_bytes_ok() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), None, b"sig");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    let result = msg.sig_structure_bytes(b"payload", None);
    assert!(result.is_ok());
    assert!(!result.unwrap().is_empty());
}

#[test]
fn sig_structure_bytes_with_external_aad() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), None, b"sig");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    let result = msg.sig_structure_bytes(b"payload", Some(b"extra"));
    assert!(result.is_ok());
}

// ===========================================================================
// provider() accessor
// ===========================================================================

#[test]
fn provider_accessor() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    let _provider = msg.provider();
}

// ===========================================================================
// Debug impl (lines 54-61)
// ===========================================================================

#[test]
fn debug_impl() {
    let raw = build_cose_sign1(false, &[], &empty_map_cbor(), Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    let debug_str = format!("{:?}", msg);
    assert!(debug_str.contains("CoseSign1Message"));
}

// ===========================================================================
// Nested array inside unprotected header — exercises the array len + loop
// (lines 524-545)
// ===========================================================================

#[test]
fn unprotected_header_nested_array() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(100).unwrap();
    enc.encode_array(2).unwrap();
    // inner array
    enc.encode_array(1).unwrap();
    enc.encode_i64(42).unwrap();
    // int
    enc.encode_i64(99).unwrap();
    let unp = enc.into_bytes();

    let raw = build_cose_sign1(false, &[], &unp, Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    if let Some(CoseHeaderValue::Array(arr)) =
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(100))
    {
        assert_eq!(arr.len(), 2);
        if let CoseHeaderValue::Array(inner) = &arr[0] {
            assert_eq!(inner.len(), 1);
            assert_eq!(inner[0], CoseHeaderValue::Int(42));
        } else {
            panic!("expected inner array");
        }
    } else {
        panic!("expected array");
    }
}

// ===========================================================================
// Map inside unprotected header with text label key (lines 548-577)
// ===========================================================================

#[test]
fn unprotected_header_map_with_text_keys() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(110).unwrap();
    enc.encode_map(2).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(10).unwrap();
    enc.encode_tstr("key2").unwrap();
    enc.encode_tstr("val2").unwrap();
    let unp = enc.into_bytes();

    let raw = build_cose_sign1(false, &[], &unp, Some(b"p"), b"s");
    let msg = CoseSign1Message::parse(&raw).unwrap();
    if let Some(CoseHeaderValue::Map(pairs)) =
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(110))
    {
        assert_eq!(pairs.len(), 2);
    } else {
        panic!("expected map");
    }
}
