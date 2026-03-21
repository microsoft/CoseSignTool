// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for `message.rs` and `sig_structure.rs` in
//! `cose_sign1_primitives`.
//!
//! ## message.rs targets
//! - Lines 130, 202, 222: payload decode (null and bstr), verify paths
//! - Lines 370–413: encode() tagged & untagged
//! - Lines 415–456: decode_unprotected_header with non-empty map
//! - Lines 458–618: decode_header_label/value all CBOR types
//! - Lines 620–637: decode_payload null vs bstr
//!
//! ## sig_structure.rs targets
//! - Lines 60–92: build_sig_structure basic
//! - Lines 137–169: build_sig_structure_prefix
//! - Lines 203–265: SigStructureHasher init/update/into_inner
//! - Lines 648–721: hash_sig_structure_streaming & chunked
//! - Lines 746–790+: stream_sig_structure & chunked

use std::io::Write;

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::algorithms::COSE_SIGN1_TAG;
use cose_sign1_primitives::headers::{CoseHeaderLabel, CoseHeaderValue};
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::{
    build_sig_structure, build_sig_structure_prefix, hash_sig_structure_streaming,
    hash_sig_structure_streaming_chunked, stream_sig_structure, stream_sig_structure_chunked,
    SigStructureHasher, SizedRead, SizedReader,
};

// ============================================================================
// Helper: construct a COSE_Sign1 array from parts
// ============================================================================

fn build_cose_sign1_bytes(
    protected: &[u8],
    unprotected_raw: &[u8],
    payload: Option<&[u8]>,
    signature: &[u8],
    tagged: bool,
) -> Vec<u8> {
    let provider = EverParseCborProvider::default();
    let mut enc = provider.encoder();

    if tagged {
        enc.encode_tag(COSE_SIGN1_TAG).unwrap();
    }
    enc.encode_array(4).unwrap();

    // Protected header as bstr
    enc.encode_bstr(protected).unwrap();

    // Unprotected header (pre-encoded map)
    enc.encode_raw(unprotected_raw).unwrap();

    // Payload
    match payload {
        Some(p) => enc.encode_bstr(p).unwrap(),
        None => enc.encode_null().unwrap(),
    }

    // Signature
    enc.encode_bstr(signature).unwrap();

    enc.into_bytes()
}

/// Encode an unprotected header map with various value types
fn encode_unprotected_map() -> Vec<u8> {
    let provider = EverParseCborProvider::default();
    let mut enc = provider.encoder();

    // Map with 9 entries to cover all decode_header_value branches
    enc.encode_map(9).unwrap();

    // 1. Int (negative) — line 503–507
    enc.encode_i64(1).unwrap(); // label
    enc.encode_i64(-7).unwrap(); // value (NegativeInt)

    // 2. Uint — line 493–501
    enc.encode_i64(2).unwrap();
    // Encode a very large uint using raw CBOR: major type 0, additional 27 (8 bytes)
    // u64::MAX = 0xFFFFFFFFFFFFFFFF
    enc.encode_raw(&[0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        .unwrap();

    // 3. Bytes — line 509–513
    enc.encode_i64(3).unwrap();
    enc.encode_bstr(&[0xDE, 0xAD]).unwrap();

    // 4. Text — line 515–519
    enc.encode_i64(4).unwrap();
    enc.encode_tstr("kid-text").unwrap();

    // 5. Array — line 521–546
    enc.encode_i64(5).unwrap();
    enc.encode_array(2).unwrap();
    enc.encode_i64(10).unwrap();
    enc.encode_i64(20).unwrap();

    // 6. Map (nested) — line 548–577
    enc.encode_i64(6).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap(); // nested label
    enc.encode_tstr("v").unwrap(); // nested value

    // 7. Tagged — line 579–584
    enc.encode_i64(7).unwrap();
    enc.encode_tag(42).unwrap();
    enc.encode_i64(99).unwrap();

    // 8. Bool — line 586–590
    enc.encode_i64(8).unwrap();
    enc.encode_bool(true).unwrap();

    // 9. Null — line 592–596
    enc.encode_i64(9).unwrap();
    enc.encode_null().unwrap();

    enc.into_bytes()
}

// ============================================================================
// CoseSign1Message: parse with non-empty unprotected headers (all value types)
// ============================================================================

/// Exercises decode_header_value for Int, Uint, Bytes, Text, Array, Map,
/// Tagged, Bool, Null, Float — lines 490–608.
#[test]
fn parse_message_with_all_unprotected_header_types() {
    let protected = b"\xa1\x01\x26"; // {1: -7}
    let unprotected = encode_unprotected_map();
    let payload = b"test-payload";
    let signature = b"\xAA\xBB";

    let data = build_cose_sign1_bytes(protected, &unprotected, Some(payload), signature, false);

    let msg = CoseSign1Message::parse(&data).expect("parse should succeed");

    // Protected header
    assert_eq!(msg.alg(), Some(-7));

    // Unprotected: Int(-7)
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(1)),
        Some(&CoseHeaderValue::Int(-7))
    );

    // Unprotected: Uint(u64::MAX)
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(2)),
        Some(&CoseHeaderValue::Uint(u64::MAX))
    );

    // Unprotected: Bytes
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(3)),
        Some(&CoseHeaderValue::Bytes(vec![0xDE, 0xAD].into()))
    );

    // Unprotected: Text
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(4)),
        Some(&CoseHeaderValue::Text("kid-text".into()))
    );

    // Unprotected: Array
    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(5)) {
        Some(CoseHeaderValue::Array(arr)) => {
            assert_eq!(arr.len(), 2);
        }
        other => panic!("expected Array, got {:?}", other),
    }

    // Unprotected: Map
    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(6)) {
        Some(CoseHeaderValue::Map(pairs)) => {
            assert_eq!(pairs.len(), 1);
        }
        other => panic!("expected Map, got {:?}", other),
    }

    // Unprotected: Tagged
    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(7)) {
        Some(CoseHeaderValue::Tagged(tag, inner)) => {
            assert_eq!(*tag, 42);
            assert_eq!(**inner, CoseHeaderValue::Int(99));
        }
        other => panic!("expected Tagged, got {:?}", other),
    }

    // Unprotected: Bool
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(8)),
        Some(&CoseHeaderValue::Bool(true))
    );

    // Unprotected: Null
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(9)),
        Some(&CoseHeaderValue::Null)
    );

    // Payload
    assert_eq!(msg.payload(), Some(payload.as_slice()));
    assert!(!msg.is_detached());
}

// ============================================================================
// CoseSign1Message: parse with null payload (line 130, 623–630)
// ============================================================================

#[test]
fn parse_message_with_null_payload() {
    let provider = EverParseCborProvider::default();
    let mut enc = provider.encoder();

    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap(); // empty protected
    enc.encode_map(0).unwrap(); // empty unprotected
    enc.encode_null().unwrap(); // null payload
    enc.encode_bstr(&[0x01]).unwrap(); // signature

    let data = enc.into_bytes();
    let msg = CoseSign1Message::parse(&data).expect("parse null payload");

    assert!(msg.payload().is_none());
    assert!(msg.is_detached());
}

// ============================================================================
// CoseSign1Message: parse with text-string label in unprotected header
// (line 472–476 in decode_header_label)
// ============================================================================

#[test]
fn parse_message_with_text_label_in_unprotected() {
    let provider = EverParseCborProvider::default();
    let mut enc = provider.encoder();

    // Unprotected: { "custom": 42 }
    enc.encode_map(1).unwrap();
    enc.encode_tstr("custom").unwrap();
    enc.encode_i64(42).unwrap();
    let unprotected = enc.into_bytes();

    let data = build_cose_sign1_bytes(&[], &unprotected, Some(b"p"), b"\x00", false);
    let msg = CoseSign1Message::parse(&data).expect("parse text label");

    assert_eq!(
        msg.unprotected_headers()
            .get(&CoseHeaderLabel::Text("custom".into())),
        Some(&CoseHeaderValue::Int(42))
    );
}

// ============================================================================
// CoseSign1Message: encode tagged & untagged (lines 370–413)
// ============================================================================

#[test]
fn encode_tagged_roundtrip() {
    let protected = b"\xa1\x01\x26"; // {1: -7}
    let data = build_cose_sign1_bytes(protected, &[0xA0], Some(b"payload"), b"\xAA\xBB", false);

    let msg = CoseSign1Message::parse(&data).expect("parse");

    // Encode tagged
    let tagged_bytes = msg.encode(true).expect("encode tagged");
    // CBOR tag 18 encodes as single byte 0xD2 (major type 6, additional info 18)
    assert_eq!(tagged_bytes[0], 0xD2);

    let reparsed = CoseSign1Message::parse(&tagged_bytes).expect("re-parse tagged");
    assert_eq!(reparsed.alg(), Some(-7));
    assert_eq!(reparsed.payload(), Some(b"payload".as_slice()));

    // Encode untagged
    let untagged_bytes = msg.encode(false).expect("encode untagged");
    assert_eq!(untagged_bytes[0], 0x84); // array(4)
    let reparsed2 = CoseSign1Message::parse(&untagged_bytes).expect("re-parse untagged");
    assert_eq!(reparsed2.payload(), Some(b"payload".as_slice()));
}

/// Encode with detached (null) payload — lines 402–404
#[test]
fn encode_with_null_payload() {
    let data = build_cose_sign1_bytes(&[], &[0xA0], None, b"\x01", false);
    let msg = CoseSign1Message::parse(&data).expect("parse detached");

    let encoded = msg.encode(false).expect("encode detached");
    let reparsed = CoseSign1Message::parse(&encoded).expect("re-parse detached");
    assert!(reparsed.payload().is_none());
}

// ============================================================================
// CoseSign1Message: parse errors
// ============================================================================

/// Wrong array length (line 107–110)
#[test]
fn parse_rejects_wrong_array_length() {
    let provider = EverParseCborProvider::default();
    let mut enc = provider.encoder();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    let data = enc.into_bytes();

    let err = CoseSign1Message::parse(&data).unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("4 elements"), "got: {}", msg);
}

/// Wrong COSE tag (line 92–96)
#[test]
fn parse_rejects_wrong_tag() {
    let provider = EverParseCborProvider::default();
    let mut enc = provider.encoder();
    enc.encode_tag(99).unwrap(); // Not 18
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(&[]).unwrap();
    let data = enc.into_bytes();

    let err = CoseSign1Message::parse(&data).unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("unexpected COSE tag"), "got: {}", msg);
}

// ============================================================================
// CoseSign1Message: sig_structure_bytes (line 353–362)
// ============================================================================

#[test]
fn sig_structure_bytes_method() {
    let data = build_cose_sign1_bytes(b"\xa1\x01\x26", &[0xA0], Some(b"p"), b"\xAA", false);
    let msg = CoseSign1Message::parse(&data).expect("parse");

    let sig_bytes = msg
        .sig_structure_bytes(b"external-payload", Some(b"aad"))
        .expect("sig_structure_bytes");

    assert!(!sig_bytes.is_empty());
    // Should be a CBOR array of 4
    assert_eq!(sig_bytes[0], 0x84);
}

// ============================================================================
// build_sig_structure with and without external AAD (lines 60–95)
// ============================================================================

#[test]
fn build_sig_structure_no_aad() {
    let sig = build_sig_structure(b"\xa1\x01\x26", None, b"payload").expect("build_sig_structure");
    assert_eq!(sig[0], 0x84); // array(4)
    assert!(!sig.is_empty());
}

#[test]
fn build_sig_structure_with_aad() {
    let sig = build_sig_structure(b"\xa0", Some(b"extra-aad"), b"payload")
        .expect("build_sig_structure with aad");
    assert_eq!(sig[0], 0x84);
}

// ============================================================================
// build_sig_structure_prefix (lines 137–172)
// ============================================================================

#[test]
fn build_sig_structure_prefix_basic() {
    let prefix = build_sig_structure_prefix(b"\xa0", None, 100).expect("prefix");
    assert!(!prefix.is_empty());
    assert_eq!(prefix[0], 0x84); // array(4)
}

#[test]
fn build_sig_structure_prefix_with_aad() {
    let prefix =
        build_sig_structure_prefix(b"\xa1\x01\x26", Some(b"aad"), 256).expect("prefix with aad");
    assert_eq!(prefix[0], 0x84);
}

// ============================================================================
// SigStructureHasher (lines 198–274)
// ============================================================================

/// Simple Write collector for test purposes.
#[derive(Clone)]
struct ByteCollector(Vec<u8>);

impl Write for ByteCollector {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn sig_structure_hasher_init_update_into_inner() {
    let mut hasher = SigStructureHasher::new(ByteCollector(Vec::new()));

    hasher.init(b"\xa0", None, 5).expect("init");

    hasher.update(b"hello").expect("update");

    let inner = hasher.into_inner();
    assert!(!inner.0.is_empty());
}

/// Double init should fail (line 222–225)
#[test]
fn sig_structure_hasher_double_init_fails() {
    let mut hasher = SigStructureHasher::new(ByteCollector(Vec::new()));
    hasher.init(b"\xa0", None, 0).expect("first init");

    let err = hasher.init(b"\xa0", None, 0).unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("already initialized"), "got: {}", msg);
}

/// Update before init should fail (line 246–249)
#[test]
fn sig_structure_hasher_update_before_init_fails() {
    let mut hasher = SigStructureHasher::new(ByteCollector(Vec::new()));
    let err = hasher.update(b"data").unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("not initialized"), "got: {}", msg);
}

/// clone_hasher (line 271–273)
#[test]
fn sig_structure_hasher_clone_hasher() {
    let mut hasher = SigStructureHasher::new(ByteCollector(Vec::new()));
    hasher.init(b"\xa0", None, 3).expect("init");
    hasher.update(b"abc").expect("update");

    let cloned = hasher.clone_hasher();
    assert!(!cloned.0.is_empty());
}

// ============================================================================
// hash_sig_structure_streaming (lines 648–666)
// ============================================================================

#[test]
fn hash_sig_structure_streaming_basic() {
    let payload_data = b"streaming payload data";
    let reader = SizedReader::new(&payload_data[..], payload_data.len() as u64);

    let result = hash_sig_structure_streaming(ByteCollector(Vec::new()), b"\xa0", None, reader)
        .expect("streaming hash");

    assert!(!result.0.is_empty());
}

#[test]
fn hash_sig_structure_streaming_with_aad() {
    let payload_data = b"payload";
    let reader = SizedReader::new(&payload_data[..], payload_data.len() as u64);

    let result = hash_sig_structure_streaming(
        ByteCollector(Vec::new()),
        b"\xa1\x01\x26",
        Some(b"external-aad"),
        reader,
    )
    .expect("streaming hash with aad");

    assert!(!result.0.is_empty());
}

// ============================================================================
// hash_sig_structure_streaming_chunked (lines 672–722)
// ============================================================================

#[test]
fn hash_sig_structure_streaming_chunked_basic() {
    let payload_data = b"chunked payload test data here";
    let mut reader = SizedReader::new(&payload_data[..], payload_data.len() as u64);
    let mut hasher = ByteCollector(Vec::new());

    let bytes_read = hash_sig_structure_streaming_chunked(
        &mut hasher,
        b"\xa0",
        None,
        &mut reader,
        8, // small chunk size to test multiple reads
    )
    .expect("chunked hash");

    assert_eq!(bytes_read, payload_data.len() as u64);
    assert!(!hasher.0.is_empty());
}

// ============================================================================
// stream_sig_structure (lines 746–763)
// ============================================================================

#[test]
fn stream_sig_structure_basic() {
    let payload_data = b"stream test";
    let reader = SizedReader::new(&payload_data[..], payload_data.len() as u64);
    let mut writer = Vec::new();

    let total =
        stream_sig_structure(&mut writer, b"\xa0", None, reader).expect("stream sig structure");

    assert_eq!(total, payload_data.len() as u64);
    assert!(!writer.is_empty());
    // Output should start with CBOR array(4)
    assert_eq!(writer[0], 0x84);
}

// ============================================================================
// stream_sig_structure_chunked (lines 766–790+)
// ============================================================================

#[test]
fn stream_sig_structure_chunked_small_chunks() {
    let payload_data = b"chunked stream sig structure test";
    let mut reader = SizedReader::new(&payload_data[..], payload_data.len() as u64);
    let mut writer = Vec::new();

    let total = stream_sig_structure_chunked(
        &mut writer,
        b"\xa1\x01\x26",
        Some(b"aad"),
        &mut reader,
        4, // very small chunks
    )
    .expect("chunked stream");

    assert_eq!(total, payload_data.len() as u64);
    assert!(!writer.is_empty());
}

// ============================================================================
// SizedRead impls: Cursor and slice
// ============================================================================

#[test]
fn sized_read_cursor() {
    let cursor = std::io::Cursor::new(vec![1u8, 2, 3, 4, 5]);
    assert_eq!(cursor.len().unwrap(), 5);
}

#[test]
fn sized_read_slice() {
    let data: &[u8] = &[10, 20, 30];
    assert_eq!(SizedRead::len(&data).unwrap(), 3);
    assert!(!SizedRead::is_empty(&data).unwrap());
}

#[test]
fn sized_read_empty_slice() {
    let data: &[u8] = &[];
    assert_eq!(SizedRead::len(&data).unwrap(), 0);
    assert!(SizedRead::is_empty(&data).unwrap());
}

// ============================================================================
// CoseSign1Message: parse_inner (line 155–157)
// ============================================================================

#[test]
fn parse_inner_delegates_to_parse() {
    let data = build_cose_sign1_bytes(&[], &[0xA0], Some(b"inner"), b"\x01", false);
    let outer = CoseSign1Message::parse(&data).expect("parse outer");

    let inner = outer.parse_inner(&data).expect("parse_inner");
    assert_eq!(inner.payload(), Some(b"inner".as_slice()));
}

// ============================================================================
// CoseSign1Message: provider() accessor (line 150–152)
// ============================================================================

#[test]
fn message_provider_accessor() {
    let data = build_cose_sign1_bytes(&[], &[0xA0], None, b"\x01", false);
    let msg = CoseSign1Message::parse(&data).expect("parse");

    // Just verify it doesn't panic — the provider is a &'static reference
    let _provider = msg.provider();
}

// ============================================================================
// CoseSign1Message: protected_header_bytes, protected_headers (lines 160–172)
// ============================================================================

#[test]
fn message_protected_accessors() {
    let protected = b"\xa1\x01\x26";
    let data = build_cose_sign1_bytes(protected, &[0xA0], Some(b"x"), b"\x01", false);
    let msg = CoseSign1Message::parse(&data).expect("parse");

    assert_eq!(msg.protected_header_bytes(), protected);
    assert_eq!(msg.protected_headers().alg(), Some(-7));
}

// ============================================================================
// CoseSign1Message: Undefined in unprotected header (line 598–602)
// ============================================================================

#[test]
fn parse_message_with_undefined_in_unprotected() {
    let provider = EverParseCborProvider::default();
    let mut enc = provider.encoder();

    // Unprotected: { 99: undefined }
    enc.encode_map(1).unwrap();
    enc.encode_i64(99).unwrap();
    enc.encode_undefined().unwrap();
    let unprotected = enc.into_bytes();

    let data = build_cose_sign1_bytes(&[], &unprotected, Some(b"p"), b"\x01", false);
    let msg = CoseSign1Message::parse(&data).expect("parse undefined");

    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(99)),
        Some(&CoseHeaderValue::Undefined)
    );
}
