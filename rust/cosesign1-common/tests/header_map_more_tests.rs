fn decode_map(bytes: &[u8]) -> std::collections::BTreeMap<cosesign1_common::HeaderKey, cosesign1_common::HeaderValue> {
    // This uses the same internal parser as production code by going through ParseCoseSign1.
    // For header-map-only tests, we construct a minimal COSE_Sign1 whose protected header bytes are the map bytes.
    let protected = bytes.to_vec();

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let parsed = cosesign1_common::parse_cose_sign1(&msg).expect("parse");
    parsed.protected_headers.map().clone()
}

#[test]
fn header_map_decodes_primitives_and_nested_structures() {
    let mut bytes = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut bytes);

    // {
    //   1: -7,
    //   "kid": h'010203',
    //   4: true,
    //   5: null,
    //   6: [1, "x"],
    //   7: {"a": "b"}
    // }
    enc.map(6).unwrap();
    enc.i64(1).unwrap();
    enc.i64(-7).unwrap();

    enc.str("kid").unwrap();
    enc.bytes(&[1u8, 2, 3]).unwrap();

    enc.i64(4).unwrap();
    enc.bool(true).unwrap();

    enc.i64(5).unwrap();
    enc.null().unwrap();

    enc.i64(6).unwrap();
    enc.array(2).unwrap();
    enc.i64(1).unwrap();
    enc.str("x").unwrap();

    enc.i64(7).unwrap();
    enc.map(1).unwrap();
    enc.str("a").unwrap();
    enc.str("b").unwrap();

    let map = decode_map(&bytes);

    assert_eq!(map.get(&cosesign1_common::HeaderKey::Int(1)), Some(&cosesign1_common::HeaderValue::Int(-7)));

    assert_eq!(
        map.get(&cosesign1_common::HeaderKey::Text("kid".to_string())),
        Some(&cosesign1_common::HeaderValue::Bytes(vec![1, 2, 3]))
    );

    assert_eq!(map.get(&cosesign1_common::HeaderKey::Int(4)), Some(&cosesign1_common::HeaderValue::Bool(true)));
    assert_eq!(map.get(&cosesign1_common::HeaderKey::Int(5)), Some(&cosesign1_common::HeaderValue::Null));

    match map.get(&cosesign1_common::HeaderKey::Int(6)).expect("array") {
        cosesign1_common::HeaderValue::Array(v) => {
            assert_eq!(v.len(), 2);
        }
        other => panic!("unexpected: {other:?}"),
    }

    match map.get(&cosesign1_common::HeaderKey::Int(7)).expect("map") {
        cosesign1_common::HeaderValue::Map(m) => {
            assert_eq!(m.len(), 1);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn header_map_rejects_indefinite_length_map() {
    // 0xbf ... 0xff is an indefinite-length map.
    let bytes = vec![0xbf, 0x01, 0x02, 0xff];

    // Put it in the protected header bstr; parse should fail when decoding the map.
    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("indefinite-length"));
}

#[test]
fn header_map_rejects_indefinite_length_array_value() {
    // { 1: [1] (indef) }
    let bytes = vec![0xa1, 0x01, 0x9f, 0x01, 0xff];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    let err_lc = err.to_lowercase();
    assert!(err_lc.contains("arrayindef") || err_lc.contains("indef"), "err was: {err}");
}

#[test]
fn header_map_rejects_unsupported_key_type() {
    // { h'0102': 1 }
    let bytes = vec![0xa1, 0x42, 0x01, 0x02, 0x01];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("unsupported header key type"));
}

#[test]
fn header_map_rejects_trailing_bytes() {
    let mut bytes = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut bytes);
    enc.map(1).unwrap();
    enc.i64(1).unwrap();
    enc.i64(2).unwrap();

    bytes.push(0x00);

    let mut msg = Vec::new();
    let mut outer = minicbor::Encoder::new(&mut msg);
    outer.array(4).unwrap();
    outer.bytes(&bytes).unwrap();
    outer.map(0).unwrap();
    outer.bytes(b"p").unwrap();
    outer.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("trailing bytes"));
}

#[test]
fn header_map_rejects_unsupported_value_type_float() {
    // { 1: 0.0 (f16) }
    let bytes = vec![0xa1, 0x01, 0xf9, 0x00, 0x00];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("unsupported header value type"), "err was: {err}");
}

#[test]
fn header_map_getters_return_none_on_type_mismatch() {
    // protected { 1: h'0102' }
    let bytes = vec![0xa1, 0x01, 0x42, 0x01, 0x02];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let parsed = cosesign1_common::parse_cose_sign1(&msg).unwrap();
    assert!(parsed.protected_headers.get_i64(1).is_none());
}

#[test]
fn cose_header_map_getters_work() {
    let mut bytes = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut bytes);
    enc.map(3).unwrap();
    enc.i64(1).unwrap();
    enc.i64(-7).unwrap();
    enc.i64(4).unwrap();
    enc.bytes(b"kid-1").unwrap();
    enc.i64(33).unwrap();
    enc.array(1).unwrap();
    enc.bytes(b"cert").unwrap();

    let mut msg = Vec::new();
    let mut outer = minicbor::Encoder::new(&mut msg);
    outer.array(4).unwrap();
    outer.bytes(&bytes).unwrap();
    outer.map(0).unwrap();
    outer.bytes(b"p").unwrap();
    outer.bytes(&[]).unwrap();

    let parsed = cosesign1_common::parse_cose_sign1(&msg).expect("parse");
    assert_eq!(parsed.protected_headers.get_i64(1), Some(-7));
    assert_eq!(parsed.protected_headers.get_bytes(4), Some(b"kid-1".as_slice()));
    assert!(matches!(parsed.protected_headers.get_array(33), Some(_)));
}

#[test]
fn header_map_reports_int_key_decode_errors() {
    // { <u32 key (missing bytes)>: 1 }
    let bytes = vec![0xa1, 0x1a];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("failed to decode int header key"), "err was: {err}");
}

#[test]
fn header_map_reports_text_key_decode_errors() {
    // { "aaaaa" (but truncated): 1 }
    let bytes = vec![0xa1, 0x78, 0x05, b'a'];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("failed to decode text header key"), "err was: {err}");
}

#[test]
fn header_map_reports_bytes_value_decode_errors() {
    // { 1: h'010203' but truncated }
    let bytes = vec![0xa1, 0x01, 0x43, 0x01];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn header_map_reports_failed_to_read_nested_map() {
    // { 1: (nested map with u32 length but truncated header) }
    let bytes = vec![0xa1, 0x01, 0xba];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("failed to read nested map"), "err was: {err}");
}

#[test]
fn header_map_reports_failed_to_read_array() {
    // { 1: (array with u32 length but truncated header) }
    let bytes = vec![0xa1, 0x01, 0x9a];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("failed to read array"), "err was: {err}");
}

#[test]
fn header_map_reports_int_value_decode_errors() {
    // { 1: <u32 value (missing bytes)> }
    let bytes = vec![0xa1, 0x01, 0x1a];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn header_map_reports_text_value_decode_errors() {
    // { 1: "aaaaa" (but truncated) }
    let bytes = vec![0xa1, 0x01, 0x78, 0x05, b'a'];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn header_map_reports_array_element_decode_errors() {
    // { 1: [ h'010203' (but truncated) ] }
    let bytes = vec![0xa1, 0x01, 0x81, 0x43, 0x01];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn header_map_reports_nested_map_key_decode_errors() {
    // { 1: { <u32 key (missing bytes)>: 1 } }
    let bytes = vec![0xa1, 0x01, 0xa1, 0x1a];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&bytes).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = cosesign1_common::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("failed to decode int header key"), "err was: {err}");
}
