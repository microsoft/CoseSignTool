// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::cose_sign1::{CoseHeaderMap, CoseHeaderValue};
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

fn encode_value<T: Encode>(value: &T) -> Vec<u8> {
    let mut buf = vec![0u8; 128];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    value.encode(&mut enc).unwrap();
    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

#[test]
fn header_value_accessors_work() {
    let v = CoseHeaderValue::Int(-7);
    assert_eq!(Some(-7), v.as_i64());
    assert!(v.as_bytes().is_none());

    let v = CoseHeaderValue::Text("t".to_string());
    assert_eq!(Some("t"), v.as_text());

    let b: Arc<[u8]> = Arc::from(b"x".to_vec().into_boxed_slice());
    let v = CoseHeaderValue::Bytes(b.clone());
    assert_eq!(Some(b"x".as_slice()), v.as_bytes());
    assert_eq!(Some(vec![b]), v.as_bytes_one_or_many());

    let a: Arc<[u8]> = Arc::from(b"a".to_vec().into_boxed_slice());
    let b: Arc<[u8]> = Arc::from(b"b".to_vec().into_boxed_slice());
    let v = CoseHeaderValue::BytesArray(vec![a.clone(), b.clone()]);
    assert_eq!(Some(vec![a, b]), v.as_bytes_one_or_many());
}

#[test]
fn header_map_decodes_bytes_text_bytes_array_int_and_other() {
    // Label 5 => other (use CBOR true)
    let other = encode_value(&true);

    let mut buf = vec![0u8; 256];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(5).unwrap();

    // Label 1 => int (alg)
    (1i64).encode(&mut enc).unwrap();
    (-1i64).encode(&mut enc).unwrap();

    // Label 2 => bstr
    (2i64).encode(&mut enc).unwrap();
    b"abc".as_slice().encode(&mut enc).unwrap();

    // Label 3 => array of bstr
    (3i64).encode(&mut enc).unwrap();
    enc.array(2).unwrap();
    b"a".as_slice().encode(&mut enc).unwrap();
    b"b".as_slice().encode(&mut enc).unwrap();

    // Label 4 => text
    (4i64).encode(&mut enc).unwrap();
    "hello".to_string().encode(&mut enc).unwrap();

    // Label 5 => other (true)
    (5i64).encode(&mut enc).unwrap();
    true.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    let map_bytes = buf;

    let m = CoseHeaderMap::from_cbor_map_bytes(&map_bytes).unwrap();

    assert_eq!(Some(-1), m.get_i64(1));
    assert_eq!(Some("hello"), m.get_text(4));

    let b = m.get_bytes_one_or_many(2).unwrap();
    assert_eq!(1, b.len());
    assert_eq!(b"abc", b[0].as_ref());

    let arr = m.get_bytes_one_or_many(3).unwrap();
    assert_eq!(2, arr.len());
    assert_eq!(b"a", arr[0].as_ref());
    assert_eq!(b"b", arr[1].as_ref());

    match m.get(5).unwrap() {
        CoseHeaderValue::Other(raw) => {
            // Ensure we preserved the raw CBOR encoding.
            assert_eq!(other.as_slice(), raw.as_ref());
        }
        _ => panic!("expected Other"),
    }
}

#[test]
fn header_map_decodes_integers_with_all_cbor_widths_and_overflow_falls_back_to_other() {
    let mut buf = vec![0u8; 512];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    // 9 entries.
    enc.map(9).unwrap();

    (10i64).encode(&mut enc).unwrap();
    (24u64).encode(&mut enc).unwrap();

    (11i64).encode(&mut enc).unwrap();
    (256u64).encode(&mut enc).unwrap();

    (12i64).encode(&mut enc).unwrap();
    (65_536u64).encode(&mut enc).unwrap();

    (13i64).encode(&mut enc).unwrap();
    (4_294_967_296u64).encode(&mut enc).unwrap();

    (14i64).encode(&mut enc).unwrap();
    (-25i64).encode(&mut enc).unwrap();

    (15i64).encode(&mut enc).unwrap();
    (-257i64).encode(&mut enc).unwrap();

    (16i64).encode(&mut enc).unwrap();
    (-65_537i64).encode(&mut enc).unwrap();

    (17i64).encode(&mut enc).unwrap();
    (-4_294_967_297i64).encode(&mut enc).unwrap();

    // Unsigned integer just above i64::MAX should not decode as i64 and should be preserved as Other.
    (18i64).encode(&mut enc).unwrap();
    ((i64::MAX as u64) + 1).encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    let map_bytes = buf;

    let m = CoseHeaderMap::from_cbor_map_bytes(&map_bytes).unwrap();

    assert_eq!(Some(24), m.get_i64(10));
    assert_eq!(Some(256), m.get_i64(11));
    assert_eq!(Some(65_536), m.get_i64(12));
    assert_eq!(Some(4_294_967_296), m.get_i64(13));

    assert_eq!(Some(-25), m.get_i64(14));
    assert_eq!(Some(-257), m.get_i64(15));
    assert_eq!(Some(-65_537), m.get_i64(16));
    assert_eq!(Some(-4_294_967_297), m.get_i64(17));

    assert!(m.get_i64(18).is_none());
    assert!(matches!(m.get(18).unwrap(), CoseHeaderValue::Other(_)));
}
