// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Roundtrip tests for CoseHeaderMap encode/decode covering ALL value types:
//! Array, Map, Tagged, Bool, Null, Undefined, Raw, and Display formatting.

use cbor_primitives_everparse::EverParseCborProvider;
use cose_primitives::headers::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};

fn _init() -> EverParseCborProvider {
    EverParseCborProvider
}

#[test]
fn roundtrip_array_value() {
    let _p = _init();
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(100),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(1),
            CoseHeaderValue::Text("hello".to_string()),
            CoseHeaderValue::Bytes(vec![0xAA]),
        ]),
    );
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    match decoded.get(&CoseHeaderLabel::Int(100)).unwrap() {
        CoseHeaderValue::Array(arr) => {
            assert_eq!(arr.len(), 3);
            assert_eq!(arr[0], CoseHeaderValue::Int(1));
            assert_eq!(arr[1], CoseHeaderValue::Text("hello".to_string()));
            assert_eq!(arr[2], CoseHeaderValue::Bytes(vec![0xAA]));
        }
        other => panic!("Expected Array, got {:?}", other),
    }
}

#[test]
fn roundtrip_map_value() {
    let _p = _init();
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(200),
        CoseHeaderValue::Map(vec![
            (CoseHeaderLabel::Int(1), CoseHeaderValue::Text("val".to_string())),
            (CoseHeaderLabel::Text("k".to_string()), CoseHeaderValue::Int(42)),
        ]),
    );
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    match decoded.get(&CoseHeaderLabel::Int(200)).unwrap() {
        CoseHeaderValue::Map(pairs) => {
            assert_eq!(pairs.len(), 2);
        }
        other => panic!("Expected Map, got {:?}", other),
    }
}

#[test]
fn roundtrip_tagged_value() {
    let _p = _init();
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(300),
        CoseHeaderValue::Tagged(18, Box::new(CoseHeaderValue::Bytes(vec![0x01]))),
    );
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    match decoded.get(&CoseHeaderLabel::Int(300)).unwrap() {
        CoseHeaderValue::Tagged(tag, inner) => {
            assert_eq!(*tag, 18);
            assert_eq!(inner.as_ref(), &CoseHeaderValue::Bytes(vec![0x01]));
        }
        other => panic!("Expected Tagged, got {:?}", other),
    }
}

#[test]
fn roundtrip_bool_value() {
    let _p = _init();
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(400), CoseHeaderValue::Bool(true));
    map.insert(CoseHeaderLabel::Int(401), CoseHeaderValue::Bool(false));
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(400)),
        Some(&CoseHeaderValue::Bool(true))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(401)),
        Some(&CoseHeaderValue::Bool(false))
    );
}

#[test]
fn roundtrip_null_value() {
    let _p = _init();
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(500), CoseHeaderValue::Null);
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(500)),
        Some(&CoseHeaderValue::Null)
    );
}

#[test]
fn roundtrip_undefined_value() {
    let _p = _init();
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(600), CoseHeaderValue::Undefined);
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(600)),
        Some(&CoseHeaderValue::Undefined)
    );
}

#[test]
fn roundtrip_text_label() {
    let _p = _init();
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Text("custom-label".to_string()),
        CoseHeaderValue::Int(99),
    );
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Text("custom-label".to_string())),
        Some(&CoseHeaderValue::Int(99))
    );
}

#[test]
fn roundtrip_uint_value() {
    let _p = _init();
    let mut map = CoseHeaderMap::new();
    // Uint > i64::MAX to hit the Uint path
    map.insert(
        CoseHeaderLabel::Int(700),
        CoseHeaderValue::Uint(u64::MAX),
    );
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(700)),
        Some(&CoseHeaderValue::Uint(u64::MAX))
    );
}

// ========== Display formatting ==========

#[test]
fn display_array_value() {
    let v = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Text("x".to_string()),
    ]);
    let s = format!("{}", v);
    assert_eq!(s, "[1, \"x\"]");
}

#[test]
fn display_map_value() {
    let v = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(1),
        CoseHeaderValue::Text("v".to_string()),
    )]);
    let s = format!("{}", v);
    assert!(s.contains("1: \"v\""));
}

#[test]
fn display_tagged_value() {
    let v = CoseHeaderValue::Tagged(18, Box::new(CoseHeaderValue::Int(0)));
    let s = format!("{}", v);
    assert_eq!(s, "tag(18, 0)");
}

#[test]
fn display_bool_null_undefined() {
    assert_eq!(format!("{}", CoseHeaderValue::Bool(true)), "true");
    assert_eq!(format!("{}", CoseHeaderValue::Null), "null");
    assert_eq!(format!("{}", CoseHeaderValue::Undefined), "undefined");
}

#[test]
fn display_float_raw() {
    assert_eq!(format!("{}", CoseHeaderValue::Float(3.14)), "3.14");
    assert_eq!(format!("{}", CoseHeaderValue::Raw(vec![0x01, 0x02])), "raw(2)");
}

// ========== All value types in one header map ==========

#[test]
fn roundtrip_all_value_types() {
    let _p = _init();
    let mut map = CoseHeaderMap::new();

    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    map.insert(CoseHeaderLabel::Int(2), CoseHeaderValue::Uint(u64::MAX));
    map.insert(CoseHeaderLabel::Int(3), CoseHeaderValue::Bytes(vec![0xDE, 0xAD]));
    map.insert(CoseHeaderLabel::Int(4), CoseHeaderValue::Text("hello".to_string()));
    map.insert(
        CoseHeaderLabel::Int(5),
        CoseHeaderValue::Array(vec![CoseHeaderValue::Int(10)]),
    );
    map.insert(
        CoseHeaderLabel::Int(6),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(1),
            CoseHeaderValue::Int(20),
        )]),
    );
    map.insert(
        CoseHeaderLabel::Int(7),
        CoseHeaderValue::Tagged(99, Box::new(CoseHeaderValue::Int(0))),
    );
    map.insert(CoseHeaderLabel::Int(8), CoseHeaderValue::Bool(true));
    map.insert(CoseHeaderLabel::Int(9), CoseHeaderValue::Null);
    map.insert(CoseHeaderLabel::Int(10), CoseHeaderValue::Undefined);

    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(decoded.len(), 10);
}
