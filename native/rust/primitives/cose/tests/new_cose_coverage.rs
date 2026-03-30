// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage tests for CoseHeaderMap, CoseHeaderValue, CoseHeaderLabel,
//! ContentType, CoseError, and From conversions.

use cose_primitives::error::CoseError;
use cose_primitives::headers::{ContentType, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};
use std::error::Error;

#[test]
fn header_value_as_bytes_one_or_many_non_bytes_array_returns_none() {
    let val = CoseHeaderValue::Array(vec![CoseHeaderValue::Int(1), CoseHeaderValue::Int(2)]);
    assert!(val.as_bytes_one_or_many().is_none());
}

#[test]
fn header_value_as_bytes_one_or_many_empty_array_returns_none() {
    let val = CoseHeaderValue::Array(vec![]);
    assert!(val.as_bytes_one_or_many().is_none());
}

#[test]
fn header_value_as_i64_for_non_int_returns_none() {
    assert!(CoseHeaderValue::Text("hi".into()).as_i64().is_none());
    assert!(CoseHeaderValue::Bool(true).as_i64().is_none());
    assert!(CoseHeaderValue::Null.as_i64().is_none());
}

#[test]
fn header_value_as_str_for_non_text_returns_none() {
    assert!(CoseHeaderValue::Int(42).as_str().is_none());
    assert!(CoseHeaderValue::Bytes(vec![1].into()).as_str().is_none());
}

#[test]
fn header_value_display_complex_variants() {
    assert_eq!(
        CoseHeaderValue::Array(vec![CoseHeaderValue::Int(1)]).to_string(),
        "[1]"
    );
    assert_eq!(
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(1),
            CoseHeaderValue::Text("v".into())
        )])
        .to_string(),
        "{1: \"v\"}"
    );
    assert_eq!(
        CoseHeaderValue::Tagged(18, Box::new(CoseHeaderValue::Null)).to_string(),
        "tag(18, null)"
    );
    assert_eq!(CoseHeaderValue::Null.to_string(), "null");
    assert_eq!(CoseHeaderValue::Undefined.to_string(), "undefined");
    assert_eq!(CoseHeaderValue::Float(3.14).to_string(), "3.14");
    assert_eq!(
        CoseHeaderValue::Raw(vec![0xAB, 0xCD].into()).to_string(),
        "raw(2)"
    );
}

#[test]
fn header_label_display() {
    assert_eq!(CoseHeaderLabel::Int(1).to_string(), "1");
    assert_eq!(CoseHeaderLabel::Text("alg".into()).to_string(), "alg");
}

#[test]
fn content_type_display() {
    assert_eq!(ContentType::Int(42).to_string(), "42");
    assert_eq!(
        ContentType::Text("application/json".into()).to_string(),
        "application/json"
    );
}

#[test]
fn cose_error_display_and_trait() {
    let cbor = CoseError::CborError("decode".into());
    assert_eq!(cbor.to_string(), "CBOR error: decode");
    assert!(cbor.source().is_none());

    let inv = CoseError::InvalidMessage("bad".into());
    assert_eq!(inv.to_string(), "invalid message: bad");
    let _: &dyn Error = &inv;
}

#[test]
fn header_map_insert_get_remove_iter_empty_len() {
    let mut map = CoseHeaderMap::new();
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);

    map.insert(CoseHeaderLabel::Int(99), CoseHeaderValue::Int(7));
    assert!(!map.is_empty());
    assert_eq!(map.len(), 1);
    assert_eq!(
        map.get(&CoseHeaderLabel::Int(99)).unwrap().as_i64(),
        Some(7)
    );

    let count = map.iter().count();
    assert_eq!(count, 1);

    let removed = map.remove(&CoseHeaderLabel::Int(99));
    assert!(removed.is_some());
    assert!(map.is_empty());
}

#[test]
fn header_map_crit_roundtrip() {
    let mut map = CoseHeaderMap::new();
    assert!(map.crit().is_none());

    let labels = vec![
        CoseHeaderLabel::Int(1),
        CoseHeaderLabel::Text("custom".into()),
    ];
    map.set_crit(labels);

    let crit = map.crit().expect("crit should be set");
    assert_eq!(crit.len(), 2);
    assert_eq!(crit[0], CoseHeaderLabel::Int(1));
    assert_eq!(crit[1], CoseHeaderLabel::Text("custom".into()));
}

#[test]
fn from_conversions_u64_slice_bool_string_str() {
    let v: CoseHeaderValue = 42u64.into();
    assert!(matches!(v, CoseHeaderValue::Uint(42)));

    let v: CoseHeaderValue = (&[1u8, 2, 3][..]).into();
    assert_eq!(v.as_bytes(), Some(&[1u8, 2, 3][..]));

    let v: CoseHeaderValue = true.into();
    assert!(matches!(v, CoseHeaderValue::Bool(true)));

    let v: CoseHeaderValue = String::from("hello").into();
    assert_eq!(v.as_str(), Some("hello"));

    let v: CoseHeaderValue = "world".into();
    assert_eq!(v.as_str(), Some("world"));
}
