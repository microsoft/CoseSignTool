// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE header map types.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum HeaderKey {
    /// Integer label (the most common COSE header key form).
    Int(i64),
    /// Text label.
    Text(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum HeaderValue {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<HeaderValue>),
    Map(BTreeMap<HeaderKey, HeaderValue>),
    Bool(bool),
    Null,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct CoseHeaderMap {
    /// For protected headers, COSE requires the original CBOR bytes (bstr content)
    /// to be included in Sig_structure. We retain those bytes to avoid re-encoding.
    encoded_map_cbor: Vec<u8>,

    /// Decoded map used for lookups.
    map: BTreeMap<HeaderKey, HeaderValue>,
}

impl CoseHeaderMap {
    /// Construct a protected header map from its original CBOR bytes + decoded map.
    pub fn new_protected(encoded_map_cbor: Vec<u8>, map: BTreeMap<HeaderKey, HeaderValue>) -> Self {
        Self { encoded_map_cbor, map }
    }

    /// Construct an unprotected header map from a decoded map.
    ///
    /// Unprotected headers are not part of Sig_structure, so `encoded_map_cbor` is empty.
    pub fn new_unprotected(map: BTreeMap<HeaderKey, HeaderValue>) -> Self {
        Self {
            encoded_map_cbor: Vec::new(),
            map,
        }
    }

    pub fn clear(&mut self) {
        self.encoded_map_cbor.clear();
        self.map.clear();
    }

    pub fn encoded_map_cbor(&self) -> &[u8] {
        &self.encoded_map_cbor
    }

    pub fn get_i64(&self, key: i64) -> Option<i64> {
        self.map.get(&HeaderKey::Int(key)).and_then(|v| match v {
            HeaderValue::Int(i) => Some(*i),
            _ => None,
        })
    }

    pub fn get_bytes(&self, key: i64) -> Option<&[u8]> {
        self.map.get(&HeaderKey::Int(key)).and_then(|v| match v {
            HeaderValue::Bytes(b) => Some(b.as_slice()),
            _ => None,
        })
    }

    pub fn get_array(&self, key: i64) -> Option<&[HeaderValue]> {
        self.map.get(&HeaderKey::Int(key)).and_then(|v| match v {
            HeaderValue::Array(a) => Some(a.as_slice()),
            _ => None,
        })
    }

    pub fn map(&self) -> &BTreeMap<HeaderKey, HeaderValue> {
        &self.map
    }
}
