// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE header map decoding.
//!
//! COSE header parameters live in two header maps:
//! - Protected headers: encoded as a CBOR bstr containing a CBOR map
//! - Unprotected headers: encoded as an inline CBOR map
//!
//! This module decodes those CBOR maps into a small set of strongly typed values.
//! The implementation is intentionally conservative:
//! - Only supports the CBOR types this project needs.
//! - Rejects indefinite-length arrays/maps.
//! - Rejects unsupported key/value types with clear errors.

use std::collections::BTreeMap;

use minicbor::data::Type;
use minicbor::Decoder;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum HeaderKey {
    /// Integer label (the most common COSE header key form).
    Int(i64),
    /// Text label (used by some ecosystems, e.g., "kid").
    Text(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum HeaderValue {
    /// Integer value.
    Int(i64),
    /// Byte string value.
    Bytes(Vec<u8>),
    /// Text string value.
    Text(String),
    /// Array of nested header values.
    Array(Vec<HeaderValue>),
    /// Nested map.
    Map(BTreeMap<HeaderKey, HeaderValue>),
    /// Boolean value.
    Bool(bool),
    /// Null value.
    Null,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct CoseHeaderMap {
    // For protected headers, COSE requires the original CBOR bytes (bstr) to be
    // included in Sig_structure. We retain those bytes to avoid re-encoding.
    encoded_map_cbor: Vec<u8>,
    // Decoded map used for lookups.
    map: BTreeMap<HeaderKey, HeaderValue>,
}

impl CoseHeaderMap {
    /// Clear both the stored CBOR encoding and the decoded map.
    pub fn clear(&mut self) {
        self.encoded_map_cbor.clear();
        self.map.clear();
    }

    /// Return the original CBOR encoding of this header map.
    ///
    /// For protected headers, this is the bstr content (CBOR-encoded map bytes).
    /// For unprotected headers, this is intentionally empty.
    pub fn encoded_map_cbor(&self) -> &[u8] {
        &self.encoded_map_cbor
    }

    /// Convenience getter: integer value for an integer key.
    /// Returns `None` when the key is missing or the value is a different type.
    pub fn get_i64(&self, key: i64) -> Option<i64> {
        self.map.get(&HeaderKey::Int(key)).and_then(|v| match v {
            HeaderValue::Int(i) => Some(*i),
            _ => None,
        })
    }

    /// Convenience getter: bytes value for an integer key.
    /// Returns `None` when the key is missing or the value is a different type.
    pub fn get_bytes(&self, key: i64) -> Option<&[u8]> {
        self.map.get(&HeaderKey::Int(key)).and_then(|v| match v {
            HeaderValue::Bytes(b) => Some(b.as_slice()),
            _ => None,
        })
    }

    /// Convenience getter: array value for an integer key.
    /// Returns `None` when the key is missing or the value is a different type.
    pub fn get_array(&self, key: i64) -> Option<&[HeaderValue]> {
        self.map.get(&HeaderKey::Int(key)).and_then(|v| match v {
            HeaderValue::Array(a) => Some(a.as_slice()),
            _ => None,
        })
    }

    /// Access the decoded map (primarily for diagnostics and testing).
    pub fn map(&self) -> &BTreeMap<HeaderKey, HeaderValue> {
        &self.map
    }

    pub(crate) fn set_encoded_map_cbor(&mut self, bytes: Vec<u8>) {
        self.encoded_map_cbor = bytes;
    }

    pub(crate) fn set_map(&mut self, map: BTreeMap<HeaderKey, HeaderValue>) {
        self.map = map;
    }
}

/// Decode a header map from the CBOR bytes contained within a protected header bstr.
///
/// This expects the provided `bytes` to be the CBOR encoding of a map.
pub(crate) fn decode_header_map_from_cbor(bytes: &[u8]) -> Result<BTreeMap<HeaderKey, HeaderValue>, String> {
    let mut dec = Decoder::new(bytes);

    // Empty bstr means empty map for protected headers.
    if bytes.is_empty() {
        return Ok(BTreeMap::new());
    }

    let len = dec
        .map()
        .map_err(|e| format!("failed to read map: {e}"))?
        .ok_or_else(|| "indefinite-length maps are not supported".to_string())?;

    let mut map = BTreeMap::new();
    for _ in 0..len {
        let key = decode_header_key(&mut dec)?;
        let value = decode_header_value(&mut dec)?;
        map.insert(key, value);
    }

    if dec.position() != bytes.len() {
        return Err("trailing bytes after header map".to_string());
    }

    Ok(map)
}

/// Decode a header map directly from a CBOR decoder.
///
/// This is used for unprotected headers, which appear inline in COSE_Sign1.
pub(crate) fn decode_header_map_from_decoder(dec: &mut Decoder<'_>) -> Result<BTreeMap<HeaderKey, HeaderValue>, String> {
    let len = dec
        .map()
        .map_err(|e| format!("failed to read map: {e}"))?
        .ok_or_else(|| "indefinite-length maps are not supported".to_string())?;

    let mut map = BTreeMap::new();
    for _ in 0..len {
        let key = decode_header_key(dec)?;
        let value = decode_header_value(dec)?;
        map.insert(key, value);
    }

    Ok(map)
}

/// Decode a COSE header map key.
///
/// COSE keys are most often small integers, but may also be text.
fn decode_header_key(dec: &mut Decoder<'_>) -> Result<HeaderKey, String> {
    match dec.datatype().map_err(|e| e.to_string())? {
        Type::I8
        | Type::I16
        | Type::I32
        | Type::I64
        | Type::Int
        | Type::U8
        | Type::U16
        | Type::U32
        | Type::U64 => {
            let i = dec
                .i64()
                .map_err(|e| format!("failed to decode int header key: {e}"))?;
            Ok(HeaderKey::Int(i))
        }
        Type::String => {
            let s = dec
                .str()
                .map_err(|e| format!("failed to decode text header key: {e}"))?;
            Ok(HeaderKey::Text(s.to_string()))
        }
        other => Err(format!("unsupported header key type: {other:?}")),
    }
}

/// Decode a COSE header map value.
///
/// Only a subset of CBOR types are supported.
fn decode_header_value(dec: &mut Decoder<'_>) -> Result<HeaderValue, String> {
    match dec.datatype().map_err(|e| e.to_string())? {
        Type::Null => {
            dec.null().map_err(|e| e.to_string())?;
            Ok(HeaderValue::Null)
        }
        Type::Bool => {
            let b = dec.bool().map_err(|e| e.to_string())?;
            Ok(HeaderValue::Bool(b))
        }
        Type::Bytes => {
            let b = dec.bytes().map_err(|e| e.to_string())?;
            Ok(HeaderValue::Bytes(b.to_vec()))
        }
        Type::String => {
            let s = dec.str().map_err(|e| e.to_string())?;
            Ok(HeaderValue::Text(s.to_string()))
        }
        Type::I8
        | Type::I16
        | Type::I32
        | Type::I64
        | Type::Int
        | Type::U8
        | Type::U16
        | Type::U32
        | Type::U64 => {
            let i = dec.i64().map_err(|e| e.to_string())?;
            Ok(HeaderValue::Int(i))
        }
        Type::Array => {
            let len = dec
                .array()
                .map_err(|e| format!("failed to read array: {e}"))?
                .ok_or_else(|| "indefinite-length arrays are not supported".to_string())?;
            let mut out = Vec::with_capacity(len as usize);
            for _ in 0..len {
                out.push(decode_header_value(dec)?);
            }
            Ok(HeaderValue::Array(out))
        }
        Type::Map => {
            let len = dec
                .map()
                .map_err(|e| format!("failed to read nested map: {e}"))?
                .ok_or_else(|| "indefinite-length maps are not supported".to_string())?;
            let mut out = BTreeMap::new();
            for _ in 0..len {
                let k = decode_header_key(dec)?;
                let v = decode_header_value(dec)?;
                out.insert(k, v);
            }
            Ok(HeaderValue::Map(out))
        }
        other => Err(format!("unsupported header value type: {other:?}")),
    }
}
