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

use cosesign1_abstractions::{HeaderKey, HeaderValue};
use minicbor::data::Type;
use minicbor::Decoder;

/// Decode a header map from the CBOR bytes contained within a protected header bstr.
///
/// This expects the provided `bytes` to be the CBOR encoding of a map.
pub(crate) fn decode_header_map_from_cbor(
    bytes: &[u8],
) -> Result<BTreeMap<HeaderKey, HeaderValue>, String> {
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
pub(crate) fn decode_header_map_from_decoder(
    dec: &mut Decoder<'_>,
) -> Result<BTreeMap<HeaderKey, HeaderValue>, String> {
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
