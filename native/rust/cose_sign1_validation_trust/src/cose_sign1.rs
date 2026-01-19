// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoseHeaderValue {
    Int(i64),
    Bytes(Arc<[u8]>),
    BytesArray(Vec<Arc<[u8]>>),
    Text(String),
    Other(Arc<[u8]>),
}

impl CoseHeaderValue {
    /// Return the value as an integer, if it is stored as [`CoseHeaderValue::Int`].
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Return the value as a byte string, if it is stored as [`CoseHeaderValue::Bytes`].
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b.as_ref()),
            _ => None,
        }
    }

    /// Return the value as an array of byte strings, if it is stored as [`CoseHeaderValue::BytesArray`].
    pub fn as_bytes_array(&self) -> Option<&[Arc<[u8]>]> {
        match self {
            Self::BytesArray(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// Return the value as a UTF-8 string, if it is stored as [`CoseHeaderValue::Text`].
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// COSE header values are often either a single bstr or an array of bstr.
    pub fn as_bytes_one_or_many(&self) -> Option<Vec<Arc<[u8]>>> {
        match self {
            Self::Bytes(b) => Some(vec![b.clone()]),
            Self::BytesArray(v) => Some(v.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoseHeaderMap {
    entries: BTreeMap<i64, CoseHeaderValue>,
}

impl CoseHeaderMap {
    /// Look up a header value by numeric COSE label.
    pub fn get(&self, label: i64) -> Option<&CoseHeaderValue> {
        self.entries.get(&label)
    }

    /// Convenience accessor for integer-valued header entries.
    pub fn get_i64(&self, label: i64) -> Option<i64> {
        self.get(label).and_then(|v| v.as_i64())
    }

    /// Convenience accessor for `bstr` or `[bstr]`-valued header entries.
    pub fn get_bytes_one_or_many(&self, label: i64) -> Option<Vec<Arc<[u8]>>> {
        self.get(label).and_then(|v| v.as_bytes_one_or_many())
    }

    /// Convenience accessor for text-valued header entries.
    pub fn get_text(&self, label: i64) -> Option<&str> {
        self.get(label).and_then(|v| v.as_text())
    }

    /// Parse a CBOR-encoded map into a typed COSE header map.
    ///
    /// Values are decoded opportunistically:
    /// - `bstr` → [`CoseHeaderValue::Bytes`]
    /// - `tstr` → [`CoseHeaderValue::Text`]
    /// - `[bstr]` → [`CoseHeaderValue::BytesArray`]
    /// - integer → [`CoseHeaderValue::Int`]
    /// - everything else is preserved as raw CBOR in [`CoseHeaderValue::Other`].
    pub fn from_cbor_map_bytes(map_bytes: &[u8]) -> Result<Self, String> {
        let mut d = tinycbor::Decoder(map_bytes);
        let mut map = d
            .map_visitor()
            .map_err(|e| format!("cbor map decode failed: {e}"))?;

        let mut out = BTreeMap::new();

        while let Some(entry) = map.visit::<i64, tinycbor::Any<'_>>() {
            let (key, value_any) =
                entry.map_err(|e| format!("cbor map entry decode failed: {e}"))?;
            let value_bytes = value_any.as_ref();

            if let Some(b) = decode_bytes(value_bytes)? {
                out.insert(key, CoseHeaderValue::Bytes(b));
                continue;
            }

            if let Some(s) = decode_text(value_bytes)? {
                out.insert(key, CoseHeaderValue::Text(s));
                continue;
            }

            if let Some(arr) = decode_bytes_array(value_bytes)? {
                out.insert(key, CoseHeaderValue::BytesArray(arr));
                continue;
            }

            if let Some(i) = decode_cbor_i64_one(value_bytes) {
                out.insert(key, CoseHeaderValue::Int(i));
                continue;
            }

            out.insert(
                key,
                CoseHeaderValue::Other(Arc::from(value_bytes.to_vec().into_boxed_slice())),
            );
        }

        Ok(Self { entries: out })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseSign1ParsedMessage {
    pub protected_header_bytes: Arc<[u8]>,
    pub protected_header: CoseHeaderMap,

    pub unprotected_header_bytes: Arc<[u8]>,
    pub unprotected_header: CoseHeaderMap,

    pub payload: Option<Arc<[u8]>>,
    pub signature: Arc<[u8]>,
}

impl CoseSign1ParsedMessage {
    /// Read the `alg` header value (COSE label `1`) from the protected headers.
    pub fn try_alg(&self) -> Option<i64> {
        // COSE header label 1 = alg
        self.protected_header.get_i64(1)
    }

    /// Build a parsed message view from the four COSE_Sign1 structural parts.
    ///
    /// This method clones bytes into owned buffers so the resulting message is cheap to share and
    /// cache inside the trust engine.
    pub fn from_parts(
        protected_header_bytes: &[u8],
        unprotected_header_bytes: &[u8],
        payload: Option<&[u8]>,
        signature: &[u8],
    ) -> Result<Self, String> {
        let protected_header_bytes: Arc<[u8]> =
            Arc::from(protected_header_bytes.to_vec().into_boxed_slice());
        let unprotected_header_bytes: Arc<[u8]> =
            Arc::from(unprotected_header_bytes.to_vec().into_boxed_slice());

        let protected_header = CoseHeaderMap::from_cbor_map_bytes(protected_header_bytes.as_ref())?;
        let unprotected_header =
            CoseHeaderMap::from_cbor_map_bytes(unprotected_header_bytes.as_ref())?;

        let payload = payload.map(|p| Arc::from(p.to_vec().into_boxed_slice()));
        let signature: Arc<[u8]> = Arc::from(signature.to_vec().into_boxed_slice());

        Ok(Self {
            protected_header_bytes,
            protected_header,
            unprotected_header_bytes,
            unprotected_header,
            payload,
            signature,
        })
    }
}

/// Decode a CBOR byte string into owned bytes.
///
/// Returns `Ok(None)` if the input isn't a `bstr`.
fn decode_bytes(value_bytes: &[u8]) -> Result<Option<Arc<[u8]>>, String> {
    let mut vd = tinycbor::Decoder(value_bytes);
    let Ok(it) = vd.bytes_iter() else {
        return Ok(None);
    };

    let mut out = Vec::new();
    for part in it {
        let part = part.map_err(|e| format!("cbor bytes decode failed: {e}"))?;
        out.extend_from_slice(part);
    }

    Ok(Some(Arc::from(out.into_boxed_slice())))
}

/// Decode a CBOR array of byte strings into owned byte-string elements.
///
/// Returns `Ok(None)` if the input isn't an array of `bstr`.
fn decode_bytes_array(value_bytes: &[u8]) -> Result<Option<Vec<Arc<[u8]>>>, String> {
    let mut vd = tinycbor::Decoder(value_bytes);
    let Ok(mut arr) = vd.array_visitor() else {
        return Ok(None);
    };

    let mut out = Vec::new();
    while let Some(item) = arr.visit::<&[u8]>() {
        let b = match item {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        out.push(Arc::from(b.to_vec().into_boxed_slice()));
    }

    Ok(Some(out))
}

/// Decode a CBOR text string.
///
/// Returns `Ok(None)` if the input isn't a `tstr`.
fn decode_text(value_bytes: &[u8]) -> Result<Option<String>, String> {
    let mut vd = tinycbor::Decoder(value_bytes);
    let Ok(s) = <String as tinycbor::Decode>::decode(&mut vd) else {
        return Ok(None);
    };
    Ok(Some(s))
}

/// Decode a single CBOR integer (major type 0/1) from a fully-consumed buffer.
fn decode_cbor_i64_one(bytes: &[u8]) -> Option<i64> {
    let (n, used) = decode_cbor_i64(bytes)?;
    if used == bytes.len() {
        Some(n)
    } else {
        None
    }
}

/// Decode a CBOR integer (major type 0/1) and return `(value, bytes_consumed)`.
fn decode_cbor_i64(bytes: &[u8]) -> Option<(i64, usize)> {
    let first = *bytes.first()?;
    let major = first >> 5;
    let ai = first & 0x1f;

    let (unsigned, used) = decode_cbor_uint_value(ai, &bytes[1..])?;

    match major {
        0 => i64::try_from(unsigned).ok().map(|v| (v, 1 + used)),
        1 => {
            // Negative integer is encoded as -1 - n.
            let n = i64::try_from(unsigned).ok()?;
            Some((-1 - n, 1 + used))
        }
        _ => None,
    }
}

/// Decode the unsigned-integer argument for a CBOR additional information (AI) value.
fn decode_cbor_uint_value(ai: u8, rest: &[u8]) -> Option<(u64, usize)> {
    match ai {
        0..=23 => Some((ai as u64, 0)),
        24 => Some((u64::from(*rest.first()?), 1)),
        25 => {
            let b = rest.get(0..2)?;
            Some((u16::from_be_bytes([b[0], b[1]]) as u64, 2))
        }
        26 => {
            let b = rest.get(0..4)?;
            Some((u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64, 4))
        }
        27 => {
            let b = rest.get(0..8)?;
            Some((
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
                8,
            ))
        }
        _ => None,
    }
}
