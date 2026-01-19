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
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b.as_ref()),
            _ => None,
        }
    }

    pub fn as_bytes_array(&self) -> Option<&[Arc<[u8]>]> {
        match self {
            Self::BytesArray(v) => Some(v.as_slice()),
            _ => None,
        }
    }

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
    pub fn get(&self, label: i64) -> Option<&CoseHeaderValue> {
        self.entries.get(&label)
    }

    pub fn get_i64(&self, label: i64) -> Option<i64> {
        self.get(label).and_then(|v| v.as_i64())
    }

    pub fn get_bytes_one_or_many(&self, label: i64) -> Option<Vec<Arc<[u8]>>> {
        self.get(label).and_then(|v| v.as_bytes_one_or_many())
    }

    pub fn get_text(&self, label: i64) -> Option<&str> {
        self.get(label).and_then(|v| v.as_text())
    }

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
    pub fn try_alg(&self) -> Option<i64> {
        // COSE header label 1 = alg
        self.protected_header.get_i64(1)
    }

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

fn decode_text(value_bytes: &[u8]) -> Result<Option<String>, String> {
    let mut vd = tinycbor::Decoder(value_bytes);
    let Ok(s) = <String as tinycbor::Decode>::decode(&mut vd) else {
        return Ok(None);
    };
    Ok(Some(s))
}

fn decode_cbor_i64_one(bytes: &[u8]) -> Option<i64> {
    let (n, used) = decode_cbor_i64(bytes)?;
    if used == bytes.len() {
        Some(n)
    } else {
        None
    }
}

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
