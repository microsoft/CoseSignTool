// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE header types and map implementation.
//!
//! Provides types for COSE header labels and values as defined in RFC 9052,
//! along with a map implementation for protected and unprotected headers.
//!
//! These types are generic across all COSE message types (Sign1, Encrypt,
//! MAC, etc.) and represent the RFC 9052 header structure.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

use cbor_primitives::{CborDecoder, CborEncoder, CborProvider, CborType};

use crate::arc_types::{ArcSlice, ArcStr};
use crate::error::CoseError;

/// Maximum nesting depth for CBOR header values (arrays, maps, tags).
///
/// Malicious inputs with deeply nested structures can cause stack overflow.
/// This limit caps recursion during decode to prevent that attack vector.
const MAX_CBOR_DEPTH: usize = 32;

/// A COSE header label (key in a header map).
///
/// Per RFC 9052, header labels can be integers or text strings.
/// Integer labels are preferred for well-known headers.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CoseHeaderLabel {
    /// Integer label (preferred for well-known headers).
    Int(i64),
    /// Text string label (for application-specific headers).
    Text(String),
}

impl From<i64> for CoseHeaderLabel {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}

impl From<&str> for CoseHeaderLabel {
    fn from(v: &str) -> Self {
        Self::Text(v.to_string())
    }
}

impl From<String> for CoseHeaderLabel {
    fn from(v: String) -> Self {
        Self::Text(v)
    }
}

impl std::fmt::Display for CoseHeaderLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoseHeaderLabel::Int(i) => write!(f, "{}", i),
            CoseHeaderLabel::Text(s) => write!(f, "{}", s),
        }
    }
}

/// A COSE header value.
///
/// Supports all CBOR types that can appear in COSE headers.
///
/// `Bytes`, `Text`, and `Raw` variants use [`ArcSlice`] / [`ArcStr`] to
/// enable zero-copy access when the value was decoded from a shared buffer.
/// When constructing values from scratch (builder path), use the [`From`]
/// impls: `ArcSlice::from(vec)`, `ArcStr::from(string)`.
#[derive(Clone, Debug, PartialEq)]
pub enum CoseHeaderValue {
    /// Signed integer.
    Int(i64),
    /// Unsigned integer (for values > i64::MAX).
    Uint(u64),
    /// Byte string (zero-copy when decoded from a shared buffer).
    Bytes(ArcSlice),
    /// Text string (zero-copy when decoded from a shared buffer).
    Text(ArcStr),
    /// Array of values.
    Array(Vec<CoseHeaderValue>),
    /// Map of key-value pairs.
    Map(Vec<(CoseHeaderLabel, CoseHeaderValue)>),
    /// Tagged value.
    Tagged(u64, Box<CoseHeaderValue>),
    /// Boolean value.
    Bool(bool),
    /// Null value.
    Null,
    /// Undefined value.
    Undefined,
    /// Floating point value.
    Float(f64),
    /// Pre-encoded CBOR bytes (passthrough, zero-copy when shared).
    Raw(ArcSlice),
}

impl From<i64> for CoseHeaderValue {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}

impl From<u64> for CoseHeaderValue {
    fn from(v: u64) -> Self {
        Self::Uint(v)
    }
}

impl From<Vec<u8>> for CoseHeaderValue {
    fn from(v: Vec<u8>) -> Self {
        Self::Bytes(ArcSlice::from(v))
    }
}

impl From<&[u8]> for CoseHeaderValue {
    fn from(v: &[u8]) -> Self {
        Self::Bytes(ArcSlice::from(v))
    }
}

impl From<String> for CoseHeaderValue {
    fn from(v: String) -> Self {
        Self::Text(ArcStr::from(v))
    }
}

impl From<&str> for CoseHeaderValue {
    fn from(v: &str) -> Self {
        Self::Text(ArcStr::from(v))
    }
}

impl From<bool> for CoseHeaderValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

impl std::fmt::Display for CoseHeaderValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoseHeaderValue::Int(i) => write!(f, "{}", i),
            CoseHeaderValue::Uint(u) => write!(f, "{}", u),
            CoseHeaderValue::Bytes(b) => write!(f, "bytes({})", b.len()),
            CoseHeaderValue::Text(s) => write!(f, "\"{}\"", s.as_str()),
            CoseHeaderValue::Array(arr) => {
                write!(f, "[")?;
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", item)?;
                }
                write!(f, "]")
            }
            CoseHeaderValue::Map(pairs) => {
                write!(f, "{{")?;
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", k, v)?;
                }
                write!(f, "}}")
            }
            CoseHeaderValue::Tagged(tag, inner) => write!(f, "tag({}, {})", tag, inner),
            CoseHeaderValue::Bool(b) => write!(f, "{}", b),
            CoseHeaderValue::Null => write!(f, "null"),
            CoseHeaderValue::Undefined => write!(f, "undefined"),
            CoseHeaderValue::Float(fl) => write!(f, "{}", fl),
            CoseHeaderValue::Raw(bytes) => write!(f, "raw({})", bytes.len()),
        }
    }
}

impl CoseHeaderValue {
    /// Try to extract a single byte string from this value.
    ///
    /// Returns `Some` if this is a `Bytes` variant, `None` otherwise.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            CoseHeaderValue::Bytes(b) => Some(b.as_bytes()),
            _ => None,
        }
    }

    /// Try to extract bytes from a value that could be a single bstr or array of bstrs.
    ///
    /// This is useful for headers like `x5chain` (label 33) which can be encoded as
    /// either a single certificate (bstr) or an array of certificates (array of bstr).
    ///
    /// Returns `None` if the value is neither a `Bytes` nor an `Array` containing `Bytes`.
    pub fn as_bytes_one_or_many(&self) -> Option<Vec<Vec<u8>>> {
        match self {
            CoseHeaderValue::Bytes(b) => Some(vec![b.as_bytes().to_vec()]),
            CoseHeaderValue::Array(arr) => {
                let mut result = Vec::new();
                for v in arr {
                    if let CoseHeaderValue::Bytes(b) = v {
                        result.push(b.as_bytes().to_vec());
                    }
                }
                if result.is_empty() {
                    None
                } else {
                    Some(result)
                }
            }
            _ => None,
        }
    }

    /// Zero-copy variant of [`as_bytes_one_or_many`](Self::as_bytes_one_or_many).
    ///
    /// Returns borrowed `ArcSlice` values that share the parent message's backing buffer,
    /// avoiding any heap allocation for the byte data itself.
    pub fn as_arc_slices_one_or_many(&self) -> Option<Vec<ArcSlice>> {
        match self {
            CoseHeaderValue::Bytes(b) => Some(vec![b.clone()]),
            CoseHeaderValue::Array(arr) => {
                let mut result = Vec::new();
                for v in arr {
                    if let CoseHeaderValue::Bytes(b) = v {
                        result.push(b.clone());
                    }
                }
                if result.is_empty() {
                    None
                } else {
                    Some(result)
                }
            }
            _ => None,
        }
    }

    /// Try to extract an integer from this value.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            CoseHeaderValue::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to extract a text string from this value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            CoseHeaderValue::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

/// Content type value per RFC 9052.
///
/// Content type can be either an integer (registered media type)
/// or a text string (media type string).
#[derive(Clone, Debug, PartialEq)]
pub enum ContentType {
    /// Integer content type (IANA registered).
    Int(u16),
    /// Text string content type (media type string).
    Text(String),
}

impl std::fmt::Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentType::Int(i) => write!(f, "{}", i),
            ContentType::Text(s) => write!(f, "{}", s),
        }
    }
}

/// COSE header map.
///
/// A map of header labels to values, used for both protected and
/// unprotected headers in COSE messages (RFC 9052 Section 3).
#[derive(Clone, Debug, Default)]
pub struct CoseHeaderMap {
    headers: BTreeMap<CoseHeaderLabel, CoseHeaderValue>,
}

impl CoseHeaderMap {
    // Well-known header labels (RFC 9052 Section 3.1)

    /// Algorithm header label.
    pub const ALG: i64 = 1;
    /// Critical headers label.
    pub const CRIT: i64 = 2;
    /// Content type header label.
    pub const CONTENT_TYPE: i64 = 3;
    /// Key ID header label.
    pub const KID: i64 = 4;
    /// Initialization vector header label.
    pub const IV: i64 = 5;
    /// Partial initialization vector header label.
    pub const PARTIAL_IV: i64 = 6;

    /// Creates a new empty header map.
    pub fn new() -> Self {
        Self {
            headers: BTreeMap::new(),
        }
    }

    /// Gets the algorithm (alg) header value.
    pub fn alg(&self) -> Option<i64> {
        match self.get(&CoseHeaderLabel::Int(Self::ALG)) {
            Some(CoseHeaderValue::Int(v)) => Some(*v),
            _ => None,
        }
    }

    /// Sets the algorithm (alg) header value.
    pub fn set_alg(&mut self, alg: i64) -> &mut Self {
        self.insert(CoseHeaderLabel::Int(Self::ALG), CoseHeaderValue::Int(alg));
        self
    }

    /// Gets the key ID (kid) header value.
    pub fn kid(&self) -> Option<&[u8]> {
        match self.get(&CoseHeaderLabel::Int(Self::KID)) {
            Some(CoseHeaderValue::Bytes(v)) => Some(v.as_bytes()),
            _ => None,
        }
    }

    /// Sets the key ID (kid) header value.
    pub fn set_kid(&mut self, kid: impl Into<Vec<u8>>) -> &mut Self {
        self.insert(
            CoseHeaderLabel::Int(Self::KID),
            CoseHeaderValue::Bytes(ArcSlice::from(kid.into())),
        );
        self
    }

    /// Gets the content type header value.
    pub fn content_type(&self) -> Option<ContentType> {
        match self.get(&CoseHeaderLabel::Int(Self::CONTENT_TYPE)) {
            Some(CoseHeaderValue::Int(v)) => {
                if *v >= 0 && *v <= u16::MAX as i64 {
                    Some(ContentType::Int(*v as u16))
                } else {
                    None
                }
            }
            Some(CoseHeaderValue::Uint(v)) => {
                if *v <= u16::MAX as u64 {
                    Some(ContentType::Int(*v as u16))
                } else {
                    None
                }
            }
            Some(CoseHeaderValue::Text(v)) => Some(ContentType::Text(v.as_str().to_string())),
            _ => None,
        }
    }

    /// Sets the content type header value.
    pub fn set_content_type(&mut self, ct: ContentType) -> &mut Self {
        let value = match ct {
            ContentType::Int(v) => CoseHeaderValue::Int(v as i64),
            ContentType::Text(v) => CoseHeaderValue::Text(ArcStr::from(v)),
        };
        self.insert(CoseHeaderLabel::Int(Self::CONTENT_TYPE), value);
        self
    }

    /// Gets the critical headers value.
    pub fn crit(&self) -> Option<Vec<CoseHeaderLabel>> {
        match self.get(&CoseHeaderLabel::Int(Self::CRIT)) {
            Some(CoseHeaderValue::Array(arr)) => {
                let labels: Vec<CoseHeaderLabel> = arr
                    .iter()
                    .filter_map(|v| match v {
                        CoseHeaderValue::Int(i) => Some(CoseHeaderLabel::Int(*i)),
                        CoseHeaderValue::Text(s) => {
                            Some(CoseHeaderLabel::Text(s.as_str().to_string()))
                        }
                        _ => None,
                    })
                    .collect();
                Some(labels)
            }
            _ => None,
        }
    }

    /// Sets the critical headers value.
    pub fn set_crit(&mut self, labels: Vec<CoseHeaderLabel>) -> &mut Self {
        let values: Vec<CoseHeaderValue> = labels
            .into_iter()
            .map(|l| match l {
                CoseHeaderLabel::Int(i) => CoseHeaderValue::Int(i),
                CoseHeaderLabel::Text(s) => CoseHeaderValue::Text(ArcStr::from(s)),
            })
            .collect();
        self.insert(
            CoseHeaderLabel::Int(Self::CRIT),
            CoseHeaderValue::Array(values),
        );
        self
    }

    /// Gets a header value by label.
    pub fn get(&self, label: &CoseHeaderLabel) -> Option<&CoseHeaderValue> {
        self.headers.get(label)
    }

    /// Gets bytes from a header that may be a single bstr or array of bstrs.
    ///
    /// This is a convenience method for headers like `x5chain` (label 33) which can be
    /// encoded as either a single certificate (bstr) or an array of certificates.
    ///
    /// Returns `None` if the header is not present or is not a `Bytes` or `Array` of `Bytes`.
    pub fn get_bytes_one_or_many(&self, label: &CoseHeaderLabel) -> Option<Vec<Vec<u8>>> {
        self.get(label)?.as_bytes_one_or_many()
    }

    /// Zero-copy variant of [`get_bytes_one_or_many`](Self::get_bytes_one_or_many).
    ///
    /// Returns `ArcSlice` values that share the parent message's backing buffer,
    /// avoiding heap allocation for byte data.
    pub fn get_arc_slices_one_or_many(&self, label: &CoseHeaderLabel) -> Option<Vec<ArcSlice>> {
        self.get(label)?.as_arc_slices_one_or_many()
    }

    /// Inserts a header value.
    pub fn insert(&mut self, label: CoseHeaderLabel, value: CoseHeaderValue) -> &mut Self {
        self.headers.insert(label, value);
        self
    }

    /// Removes a header value.
    pub fn remove(&mut self, label: &CoseHeaderLabel) -> Option<CoseHeaderValue> {
        self.headers.remove(label)
    }

    /// Returns true if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Returns the number of headers in the map.
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Returns an iterator over the header labels and values.
    pub fn iter(&self) -> impl Iterator<Item = (&CoseHeaderLabel, &CoseHeaderValue)> {
        self.headers.iter()
    }

    /// Encodes the header map to CBOR bytes.
    pub fn encode(&self) -> Result<Vec<u8>, CoseError> {
        let provider = crate::provider::cbor_provider();
        let mut encoder = provider.encoder();

        encoder
            .encode_map(self.headers.len())
            .map_err(|e| CoseError::CborError(e.to_string()))?;

        for (label, value) in &self.headers {
            Self::encode_label(&mut encoder, label)?;
            Self::encode_value(&mut encoder, value)?;
        }

        Ok(encoder.into_bytes())
    }

    /// Decodes a header map from CBOR bytes.
    pub fn decode(data: &[u8]) -> Result<Self, CoseError> {
        let provider = crate::provider::cbor_provider();
        if data.is_empty() {
            return Ok(Self::new());
        }

        let mut decoder = provider.decoder(data);
        let len = decoder
            .decode_map_len()
            .map_err(|e| CoseError::CborError(e.to_string()))?;

        let mut headers = BTreeMap::new();

        match len {
            Some(n) => {
                for _ in 0..n {
                    let label = Self::decode_label(&mut decoder)?;
                    let value = Self::decode_value(&mut decoder, 0)?;
                    headers.insert(label, value);
                }
            }
            None => {
                // Indefinite length map
                loop {
                    if decoder
                        .is_break()
                        .map_err(|e| CoseError::CborError(e.to_string()))?
                    {
                        decoder
                            .decode_break()
                            .map_err(|e| CoseError::CborError(e.to_string()))?;
                        break;
                    }
                    let label = Self::decode_label(&mut decoder)?;
                    let value = Self::decode_value(&mut decoder, 0)?;
                    headers.insert(label, value);
                }
            }
        }

        Ok(Self { headers })
    }

    /// Decodes a header map from a shared buffer (zero-copy for byte/text values).
    ///
    /// Byte-string and text-string values will reference the backing `arc` via
    /// [`ArcSlice`] / [`ArcStr`], avoiding copies for those types.
    pub fn decode_shared(arc: &Arc<[u8]>, range: Range<usize>) -> Result<Self, CoseError> {
        let data = &arc[range.clone()];
        if data.is_empty() {
            return Ok(Self::new());
        }

        let provider = crate::provider::cbor_provider();
        let mut decoder = provider.decoder(data);
        let len = decoder
            .decode_map_len()
            .map_err(|e| CoseError::CborError(e.to_string()))?;

        let mut headers = BTreeMap::new();

        match len {
            Some(n) => {
                for _ in 0..n {
                    let label = Self::decode_label(&mut decoder)?;
                    let value = Self::decode_value_shared(&mut decoder, arc, 0)?;
                    headers.insert(label, value);
                }
            }
            None => {
                // Indefinite length map
                loop {
                    if decoder
                        .is_break()
                        .map_err(|e| CoseError::CborError(e.to_string()))?
                    {
                        decoder
                            .decode_break()
                            .map_err(|e| CoseError::CborError(e.to_string()))?;
                        break;
                    }
                    let label = Self::decode_label(&mut decoder)?;
                    let value = Self::decode_value_shared(&mut decoder, arc, 0)?;
                    headers.insert(label, value);
                }
            }
        }

        Ok(Self { headers })
    }

    fn encode_label<E: CborEncoder>(
        encoder: &mut E,
        label: &CoseHeaderLabel,
    ) -> Result<(), CoseError> {
        match label {
            CoseHeaderLabel::Int(v) => encoder
                .encode_i64(*v)
                .map_err(|e| CoseError::CborError(e.to_string())),
            CoseHeaderLabel::Text(v) => encoder
                .encode_tstr(v)
                .map_err(|e| CoseError::CborError(e.to_string())),
        }
    }

    fn encode_value<E: CborEncoder>(
        encoder: &mut E,
        value: &CoseHeaderValue,
    ) -> Result<(), CoseError> {
        match value {
            CoseHeaderValue::Int(v) => encoder
                .encode_i64(*v)
                .map_err(|e| CoseError::CborError(e.to_string())),
            CoseHeaderValue::Uint(v) => encoder
                .encode_u64(*v)
                .map_err(|e| CoseError::CborError(e.to_string())),
            CoseHeaderValue::Bytes(v) => encoder
                .encode_bstr(v.as_bytes())
                .map_err(|e| CoseError::CborError(e.to_string())),
            CoseHeaderValue::Text(v) => encoder
                .encode_tstr(v.as_str())
                .map_err(|e| CoseError::CborError(e.to_string())),
            CoseHeaderValue::Array(arr) => {
                encoder
                    .encode_array(arr.len())
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                for item in arr {
                    Self::encode_value(encoder, item)?;
                }
                Ok(())
            }
            CoseHeaderValue::Map(pairs) => {
                encoder
                    .encode_map(pairs.len())
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                for (k, v) in pairs {
                    Self::encode_label(encoder, k)?;
                    Self::encode_value(encoder, v)?;
                }
                Ok(())
            }
            CoseHeaderValue::Tagged(tag, inner) => {
                encoder
                    .encode_tag(*tag)
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Self::encode_value(encoder, inner)
            }
            CoseHeaderValue::Bool(v) => encoder
                .encode_bool(*v)
                .map_err(|e| CoseError::CborError(e.to_string())),
            CoseHeaderValue::Null => encoder
                .encode_null()
                .map_err(|e| CoseError::CborError(e.to_string())),
            CoseHeaderValue::Undefined => encoder
                .encode_undefined()
                .map_err(|e| CoseError::CborError(e.to_string())),
            CoseHeaderValue::Float(v) => encoder
                .encode_f64(*v)
                .map_err(|e| CoseError::CborError(e.to_string())),
            CoseHeaderValue::Raw(bytes) => encoder
                .encode_raw(bytes.as_bytes())
                .map_err(|e| CoseError::CborError(e.to_string())),
        }
    }

    fn decode_label<'a, D: CborDecoder<'a>>(decoder: &mut D) -> Result<CoseHeaderLabel, CoseError> {
        let typ = decoder
            .peek_type()
            .map_err(|e| CoseError::CborError(e.to_string()))?;

        match typ {
            CborType::UnsignedInt | CborType::NegativeInt => {
                let v = decoder
                    .decode_i64()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderLabel::Int(v))
            }
            CborType::TextString => {
                let v = decoder
                    .decode_tstr()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderLabel::Text(v.to_string()))
            }
            _ => Err(CoseError::InvalidMessage(format!(
                "invalid header label type: {:?}",
                typ
            ))),
        }
    }

    fn decode_value<'a, D: CborDecoder<'a>>(decoder: &mut D, depth: usize) -> Result<CoseHeaderValue, CoseError> {
        if depth >= MAX_CBOR_DEPTH {
            return Err(CoseError::InvalidMessage(
                "CBOR nesting depth exceeds maximum allowed depth".into(),
            ));
        }

        let typ = decoder
            .peek_type()
            .map_err(|e| CoseError::CborError(e.to_string()))?;

        match typ {
            CborType::UnsignedInt => {
                let v = decoder
                    .decode_u64()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                // Store as Int if it fits, otherwise Uint
                if v <= i64::MAX as u64 {
                    Ok(CoseHeaderValue::Int(v as i64))
                } else {
                    Ok(CoseHeaderValue::Uint(v))
                }
            }
            CborType::NegativeInt => {
                let v = decoder
                    .decode_i64()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Int(v))
            }
            CborType::ByteString => {
                let v = decoder
                    .decode_bstr()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Bytes(ArcSlice::from(v)))
            }
            CborType::TextString => {
                let v = decoder
                    .decode_tstr()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Text(ArcStr::from(v)))
            }
            CborType::Array => {
                let len = decoder
                    .decode_array_len()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;

                let mut arr = Vec::new();
                match len {
                    Some(n) => {
                        for _ in 0..n {
                            arr.push(Self::decode_value(decoder, depth + 1)?);
                        }
                    }
                    None => loop {
                        if decoder
                            .is_break()
                            .map_err(|e| CoseError::CborError(e.to_string()))?
                        {
                            decoder
                                .decode_break()
                                .map_err(|e| CoseError::CborError(e.to_string()))?;
                            break;
                        }
                        arr.push(Self::decode_value(decoder, depth + 1)?);
                    },
                }
                Ok(CoseHeaderValue::Array(arr))
            }
            CborType::Map => {
                let len = decoder
                    .decode_map_len()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;

                let mut pairs = Vec::new();
                match len {
                    Some(n) => {
                        for _ in 0..n {
                            let k = Self::decode_label(decoder)?;
                            let v = Self::decode_value(decoder, depth + 1)?;
                            pairs.push((k, v));
                        }
                    }
                    None => loop {
                        if decoder
                            .is_break()
                            .map_err(|e| CoseError::CborError(e.to_string()))?
                        {
                            decoder
                                .decode_break()
                                .map_err(|e| CoseError::CborError(e.to_string()))?;
                            break;
                        }
                        let k = Self::decode_label(decoder)?;
                        let v = Self::decode_value(decoder, depth + 1)?;
                        pairs.push((k, v));
                    },
                }
                Ok(CoseHeaderValue::Map(pairs))
            }
            CborType::Tag => {
                let tag = decoder
                    .decode_tag()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                let inner = Self::decode_value(decoder, depth + 1)?;
                Ok(CoseHeaderValue::Tagged(tag, Box::new(inner)))
            }
            CborType::Bool => {
                let v = decoder
                    .decode_bool()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Bool(v))
            }
            CborType::Null => {
                decoder
                    .decode_null()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Null)
            }
            CborType::Undefined => {
                decoder
                    .decode_undefined()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Undefined)
            }
            CborType::Float16 | CborType::Float32 | CborType::Float64 => {
                let v = decoder
                    .decode_f64()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Float(v))
            }
            _ => Err(CoseError::InvalidMessage(format!(
                "unsupported CBOR type in header: {:?}",
                typ
            ))),
        }
    }

    /// Like [`decode_value`], but byte/text values become zero-copy
    /// [`ArcSlice`] / [`ArcStr`] referencing `arc`.
    fn decode_value_shared<'a, D: CborDecoder<'a>>(
        decoder: &mut D,
        arc: &Arc<[u8]>,
        depth: usize,
    ) -> Result<CoseHeaderValue, CoseError> {
        if depth >= MAX_CBOR_DEPTH {
            return Err(CoseError::InvalidMessage(
                "CBOR nesting depth exceeds maximum allowed depth".into(),
            ));
        }

        let typ = decoder
            .peek_type()
            .map_err(|e| CoseError::CborError(e.to_string()))?;

        match typ {
            CborType::UnsignedInt => {
                let v = decoder
                    .decode_u64()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                if v <= i64::MAX as u64 {
                    Ok(CoseHeaderValue::Int(v as i64))
                } else {
                    Ok(CoseHeaderValue::Uint(v))
                }
            }
            CborType::NegativeInt => {
                let v = decoder
                    .decode_i64()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Int(v))
            }
            CborType::ByteString => {
                let v = decoder
                    .decode_bstr()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                let range = slice_range_in(v, &arc[..]);
                Ok(CoseHeaderValue::Bytes(ArcSlice::new(arc.clone(), range)))
            }
            CborType::TextString => {
                let v = decoder
                    .decode_tstr()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                let range = slice_range_in(v.as_bytes(), &arc[..]);
                Ok(CoseHeaderValue::Text(ArcStr::new(arc.clone(), range)))
            }
            CborType::Array => {
                let len = decoder
                    .decode_array_len()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;

                let mut arr = Vec::new();
                match len {
                    Some(n) => {
                        for _ in 0..n {
                            arr.push(Self::decode_value_shared(decoder, arc, depth + 1)?);
                        }
                    }
                    None => loop {
                        if decoder
                            .is_break()
                            .map_err(|e| CoseError::CborError(e.to_string()))?
                        {
                            decoder
                                .decode_break()
                                .map_err(|e| CoseError::CborError(e.to_string()))?;
                            break;
                        }
                        arr.push(Self::decode_value_shared(decoder, arc, depth + 1)?);
                    },
                }
                Ok(CoseHeaderValue::Array(arr))
            }
            CborType::Map => {
                let len = decoder
                    .decode_map_len()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;

                let mut pairs = Vec::new();
                match len {
                    Some(n) => {
                        for _ in 0..n {
                            let k = Self::decode_label(decoder)?;
                            let v = Self::decode_value_shared(decoder, arc, depth + 1)?;
                            pairs.push((k, v));
                        }
                    }
                    None => loop {
                        if decoder
                            .is_break()
                            .map_err(|e| CoseError::CborError(e.to_string()))?
                        {
                            decoder
                                .decode_break()
                                .map_err(|e| CoseError::CborError(e.to_string()))?;
                            break;
                        }
                        let k = Self::decode_label(decoder)?;
                        let v = Self::decode_value_shared(decoder, arc, depth + 1)?;
                        pairs.push((k, v));
                    },
                }
                Ok(CoseHeaderValue::Map(pairs))
            }
            CborType::Tag => {
                let tag = decoder
                    .decode_tag()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                let inner = Self::decode_value_shared(decoder, arc, depth + 1)?;
                Ok(CoseHeaderValue::Tagged(tag, Box::new(inner)))
            }
            CborType::Bool => {
                let v = decoder
                    .decode_bool()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Bool(v))
            }
            CborType::Null => {
                decoder
                    .decode_null()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Null)
            }
            CborType::Undefined => {
                decoder
                    .decode_undefined()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Undefined)
            }
            CborType::Float16 | CborType::Float32 | CborType::Float64 => {
                let v = decoder
                    .decode_f64()
                    .map_err(|e| CoseError::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Float(v))
            }
            _ => Err(CoseError::InvalidMessage(format!(
                "unsupported CBOR type in header: {:?}",
                typ
            ))),
        }
    }
}

/// Computes the byte range of `slice` within `parent` using pointer arithmetic.
fn slice_range_in(slice: &[u8], parent: &[u8]) -> Range<usize> {
    let start = slice.as_ptr() as usize - parent.as_ptr() as usize;
    let end = start + slice.len();
    debug_assert!(
        end <= parent.len(),
        "slice_range_in: sub-slice is not within parent"
    );
    start..end
}

/// Protected header with its raw CBOR bytes.
///
/// In COSE, the protected header is integrity-protected by the signature.
/// The signature is computed over the raw CBOR bytes of the protected header,
/// not over a re-encoded version. This type keeps the parsed headers together
/// with the original bytes to ensure verification uses the exact bytes that
/// were signed.
#[derive(Clone, Debug)]
pub struct ProtectedHeader {
    /// The parsed header map.
    headers: CoseHeaderMap,
    /// Raw CBOR bytes (needed for Sig_structure during verification).
    raw_bytes: Vec<u8>,
}

impl ProtectedHeader {
    /// Creates a protected header by encoding a header map.
    pub fn encode(headers: CoseHeaderMap) -> Result<Self, CoseError> {
        let raw_bytes = headers.encode()?;
        Ok(Self { headers, raw_bytes })
    }

    /// Decodes a protected header from CBOR bytes.
    pub fn decode(raw_bytes: Vec<u8>) -> Result<Self, CoseError> {
        let headers = if raw_bytes.is_empty() {
            CoseHeaderMap::new()
        } else {
            CoseHeaderMap::decode(&raw_bytes)?
        };
        Ok(Self { headers, raw_bytes })
    }

    /// Returns the raw CBOR bytes (for Sig_structure construction).
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    /// Returns a reference to the parsed header map.
    pub fn headers(&self) -> &CoseHeaderMap {
        &self.headers
    }

    /// Returns a mutable reference to the parsed header map.
    ///
    /// Note: Modifying headers after decoding will cause verification to fail
    /// since the raw bytes won't match the modified headers.
    pub fn headers_mut(&mut self) -> &mut CoseHeaderMap {
        &mut self.headers
    }

    /// Returns the algorithm from the protected header.
    pub fn alg(&self) -> Option<i64> {
        self.headers.alg()
    }

    /// Returns the key ID from the protected header.
    pub fn kid(&self) -> Option<&[u8]> {
        self.headers.kid()
    }

    /// Returns the content type from the protected header.
    pub fn content_type(&self) -> Option<ContentType> {
        self.headers.content_type()
    }

    /// Returns true if the header map is empty.
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Gets a header value by label.
    pub fn get(&self, label: &CoseHeaderLabel) -> Option<&CoseHeaderValue> {
        self.headers.get(label)
    }
}

impl Default for ProtectedHeader {
    fn default() -> Self {
        Self {
            headers: CoseHeaderMap::new(),
            raw_bytes: Vec::new(),
        }
    }
}
