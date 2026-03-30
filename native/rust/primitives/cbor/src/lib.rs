// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! # CBOR Primitives
//!
//! A zero-dependency trait crate that defines abstractions for CBOR encoding/decoding,
//! allowing pluggable implementations per RFC 8949.
//!
//! This crate provides:
//! - [`CborType`] - Enum for CBOR type inspection
//! - [`CborSimple`] - Enum for CBOR simple values
//! - [`CborEncoder`] - Trait for CBOR encoding operations
//! - [`CborDecoder`] - Trait for CBOR decoding operations
//! - [`CborStreamDecoder`] - Trait for streaming CBOR decoding from `Read + Seek` sources
//! - [`RawCbor`] - Newtype for raw, unparsed CBOR data
//! - [`CborProvider`] - Factory trait for creating encoders/decoders
//! - [`CborError`] - Common error type for CBOR operations

/// CBOR data types as defined in RFC 8949.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CborType {
    /// Major type 0: An unsigned integer in the range 0..2^64-1 inclusive.
    UnsignedInt,
    /// Major type 1: A negative integer in the range -2^64..-1 inclusive.
    NegativeInt,
    /// Major type 2: A byte string.
    ByteString,
    /// Major type 3: A text string encoded as UTF-8.
    TextString,
    /// Major type 4: An array of data items.
    Array,
    /// Major type 5: A map of pairs of data items.
    Map,
    /// Major type 6: A tagged data item.
    Tag,
    /// Major type 7: Simple value (other than bool/null/undefined/float).
    Simple,
    /// Major type 7: IEEE 754 half-precision float (16-bit).
    Float16,
    /// Major type 7: IEEE 754 single-precision float (32-bit).
    Float32,
    /// Major type 7: IEEE 754 double-precision float (64-bit).
    Float64,
    /// Major type 7: Boolean value (true or false).
    Bool,
    /// Major type 7: Null value.
    Null,
    /// Major type 7: Undefined value.
    Undefined,
    /// Major type 7: Break stop code for indefinite-length items.
    Break,
}

/// CBOR simple values as defined in RFC 8949.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CborSimple {
    /// Simple value 20: false
    False,
    /// Simple value 21: true
    True,
    /// Simple value 22: null
    Null,
    /// Simple value 23: undefined
    Undefined,
    /// Unassigned simple value (0-19, 24-31, or 32-255)
    Unassigned(u8),
}

/// A slice of raw, unparsed CBOR data.
///
/// This type wraps borrowed bytes that are known to contain valid CBOR.
/// It provides methods to re-parse the data when needed.
///
/// # Examples
///
/// ```
/// # use cbor_primitives::RawCbor;
/// let cbor_bytes = &[0x18, 0x2A]; // CBOR encoding of integer 42
/// let raw = RawCbor::new(cbor_bytes);
/// assert_eq!(raw.as_bytes(), cbor_bytes);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawCbor<'a>(pub &'a [u8]);

impl<'a> RawCbor<'a> {
    /// Creates a new RawCbor from bytes.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    // ========================================================================
    // Provider-independent scalar decoding
    // ========================================================================
    //
    // These methods decode simple CBOR scalars (integers, booleans, strings)
    // directly from bytes without requiring a CborProvider. For complex types
    // (arrays, maps, tags), use a CborProvider-based decoder.

    /// Try to decode as a signed integer (i64).
    ///
    /// Handles both CBOR major type 0 (unsigned) and major type 1 (negative).
    /// Returns `None` if not an integer or if the value is out of i64 range.
    pub fn try_as_i64(&self) -> Option<i64> {
        let (&initial, rest) = self.0.split_first()?;
        let major = initial >> 5;
        match major {
            // Major type 0: unsigned integer
            0 => {
                let (val, _) = Self::decode_uint_arg(initial, rest)?;
                i64::try_from(val).ok()
            }
            // Major type 1: negative integer (-1 - val)
            1 => {
                let (val, _) = Self::decode_uint_arg(initial, rest)?;
                if val <= i64::MAX as u64 {
                    Some(-1 - val as i64)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Try to decode as an unsigned integer (u64).
    ///
    /// Only handles CBOR major type 0.
    /// Returns `None` if not an unsigned integer.
    pub fn try_as_u64(&self) -> Option<u64> {
        let (&initial, rest) = self.0.split_first()?;
        let major = initial >> 5;
        if major != 0 {
            return None;
        }
        let (val, _) = Self::decode_uint_arg(initial, rest)?;
        Some(val)
    }

    /// Try to decode as a boolean.
    ///
    /// Returns `None` if not a CBOR boolean (0xF4 or 0xF5).
    pub fn try_as_bool(&self) -> Option<bool> {
        match self.0 {
            [0xF4] => Some(false),
            [0xF5] => Some(true),
            _ => None,
        }
    }

    /// Try to decode as a text string (UTF-8).
    ///
    /// Returns `None` if not a CBOR text string or if not valid UTF-8.
    pub fn try_as_str(&self) -> Option<&'a str> {
        let (&initial, rest) = self.0.split_first()?;
        let major = initial >> 5;
        if major != 3 {
            return None;
        }
        let (len, consumed) = Self::decode_uint_arg(initial, rest)?;
        let len = usize::try_from(len).ok()?;
        let text_bytes = rest.get(consumed..consumed + len)?;
        std::str::from_utf8(text_bytes).ok()
    }

    /// Try to decode as bytes (byte string).
    ///
    /// Returns `None` if not a CBOR byte string.
    pub fn try_as_bstr(&self) -> Option<&'a [u8]> {
        let (&initial, rest) = self.0.split_first()?;
        let major = initial >> 5;
        if major != 2 {
            return None;
        }
        let (len, consumed) = Self::decode_uint_arg(initial, rest)?;
        let len = usize::try_from(len).ok()?;
        rest.get(consumed..consumed + len)
    }

    /// Returns the CBOR major type of this value.
    ///
    /// Returns `None` if the bytes are empty.
    pub fn major_type(&self) -> Option<u8> {
        self.0.first().map(|b| b >> 5)
    }

    /// Decode the unsigned integer argument from initial byte and remaining bytes.
    fn decode_uint_arg(initial: u8, rest: &[u8]) -> Option<(u64, usize)> {
        let additional = initial & 0x1F;
        match additional {
            0..=23 => Some((additional as u64, 0)),
            24 => rest.first().map(|&b| (b as u64, 1)),
            25 if rest.len() >= 2 => Some((u16::from_be_bytes([rest[0], rest[1]]) as u64, 2)),
            26 if rest.len() >= 4 => Some((
                u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as u64,
                4,
            )),
            27 if rest.len() >= 8 => {
                let val = u64::from_be_bytes([
                    rest[0], rest[1], rest[2], rest[3], rest[4], rest[5], rest[6], rest[7],
                ]);
                Some((val, 8))
            }
            _ => None,
        }
    }
}

impl AsRef<[u8]> for RawCbor<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

/// Trait for CBOR encoding operations per RFC 8949.
///
/// Implementors of this trait provide the ability to encode all CBOR data types
/// into a byte buffer.
pub trait CborEncoder {
    /// The error type returned by encoding operations.
    type Error: std::error::Error + Send + Sync + 'static;

    // Major type 0: Unsigned integers

    /// Encodes an unsigned 8-bit integer.
    fn encode_u8(&mut self, value: u8) -> Result<(), Self::Error>;

    /// Encodes an unsigned 16-bit integer.
    fn encode_u16(&mut self, value: u16) -> Result<(), Self::Error>;

    /// Encodes an unsigned 32-bit integer.
    fn encode_u32(&mut self, value: u32) -> Result<(), Self::Error>;

    /// Encodes an unsigned 64-bit integer.
    fn encode_u64(&mut self, value: u64) -> Result<(), Self::Error>;

    // Major type 1: Negative integers

    /// Encodes a signed 8-bit integer.
    fn encode_i8(&mut self, value: i8) -> Result<(), Self::Error>;

    /// Encodes a signed 16-bit integer.
    fn encode_i16(&mut self, value: i16) -> Result<(), Self::Error>;

    /// Encodes a signed 32-bit integer.
    fn encode_i32(&mut self, value: i32) -> Result<(), Self::Error>;

    /// Encodes a signed 64-bit integer.
    fn encode_i64(&mut self, value: i64) -> Result<(), Self::Error>;

    /// Encodes a signed 128-bit integer.
    fn encode_i128(&mut self, value: i128) -> Result<(), Self::Error>;

    // Major type 2: Byte strings

    /// Encodes a byte string (definite length).
    fn encode_bstr(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Encodes only the byte string header with the given length.
    fn encode_bstr_header(&mut self, len: u64) -> Result<(), Self::Error>;

    /// Begins an indefinite-length byte string.
    fn encode_bstr_indefinite_begin(&mut self) -> Result<(), Self::Error>;

    // Major type 3: Text strings

    /// Encodes a text string (definite length).
    fn encode_tstr(&mut self, data: &str) -> Result<(), Self::Error>;

    /// Encodes only the text string header with the given length.
    fn encode_tstr_header(&mut self, len: u64) -> Result<(), Self::Error>;

    /// Begins an indefinite-length text string.
    fn encode_tstr_indefinite_begin(&mut self) -> Result<(), Self::Error>;

    // Major type 4: Arrays

    /// Encodes an array header with the given length.
    fn encode_array(&mut self, len: usize) -> Result<(), Self::Error>;

    /// Begins an indefinite-length array.
    fn encode_array_indefinite_begin(&mut self) -> Result<(), Self::Error>;

    // Major type 5: Maps

    /// Encodes a map header with the given number of key-value pairs.
    fn encode_map(&mut self, len: usize) -> Result<(), Self::Error>;

    /// Begins an indefinite-length map.
    fn encode_map_indefinite_begin(&mut self) -> Result<(), Self::Error>;

    // Major type 6: Tags

    /// Encodes a tag value.
    fn encode_tag(&mut self, tag: u64) -> Result<(), Self::Error>;

    // Major type 7: Simple/Float

    /// Encodes a boolean value.
    fn encode_bool(&mut self, value: bool) -> Result<(), Self::Error>;

    /// Encodes a null value.
    fn encode_null(&mut self) -> Result<(), Self::Error>;

    /// Encodes an undefined value.
    fn encode_undefined(&mut self) -> Result<(), Self::Error>;

    /// Encodes a simple value.
    fn encode_simple(&mut self, value: CborSimple) -> Result<(), Self::Error>;

    /// Encodes a half-precision (16-bit) floating point value.
    fn encode_f16(&mut self, value: f32) -> Result<(), Self::Error>;

    /// Encodes a single-precision (32-bit) floating point value.
    fn encode_f32(&mut self, value: f32) -> Result<(), Self::Error>;

    /// Encodes a double-precision (64-bit) floating point value.
    fn encode_f64(&mut self, value: f64) -> Result<(), Self::Error>;

    /// Encodes a break stop code for indefinite-length items.
    fn encode_break(&mut self) -> Result<(), Self::Error>;

    // Raw bytes (pre-encoded)

    /// Writes raw pre-encoded CBOR bytes directly to the output.
    fn encode_raw(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;

    // Output

    /// Consumes the encoder and returns the encoded bytes.
    fn into_bytes(self) -> Vec<u8>;

    /// Returns a reference to the currently encoded bytes.
    fn as_bytes(&self) -> &[u8];
}

/// Trait for CBOR decoding operations per RFC 8949.
///
/// Implementors of this trait provide the ability to decode all CBOR data types
/// from a byte buffer.
pub trait CborDecoder<'a> {
    /// The error type returned by decoding operations.
    type Error: std::error::Error + Send + Sync + 'static;

    // Type inspection

    /// Peeks at the next CBOR type without consuming it.
    fn peek_type(&mut self) -> Result<CborType, Self::Error>;

    /// Checks if the next item is a break stop code.
    fn is_break(&mut self) -> Result<bool, Self::Error>;

    /// Checks if the next item is a null value.
    fn is_null(&mut self) -> Result<bool, Self::Error>;

    /// Checks if the next item is an undefined value.
    fn is_undefined(&mut self) -> Result<bool, Self::Error>;

    // Major type 0/1: Integers

    /// Decodes an unsigned 8-bit integer.
    fn decode_u8(&mut self) -> Result<u8, Self::Error>;

    /// Decodes an unsigned 16-bit integer.
    fn decode_u16(&mut self) -> Result<u16, Self::Error>;

    /// Decodes an unsigned 32-bit integer.
    fn decode_u32(&mut self) -> Result<u32, Self::Error>;

    /// Decodes an unsigned 64-bit integer.
    fn decode_u64(&mut self) -> Result<u64, Self::Error>;

    /// Decodes a signed 8-bit integer.
    fn decode_i8(&mut self) -> Result<i8, Self::Error>;

    /// Decodes a signed 16-bit integer.
    fn decode_i16(&mut self) -> Result<i16, Self::Error>;

    /// Decodes a signed 32-bit integer.
    fn decode_i32(&mut self) -> Result<i32, Self::Error>;

    /// Decodes a signed 64-bit integer.
    fn decode_i64(&mut self) -> Result<i64, Self::Error>;

    /// Decodes a signed 128-bit integer.
    fn decode_i128(&mut self) -> Result<i128, Self::Error>;

    // Major type 2: Byte strings

    /// Decodes a byte string, returning a reference to the underlying data.
    fn decode_bstr(&mut self) -> Result<&'a [u8], Self::Error>;

    /// Decodes a byte string and returns an owned copy.
    fn decode_bstr_owned(&mut self) -> Result<Vec<u8>, Self::Error> {
        self.decode_bstr().map(|b| b.to_vec())
    }

    /// Decodes a byte string header, returning the length (None for indefinite).
    fn decode_bstr_header(&mut self) -> Result<Option<u64>, Self::Error>;

    // Major type 3: Text strings

    /// Decodes a text string, returning a reference to the underlying data.
    fn decode_tstr(&mut self) -> Result<&'a str, Self::Error>;

    /// Decodes a text string and returns an owned copy.
    fn decode_tstr_owned(&mut self) -> Result<String, Self::Error> {
        self.decode_tstr().map(|s| s.to_string())
    }

    /// Decodes a text string header, returning the length (None for indefinite).
    fn decode_tstr_header(&mut self) -> Result<Option<u64>, Self::Error>;

    // Major type 4: Arrays

    /// Decodes an array header, returning the length (None for indefinite).
    fn decode_array_len(&mut self) -> Result<Option<usize>, Self::Error>;

    // Major type 5: Maps

    /// Decodes a map header, returning the number of pairs (None for indefinite).
    fn decode_map_len(&mut self) -> Result<Option<usize>, Self::Error>;

    // Major type 6: Tags

    /// Decodes a tag value.
    fn decode_tag(&mut self) -> Result<u64, Self::Error>;

    // Major type 7: Simple/Float

    /// Decodes a boolean value.
    fn decode_bool(&mut self) -> Result<bool, Self::Error>;

    /// Decodes and consumes a null value.
    fn decode_null(&mut self) -> Result<(), Self::Error>;

    /// Decodes and consumes an undefined value.
    fn decode_undefined(&mut self) -> Result<(), Self::Error>;

    /// Decodes a simple value.
    fn decode_simple(&mut self) -> Result<CborSimple, Self::Error>;

    /// Decodes a half-precision (16-bit) floating point value.
    fn decode_f16(&mut self) -> Result<f32, Self::Error>;

    /// Decodes a single-precision (32-bit) floating point value.
    fn decode_f32(&mut self) -> Result<f32, Self::Error>;

    /// Decodes a double-precision (64-bit) floating point value.
    fn decode_f64(&mut self) -> Result<f64, Self::Error>;

    /// Decodes and consumes a break stop code.
    fn decode_break(&mut self) -> Result<(), Self::Error>;

    // Navigation

    /// Skips the next CBOR item without decoding it.
    fn skip(&mut self) -> Result<(), Self::Error>;

    /// Returns a reference to the remaining undecoded bytes.
    fn remaining(&self) -> &'a [u8];

    /// Returns the current position in the input buffer.
    fn position(&self) -> usize;

    // Raw CBOR capture

    /// Decodes the next CBOR item and returns its raw bytes without further parsing.
    ///
    /// This is useful for capturing CBOR data that will be re-parsed later or
    /// passed through unchanged. This method provides an abstraction for capturing
    /// CBOR without parsing, replacing direct use of implementation-specific types
    /// like implementation-specific raw CBOR types.
    ///
    /// The returned slice contains the complete CBOR encoding of the next item,
    /// including any nested structures.
    fn decode_raw(&mut self) -> Result<&'a [u8], Self::Error>;
}

/// Factory trait for creating CBOR encoders and decoders.
///
/// This trait allows for pluggable CBOR implementations. Implementors provide
/// concrete encoder and decoder types that can be instantiated through this
/// factory interface.
pub trait CborProvider: Send + Sync + Clone + 'static {
    /// The encoder type produced by this provider.
    type Encoder: CborEncoder;

    /// The decoder type produced by this provider.
    type Decoder<'a>: CborDecoder<'a>;

    /// The error type used by encoders/decoders from this provider.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Creates a new encoder with default capacity.
    fn encoder(&self) -> Self::Encoder;

    /// Creates a new encoder with the specified initial capacity.
    fn encoder_with_capacity(&self, capacity: usize) -> Self::Encoder;

    /// Creates a new decoder for the given input data.
    fn decoder<'a>(&self, data: &'a [u8]) -> Self::Decoder<'a>;
}

/// Common error type for CBOR operations.
///
/// This error type can be used by implementations or converted to/from
/// implementation-specific error types.
#[derive(Debug, Clone)]
pub enum CborError {
    /// Expected one CBOR type but found another.
    UnexpectedType {
        /// The expected CBOR type.
        expected: CborType,
        /// The actual CBOR type found.
        found: CborType,
    },
    /// Unexpected end of input data.
    UnexpectedEof,
    /// Invalid UTF-8 encoding in a text string.
    InvalidUtf8,
    /// Integer overflow during encoding or decoding.
    Overflow,
    /// Invalid simple value.
    InvalidSimple(u8),
    /// Custom error message.
    Custom(String),
}

impl std::fmt::Display for CborError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CborError::UnexpectedType { expected, found } => {
                write!(
                    f,
                    "unexpected CBOR type: expected {:?}, found {:?}",
                    expected, found
                )
            }
            CborError::UnexpectedEof => write!(f, "unexpected end of CBOR data"),
            CborError::InvalidUtf8 => write!(f, "invalid UTF-8 in CBOR text string"),
            CborError::Overflow => write!(f, "integer overflow in CBOR encoding/decoding"),
            CborError::InvalidSimple(v) => write!(f, "invalid CBOR simple value: {}", v),
            CborError::Custom(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for CborError {}

/// A CBOR decoder that reads from a byte stream.
///
/// Unlike [`CborDecoder`] which borrows from an in-memory buffer,
/// this decoder owns a reader and returns owned values. It is designed
/// for parsing large COSE files where materializing the entire payload
/// in memory is not feasible.
///
/// # Key Method
///
/// [`decode_bstr_header_offset`](CborStreamDecoder::decode_bstr_header_offset)
/// reads only the CBOR byte string length prefix and returns the content
/// offset and length without reading the content bytes. This allows
/// callers to skip over or stream large payloads without buffering.
pub trait CborStreamDecoder {
    /// The error type returned by decoding operations.
    type Error: std::error::Error + Send + Sync + 'static;

    // Type inspection

    /// Peeks at the next CBOR type without consuming it.
    fn peek_type(&mut self) -> Result<CborType, Self::Error>;

    // Major type 0/1: Integers

    /// Decodes an unsigned 64-bit integer (major type 0).
    fn decode_u64(&mut self) -> Result<u64, Self::Error>;

    /// Decodes a signed 64-bit integer (major types 0 and 1).
    fn decode_i64(&mut self) -> Result<i64, Self::Error>;

    // Major type 2: Byte strings

    /// Decodes a byte string, reading its content into a new `Vec<u8>`.
    fn decode_bstr_owned(&mut self) -> Result<Vec<u8>, Self::Error>;

    /// Decodes a byte string header only, returning `(offset, length)`.
    ///
    /// The stream position advances past the header but **not** past the
    /// content bytes. The caller can then:
    /// - Skip: `stream.seek(SeekFrom::Current(len as i64))`
    /// - Read later: `stream.seek(SeekFrom::Start(offset)); stream.read_exact(&mut buf)`
    /// - Stream through a hasher without buffering
    fn decode_bstr_header_offset(&mut self) -> Result<(u64, u64), Self::Error>;

    // Major type 3: Text strings

    /// Decodes a text string, reading its content and validating UTF-8.
    fn decode_tstr_owned(&mut self) -> Result<String, Self::Error>;

    // Major type 4: Arrays

    /// Decodes an array header, returning the length (`None` for indefinite).
    fn decode_array_len(&mut self) -> Result<Option<usize>, Self::Error>;

    // Major type 5: Maps

    /// Decodes a map header, returning the number of pairs (`None` for indefinite).
    fn decode_map_len(&mut self) -> Result<Option<usize>, Self::Error>;

    // Major type 6: Tags

    /// Decodes a tag value.
    fn decode_tag(&mut self) -> Result<u64, Self::Error>;

    // Major type 7: Simple values

    /// Decodes a boolean value.
    fn decode_bool(&mut self) -> Result<bool, Self::Error>;

    /// Decodes and consumes a null value (0xf6).
    fn decode_null(&mut self) -> Result<(), Self::Error>;

    /// Peeks to check if the next value is null without consuming it.
    fn is_null(&mut self) -> Result<bool, Self::Error>;

    // Navigation

    /// Skips the next CBOR item without decoding it.
    fn skip(&mut self) -> Result<(), Self::Error>;

    /// Returns the current byte position in the stream.
    fn position(&self) -> u64;
}
