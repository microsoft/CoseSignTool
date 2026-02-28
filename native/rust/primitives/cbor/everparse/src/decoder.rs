// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! EverParse-based CBOR decoder implementation.
//!
//! Uses EverParse's formally verified `cborrs` parser for decoding scalar CBOR
//! items and skipping nested structures. Structural headers (array/map lengths,
//! tags) and floating-point values are decoded directly from raw bytes since
//! `cborrs` operates on complete CBOR objects rather than streaming headers.

use cbor_primitives::{CborDecoder, CborSimple, CborType};
use cborrs::cbordet::{
    cbor_det_destruct, cbor_det_parse, CborDetIntKind, CborDetView,
};

use crate::EverparseError;

/// CBOR decoder backed by EverParse's verified deterministic CBOR parser.
pub struct EverparseCborDecoder<'a> {
    input: &'a [u8],
    remaining: &'a [u8],
}

impl<'a> EverparseCborDecoder<'a> {
    /// Creates a new decoder for the given input data.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            input: data,
            remaining: data,
        }
    }

    /// Parses the next scalar CBOR item using the verified EverParse parser.
    fn parse_next_item(&mut self) -> Result<CborDetView<'a>, EverparseError> {
        let (obj, rest) = cbor_det_parse(self.remaining)
            .ok_or_else(|| self.make_parse_error())?;
        self.remaining = rest;
        Ok(cbor_det_destruct(obj))
    }

    /// Produces an appropriate error when `cbor_det_parse` fails.
    fn make_parse_error(&self) -> EverparseError {
        if self.remaining.is_empty() {
            return EverparseError::UnexpectedEof;
        }

        let first_byte = self.remaining[0];
        let major_type = first_byte >> 5;
        let additional_info = first_byte & 0x1f;

        if major_type == 7 {
            match additional_info {
                25..=27 => EverparseError::InvalidData(
                    "floating-point values not supported by EverParse deterministic CBOR".into(),
                ),
                31 => EverparseError::InvalidData(
                    "break/indefinite-length not supported by EverParse deterministic CBOR".into(),
                ),
                _ => EverparseError::InvalidData("invalid CBOR data".into()),
            }
        } else if additional_info == 31 {
            EverparseError::InvalidData(
                "indefinite-length encoding not supported by EverParse deterministic CBOR".into(),
            )
        } else {
            EverparseError::InvalidData("invalid or non-deterministic CBOR data".into())
        }
    }

    /// Maps a `CborDetView` to a `CborType` for error reporting.
    fn view_to_cbor_type(view: &CborDetView<'_>) -> CborType {
        match view {
            CborDetView::Int64 { kind: CborDetIntKind::UInt64, .. } => CborType::UnsignedInt,
            CborDetView::Int64 { kind: CborDetIntKind::NegInt64, .. } => CborType::NegativeInt,
            CborDetView::ByteString { .. } => CborType::ByteString,
            CborDetView::TextString { .. } => CborType::TextString,
            CborDetView::Array { .. } => CborType::Array,
            CborDetView::Map { .. } => CborType::Map,
            CborDetView::Tagged { .. } => CborType::Tag,
            CborDetView::SimpleValue { _0: v } => match *v {
                20 | 21 => CborType::Bool,
                22 => CborType::Null,
                23 => CborType::Undefined,
                _ => CborType::Simple,
            },
        }
    }

    /// Decodes a CBOR argument (length/value) from raw bytes, returning
    /// (value, bytes_consumed).
    fn decode_raw_argument(&mut self) -> Result<(u64, usize), EverparseError> {
        let data = self.remaining;
        if data.is_empty() {
            return Err(EverparseError::UnexpectedEof);
        }

        let additional_info = data[0] & 0x1f;

        let (value, consumed) = if additional_info < 24 {
            (additional_info as u64, 1)
        } else if additional_info == 24 {
            if data.len() < 2 {
                return Err(EverparseError::UnexpectedEof);
            }
            (data[1] as u64, 2)
        } else if additional_info == 25 {
            if data.len() < 3 {
                return Err(EverparseError::UnexpectedEof);
            }
            (u16::from_be_bytes([data[1], data[2]]) as u64, 3)
        } else if additional_info == 26 {
            if data.len() < 5 {
                return Err(EverparseError::UnexpectedEof);
            }
            (u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as u64, 5)
        } else if additional_info == 27 {
            if data.len() < 9 {
                return Err(EverparseError::UnexpectedEof);
            }
            (
                u64::from_be_bytes([
                    data[1], data[2], data[3], data[4],
                    data[5], data[6], data[7], data[8],
                ]),
                9,
            )
        } else {
            return Err(EverparseError::InvalidData("invalid additional info".into()));
        };

        self.remaining = &data[consumed..];
        Ok((value, consumed))
    }

    /// Skips a single complete CBOR item from raw bytes (used as fallback
    /// when `cbor_det_parse` cannot handle the item, e.g., floats or
    /// non-deterministic maps with unsorted keys such as real-world CCF receipts).
    fn skip_raw_item(&mut self) -> Result<(), EverparseError> {
        let data = self.remaining;
        if data.is_empty() {
            return Err(EverparseError::UnexpectedEof);
        }

        let first_byte = data[0];
        let major_type = first_byte >> 5;
        let additional_info = first_byte & 0x1f;

        match major_type {
            // Major types 0-1: unsigned/negative integers
            0 | 1 => {
                let (_, _) = self.decode_raw_argument()?;
                Ok(())
            }
            // Major types 2-3: byte/text strings
            2 | 3 => {
                if additional_info == 31 {
                    // Indefinite length: skip chunks until break
                    self.remaining = &data[1..];
                    loop {
                        if self.remaining.is_empty() {
                            return Err(EverparseError::UnexpectedEof);
                        }
                        if self.remaining[0] == 0xff {
                            self.remaining = &self.remaining[1..];
                            break;
                        }
                        self.skip_raw_item()?;
                    }
                    Ok(())
                } else {
                    let (len, _) = self.decode_raw_argument()?;
                    let len = len as usize;
                    if self.remaining.len() < len {
                        return Err(EverparseError::UnexpectedEof);
                    }
                    self.remaining = &self.remaining[len..];
                    Ok(())
                }
            }
            // Major type 4: array
            4 => {
                if additional_info == 31 {
                    self.remaining = &data[1..];
                    loop {
                        if self.remaining.is_empty() {
                            return Err(EverparseError::UnexpectedEof);
                        }
                        if self.remaining[0] == 0xff {
                            self.remaining = &self.remaining[1..];
                            break;
                        }
                        self.skip_raw_item()?;
                    }
                } else {
                    let (count, _) = self.decode_raw_argument()?;
                    for _ in 0..count {
                        self.skip_raw_item()?;
                    }
                }
                Ok(())
            }
            // Major type 5: map
            5 => {
                if additional_info == 31 {
                    self.remaining = &data[1..];
                    loop {
                        if self.remaining.is_empty() {
                            return Err(EverparseError::UnexpectedEof);
                        }
                        if self.remaining[0] == 0xff {
                            self.remaining = &self.remaining[1..];
                            break;
                        }
                        self.skip_raw_item()?; // key
                        self.skip_raw_item()?; // value
                    }
                } else {
                    let (count, _) = self.decode_raw_argument()?;
                    for _ in 0..count {
                        self.skip_raw_item()?; // key
                        self.skip_raw_item()?; // value
                    }
                }
                Ok(())
            }
            // Major type 6: tag
            6 => {
                let (_, _) = self.decode_raw_argument()?;
                self.skip_raw_item()?; // tagged content
                Ok(())
            }
            // Major type 7: simple values and floats
            7 => {
                let skip = match additional_info {
                    0..=23 => 1,
                    24 => 2,
                    25 => 3,  // f16
                    26 => 5,  // f32
                    27 => 9,  // f64
                    31 => 1,  // break
                    _ => return Err(EverparseError::InvalidData("invalid additional info".into())),
                };
                if data.len() < skip {
                    return Err(EverparseError::UnexpectedEof);
                }
                self.remaining = &data[skip..];
                Ok(())
            }
            _ => unreachable!("CBOR major type is 3 bits, range 0-7"),
        }
    }
}

impl<'a> CborDecoder<'a> for EverparseCborDecoder<'a> {
    type Error = EverparseError;

    fn peek_type(&mut self) -> Result<CborType, Self::Error> {
        let data = self.remaining;
        if data.is_empty() {
            return Err(EverparseError::UnexpectedEof);
        }

        let first_byte = data[0];
        let major_type = first_byte >> 5;
        let additional_info = first_byte & 0x1f;

        match major_type {
            0 => Ok(CborType::UnsignedInt),
            1 => Ok(CborType::NegativeInt),
            2 => Ok(CborType::ByteString),
            3 => Ok(CborType::TextString),
            4 => Ok(CborType::Array),
            5 => Ok(CborType::Map),
            6 => Ok(CborType::Tag),
            7 => match additional_info {
                20 | 21 => Ok(CborType::Bool),
                22 => Ok(CborType::Null),
                23 => Ok(CborType::Undefined),
                24 => Ok(CborType::Simple),
                25 => Ok(CborType::Float16),
                26 => Ok(CborType::Float32),
                27 => Ok(CborType::Float64),
                31 => Ok(CborType::Break),
                _ if additional_info < 20 => Ok(CborType::Simple),
                _ => Ok(CborType::Simple),
            },
            _ => Err(EverparseError::InvalidData("invalid major type".into())),
        }
    }

    fn is_break(&mut self) -> Result<bool, Self::Error> {
        Ok(matches!(self.peek_type()?, CborType::Break))
    }

    fn is_null(&mut self) -> Result<bool, Self::Error> {
        Ok(matches!(self.peek_type()?, CborType::Null))
    }

    fn is_undefined(&mut self) -> Result<bool, Self::Error> {
        Ok(matches!(self.peek_type()?, CborType::Undefined))
    }

    fn decode_u8(&mut self) -> Result<u8, Self::Error> {
        let value = self.decode_u64()?;
        u8::try_from(value).map_err(|_| EverparseError::Overflow)
    }

    fn decode_u16(&mut self) -> Result<u16, Self::Error> {
        let value = self.decode_u64()?;
        u16::try_from(value).map_err(|_| EverparseError::Overflow)
    }

    fn decode_u32(&mut self) -> Result<u32, Self::Error> {
        let value = self.decode_u64()?;
        u32::try_from(value).map_err(|_| EverparseError::Overflow)
    }

    fn decode_u64(&mut self) -> Result<u64, Self::Error> {
        let view = self.parse_next_item()?;
        match view {
            CborDetView::Int64 { kind: CborDetIntKind::UInt64, value } => Ok(value),
            other => Err(EverparseError::UnexpectedType {
                expected: CborType::UnsignedInt,
                found: Self::view_to_cbor_type(&other),
            }),
        }
    }

    fn decode_i8(&mut self) -> Result<i8, Self::Error> {
        let value = self.decode_i64()?;
        i8::try_from(value).map_err(|_| EverparseError::Overflow)
    }

    fn decode_i16(&mut self) -> Result<i16, Self::Error> {
        let value = self.decode_i64()?;
        i16::try_from(value).map_err(|_| EverparseError::Overflow)
    }

    fn decode_i32(&mut self) -> Result<i32, Self::Error> {
        let value = self.decode_i64()?;
        i32::try_from(value).map_err(|_| EverparseError::Overflow)
    }

    fn decode_i64(&mut self) -> Result<i64, Self::Error> {
        let view = self.parse_next_item()?;
        match view {
            CborDetView::Int64 { kind: CborDetIntKind::UInt64, value } => {
                if value > i64::MAX as u64 {
                    Err(EverparseError::Overflow)
                } else {
                    Ok(value as i64)
                }
            }
            CborDetView::Int64 { kind: CborDetIntKind::NegInt64, value } => {
                // CBOR negative: -1 - value
                if value > i64::MAX as u64 {
                    Err(EverparseError::Overflow)
                } else {
                    Ok(-1 - value as i64)
                }
            }
            other => Err(EverparseError::UnexpectedType {
                expected: CborType::UnsignedInt,
                found: Self::view_to_cbor_type(&other),
            }),
        }
    }

    fn decode_i128(&mut self) -> Result<i128, Self::Error> {
        let view = self.parse_next_item()?;
        match view {
            CborDetView::Int64 { kind: CborDetIntKind::UInt64, value } => {
                Ok(value as i128)
            }
            CborDetView::Int64 { kind: CborDetIntKind::NegInt64, value } => {
                // CBOR negative: -1 - value
                Ok(-1i128 - value as i128)
            }
            other => Err(EverparseError::UnexpectedType {
                expected: CborType::UnsignedInt,
                found: Self::view_to_cbor_type(&other),
            }),
        }
    }

    fn decode_bstr(&mut self) -> Result<&'a [u8], Self::Error> {
        let view = self.parse_next_item()?;
        match view {
            CborDetView::ByteString { payload } => Ok(payload),
            other => Err(EverparseError::UnexpectedType {
                expected: CborType::ByteString,
                found: Self::view_to_cbor_type(&other),
            }),
        }
    }

    fn decode_bstr_header(&mut self) -> Result<Option<u64>, Self::Error> {
        let data = self.remaining;
        if data.is_empty() {
            return Err(EverparseError::UnexpectedEof);
        }

        let major_type = data[0] >> 5;
        let additional_info = data[0] & 0x1f;

        if major_type != 2 {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::ByteString,
                found: self.peek_type()?,
            });
        }

        if additional_info == 31 {
            self.remaining = &data[1..];
            Ok(None)
        } else {
            let (len, _) = self.decode_raw_argument()?;
            Ok(Some(len))
        }
    }

    fn decode_tstr(&mut self) -> Result<&'a str, Self::Error> {
        let view = self.parse_next_item()?;
        match view {
            CborDetView::TextString { payload } => Ok(payload),
            other => Err(EverparseError::UnexpectedType {
                expected: CborType::TextString,
                found: Self::view_to_cbor_type(&other),
            }),
        }
    }

    fn decode_tstr_header(&mut self) -> Result<Option<u64>, Self::Error> {
        let data = self.remaining;
        if data.is_empty() {
            return Err(EverparseError::UnexpectedEof);
        }

        let major_type = data[0] >> 5;
        let additional_info = data[0] & 0x1f;

        if major_type != 3 {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::TextString,
                found: self.peek_type()?,
            });
        }

        if additional_info == 31 {
            self.remaining = &data[1..];
            Ok(None)
        } else {
            let (len, _) = self.decode_raw_argument()?;
            Ok(Some(len))
        }
    }

    fn decode_array_len(&mut self) -> Result<Option<usize>, Self::Error> {
        let data = self.remaining;
        if data.is_empty() {
            return Err(EverparseError::UnexpectedEof);
        }

        let major_type = data[0] >> 5;
        let additional_info = data[0] & 0x1f;

        if major_type != 4 {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::Array,
                found: self.peek_type()?,
            });
        }

        if additional_info == 31 {
            self.remaining = &data[1..];
            Ok(None)
        } else {
            let (len, _) = self.decode_raw_argument()?;
            Ok(Some(len as usize))
        }
    }

    fn decode_map_len(&mut self) -> Result<Option<usize>, Self::Error> {
        let data = self.remaining;
        if data.is_empty() {
            return Err(EverparseError::UnexpectedEof);
        }

        let major_type = data[0] >> 5;
        let additional_info = data[0] & 0x1f;

        if major_type != 5 {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::Map,
                found: self.peek_type()?,
            });
        }

        if additional_info == 31 {
            self.remaining = &data[1..];
            Ok(None)
        } else {
            let (len, _) = self.decode_raw_argument()?;
            Ok(Some(len as usize))
        }
    }

    fn decode_tag(&mut self) -> Result<u64, Self::Error> {
        let data = self.remaining;
        if data.is_empty() {
            return Err(EverparseError::UnexpectedEof);
        }

        let major_type = data[0] >> 5;
        if major_type != 6 {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::Tag,
                found: self.peek_type()?,
            });
        }

        let (tag, _) = self.decode_raw_argument()?;
        Ok(tag)
    }

    fn decode_bool(&mut self) -> Result<bool, Self::Error> {
        let view = self.parse_next_item()?;
        match view {
            CborDetView::SimpleValue { _0: 20 } => Ok(false),
            CborDetView::SimpleValue { _0: 21 } => Ok(true),
            other => Err(EverparseError::UnexpectedType {
                expected: CborType::Bool,
                found: Self::view_to_cbor_type(&other),
            }),
        }
    }

    fn decode_null(&mut self) -> Result<(), Self::Error> {
        let view = self.parse_next_item()?;
        match view {
            CborDetView::SimpleValue { _0: 22 } => Ok(()),
            other => Err(EverparseError::UnexpectedType {
                expected: CborType::Null,
                found: Self::view_to_cbor_type(&other),
            }),
        }
    }

    fn decode_undefined(&mut self) -> Result<(), Self::Error> {
        let view = self.parse_next_item()?;
        match view {
            CborDetView::SimpleValue { _0: 23 } => Ok(()),
            other => Err(EverparseError::UnexpectedType {
                expected: CborType::Undefined,
                found: Self::view_to_cbor_type(&other),
            }),
        }
    }

    fn decode_simple(&mut self) -> Result<CborSimple, Self::Error> {
        let view = self.parse_next_item()?;
        match view {
            CborDetView::SimpleValue { _0: v } => match v {
                20 => Ok(CborSimple::False),
                21 => Ok(CborSimple::True),
                22 => Ok(CborSimple::Null),
                23 => Ok(CborSimple::Undefined),
                other => Ok(CborSimple::Unassigned(other)),
            },
            other => Err(EverparseError::UnexpectedType {
                expected: CborType::Simple,
                found: Self::view_to_cbor_type(&other),
            }),
        }
    }

    fn decode_f16(&mut self) -> Result<f32, Self::Error> {
        let data = self.remaining;
        if data.is_empty() {
            return Err(EverparseError::UnexpectedEof);
        }
        if data[0] != 0xf9 {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::Float16,
                found: self.peek_type()?,
            });
        }
        if data.len() < 3 {
            return Err(EverparseError::UnexpectedEof);
        }

        let bits = u16::from_be_bytes([data[1], data[2]]);
        self.remaining = &data[3..];
        Ok(f16_bits_to_f32(bits))
    }

    fn decode_f32(&mut self) -> Result<f32, Self::Error> {
        let data = self.remaining;
        if data.is_empty() {
            return Err(EverparseError::UnexpectedEof);
        }
        if data[0] != 0xfa {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::Float32,
                found: self.peek_type()?,
            });
        }
        if data.len() < 5 {
            return Err(EverparseError::UnexpectedEof);
        }

        let bits = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        self.remaining = &data[5..];
        Ok(f32::from_bits(bits))
    }

    fn decode_f64(&mut self) -> Result<f64, Self::Error> {
        let data = self.remaining;
        if data.is_empty() {
            return Err(EverparseError::UnexpectedEof);
        }
        if data[0] != 0xfb {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::Float64,
                found: self.peek_type()?,
            });
        }
        if data.len() < 9 {
            return Err(EverparseError::UnexpectedEof);
        }

        let bits = u64::from_be_bytes([
            data[1], data[2], data[3], data[4],
            data[5], data[6], data[7], data[8],
        ]);
        self.remaining = &data[9..];
        Ok(f64::from_bits(bits))
    }

    fn decode_break(&mut self) -> Result<(), Self::Error> {
        let data = self.remaining;
        if data.is_empty() {
            return Err(EverparseError::UnexpectedEof);
        }
        if data[0] != 0xff {
            return Err(EverparseError::UnexpectedType {
                expected: CborType::Break,
                found: self.peek_type()?,
            });
        }
        self.remaining = &data[1..];
        Ok(())
    }

    fn skip(&mut self) -> Result<(), Self::Error> {
        // Try EverParse verified parser first for complete items
        if let Some((_, rest)) = cbor_det_parse(self.remaining) {
            self.remaining = rest;
            Ok(())
        } else {
            // Fall back to manual skip for floats and other unsupported types
            self.skip_raw_item()
        }
    }

    fn decode_raw(&mut self) -> Result<&'a [u8], Self::Error> {
        let start = self.position();
        self.skip()?;
        let end = self.position();
        Ok(&self.input[start..end])
    }

    fn remaining(&self) -> &'a [u8] {
        self.remaining
    }

    fn position(&self) -> usize {
        self.input.len() - self.remaining.len()
    }
}

/// Converts IEEE 754 half-precision (binary16) bits to an f32 value.
fn f16_bits_to_f32(bits: u16) -> f32 {
    let sign = ((bits >> 15) & 1) as u32;
    let exponent = ((bits >> 10) & 0x1f) as u32;
    let mantissa = (bits & 0x3ff) as u32;

    if exponent == 0 {
        if mantissa == 0 {
            // Zero
            f32::from_bits(sign << 31)
        } else {
            // Subnormal: convert to normalized f32
            let mut m = mantissa;
            let mut e: i32 = -14;
            while (m & 0x400) == 0 {
                m <<= 1;
                e -= 1;
            }
            m &= 0x3ff;
            let f32_exp = ((e + 127) as u32) & 0xff;
            f32::from_bits((sign << 31) | (f32_exp << 23) | (m << 13))
        }
    } else if exponent == 31 {
        // Inf or NaN
        if mantissa == 0 {
            f32::from_bits((sign << 31) | 0x7f80_0000)
        } else {
            f32::from_bits((sign << 31) | 0x7f80_0000 | (mantissa << 13))
        }
    } else {
        // Normal
        let f32_exp = exponent + 112; // 112 = 127 - 15
        f32::from_bits((sign << 31) | (f32_exp << 23) | (mantissa << 13))
    }
}
