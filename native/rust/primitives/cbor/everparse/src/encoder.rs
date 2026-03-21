// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! EverParse-compatible CBOR encoder implementation.
//!
//! Produces deterministic CBOR encoding (RFC 8949 Section 4.2.1) using the
//! shortest-form integer encoding rules. Also supports non-deterministic features
//! (floats, indefinite-length) for full trait compatibility.

use cbor_primitives::{CborEncoder, CborSimple};

use crate::EverparseError;

/// CBOR encoder producing deterministic encoding compatible with EverParse's
/// verified parser.
pub struct EverparseCborEncoder {
    buffer: Vec<u8>,
}

impl EverparseCborEncoder {
    /// Creates a new encoder with default capacity.
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Creates a new encoder with the specified initial capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    /// Encodes a CBOR header with the given major type and argument value,
    /// using the shortest encoding per RFC 8949 Section 4.2.1.
    fn encode_header(&mut self, major_type: u8, value: u64) {
        let mt = major_type << 5;
        if value < 24 {
            self.buffer.push(mt | (value as u8));
        } else if value <= u8::MAX as u64 {
            self.buffer.push(mt | 24);
            self.buffer.push(value as u8);
        } else if value <= u16::MAX as u64 {
            self.buffer.push(mt | 25);
            self.buffer.extend_from_slice(&(value as u16).to_be_bytes());
        } else if value <= u32::MAX as u64 {
            self.buffer.push(mt | 26);
            self.buffer.extend_from_slice(&(value as u32).to_be_bytes());
        } else {
            self.buffer.push(mt | 27);
            self.buffer.extend_from_slice(&value.to_be_bytes());
        }
    }
}

impl Default for EverparseCborEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl CborEncoder for EverparseCborEncoder {
    type Error = EverparseError;

    fn encode_u8(&mut self, value: u8) -> Result<(), Self::Error> {
        self.encode_header(0, value as u64);
        Ok(())
    }

    fn encode_u16(&mut self, value: u16) -> Result<(), Self::Error> {
        self.encode_header(0, value as u64);
        Ok(())
    }

    fn encode_u32(&mut self, value: u32) -> Result<(), Self::Error> {
        self.encode_header(0, value as u64);
        Ok(())
    }

    fn encode_u64(&mut self, value: u64) -> Result<(), Self::Error> {
        self.encode_header(0, value);
        Ok(())
    }

    fn encode_i8(&mut self, value: i8) -> Result<(), Self::Error> {
        self.encode_i64(value as i64)
    }

    fn encode_i16(&mut self, value: i16) -> Result<(), Self::Error> {
        self.encode_i64(value as i64)
    }

    fn encode_i32(&mut self, value: i32) -> Result<(), Self::Error> {
        self.encode_i64(value as i64)
    }

    fn encode_i64(&mut self, value: i64) -> Result<(), Self::Error> {
        if value >= 0 {
            self.encode_header(0, value as u64);
        } else {
            // CBOR negative: major type 1, argument = -1 - value
            self.encode_header(1, (-1 - value) as u64);
        }
        Ok(())
    }

    fn encode_i128(&mut self, value: i128) -> Result<(), Self::Error> {
        if value >= 0 {
            if value > u64::MAX as i128 {
                return Err(EverparseError::Overflow);
            }
            self.encode_header(0, value as u64);
        } else {
            // CBOR can represent down to -(2^64)
            let min_cbor = -(u64::MAX as i128) - 1;
            if value < min_cbor {
                return Err(EverparseError::Overflow);
            }
            let raw_value = (-1i128 - value) as u64;
            self.encode_header(1, raw_value);
        }
        Ok(())
    }

    fn encode_bstr(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.encode_header(2, data.len() as u64);
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn encode_bstr_header(&mut self, len: u64) -> Result<(), Self::Error> {
        self.encode_header(2, len);
        Ok(())
    }

    fn encode_bstr_indefinite_begin(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0x5f);
        Ok(())
    }

    fn encode_tstr(&mut self, data: &str) -> Result<(), Self::Error> {
        self.encode_header(3, data.len() as u64);
        self.buffer.extend_from_slice(data.as_bytes());
        Ok(())
    }

    fn encode_tstr_header(&mut self, len: u64) -> Result<(), Self::Error> {
        self.encode_header(3, len);
        Ok(())
    }

    fn encode_tstr_indefinite_begin(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0x7f);
        Ok(())
    }

    fn encode_array(&mut self, len: usize) -> Result<(), Self::Error> {
        self.encode_header(4, len as u64);
        Ok(())
    }

    fn encode_array_indefinite_begin(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0x9f);
        Ok(())
    }

    fn encode_map(&mut self, len: usize) -> Result<(), Self::Error> {
        self.encode_header(5, len as u64);
        Ok(())
    }

    fn encode_map_indefinite_begin(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0xbf);
        Ok(())
    }

    fn encode_tag(&mut self, tag: u64) -> Result<(), Self::Error> {
        self.encode_header(6, tag);
        Ok(())
    }

    fn encode_bool(&mut self, value: bool) -> Result<(), Self::Error> {
        self.buffer.push(if value { 0xf5 } else { 0xf4 });
        Ok(())
    }

    fn encode_null(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0xf6);
        Ok(())
    }

    fn encode_undefined(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0xf7);
        Ok(())
    }

    fn encode_simple(&mut self, value: CborSimple) -> Result<(), Self::Error> {
        match value {
            CborSimple::False => self.encode_bool(false),
            CborSimple::True => self.encode_bool(true),
            CborSimple::Null => self.encode_null(),
            CborSimple::Undefined => self.encode_undefined(),
            CborSimple::Unassigned(v) => {
                if v < 24 {
                    self.buffer.push(0xe0 | v);
                } else {
                    self.buffer.push(0xf8);
                    self.buffer.push(v);
                }
                Ok(())
            }
        }
    }

    fn encode_f16(&mut self, value: f32) -> Result<(), Self::Error> {
        let bits = f32_to_f16_bits(value);
        self.buffer.push(0xf9);
        self.buffer.extend_from_slice(&bits.to_be_bytes());
        Ok(())
    }

    fn encode_f32(&mut self, value: f32) -> Result<(), Self::Error> {
        self.buffer.push(0xfa);
        self.buffer
            .extend_from_slice(&value.to_bits().to_be_bytes());
        Ok(())
    }

    fn encode_f64(&mut self, value: f64) -> Result<(), Self::Error> {
        self.buffer.push(0xfb);
        self.buffer
            .extend_from_slice(&value.to_bits().to_be_bytes());
        Ok(())
    }

    fn encode_break(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0xff);
        Ok(())
    }

    fn encode_raw(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }
}

/// Converts an f32 value to IEEE 754 half-precision (binary16) bits.
fn f32_to_f16_bits(value: f32) -> u16 {
    let bits = value.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exponent = ((bits >> 23) & 0xff) as i32;
    let mantissa = bits & 0x007f_ffff;

    if exponent == 255 {
        // Inf or NaN
        if mantissa != 0 {
            // NaN: preserve some mantissa bits
            sign | 0x7c00 | ((mantissa >> 13) as u16).max(1)
        } else {
            // Infinity
            sign | 0x7c00
        }
    } else if exponent > 142 {
        // Overflow → infinity
        sign | 0x7c00
    } else if exponent > 112 {
        // Normal f16 range
        let exp16 = (exponent - 112) as u16;
        let mant16 = (mantissa >> 13) as u16;
        sign | (exp16 << 10) | mant16
    } else if exponent > 101 {
        // Subnormal f16
        let shift = 126 - exponent;
        let mant = (mantissa | 0x0080_0000) >> (shift + 13);
        sign | mant as u16
    } else {
        // Too small → zero
        sign
    }
}

/// Simplified CBOR encoder without floating-point support.
///
/// This encoder produces deterministic CBOR encoding per RFC 8949 but does not
/// support floating-point values, as EverParse's verified cborrs parser does not
/// handle floats.
pub struct EverParseEncoder {
    buffer: Vec<u8>,
}

impl EverParseEncoder {
    /// Creates a new encoder with default capacity.
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Creates a new encoder with the specified initial capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    /// Encodes a CBOR header with the given major type and argument value.
    fn encode_header(&mut self, major_type: u8, value: u64) {
        let mt = major_type << 5;
        if value < 24 {
            self.buffer.push(mt | (value as u8));
        } else if value <= u8::MAX as u64 {
            self.buffer.push(mt | 24);
            self.buffer.push(value as u8);
        } else if value <= u16::MAX as u64 {
            self.buffer.push(mt | 25);
            self.buffer.extend_from_slice(&(value as u16).to_be_bytes());
        } else if value <= u32::MAX as u64 {
            self.buffer.push(mt | 26);
            self.buffer.extend_from_slice(&(value as u32).to_be_bytes());
        } else {
            self.buffer.push(mt | 27);
            self.buffer.extend_from_slice(&value.to_be_bytes());
        }
    }
}

impl Default for EverParseEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl CborEncoder for EverParseEncoder {
    type Error = EverparseError;

    fn encode_u8(&mut self, value: u8) -> Result<(), Self::Error> {
        self.encode_header(0, value as u64);
        Ok(())
    }

    fn encode_u16(&mut self, value: u16) -> Result<(), Self::Error> {
        self.encode_header(0, value as u64);
        Ok(())
    }

    fn encode_u32(&mut self, value: u32) -> Result<(), Self::Error> {
        self.encode_header(0, value as u64);
        Ok(())
    }

    fn encode_u64(&mut self, value: u64) -> Result<(), Self::Error> {
        self.encode_header(0, value);
        Ok(())
    }

    fn encode_i8(&mut self, value: i8) -> Result<(), Self::Error> {
        self.encode_i64(value as i64)
    }

    fn encode_i16(&mut self, value: i16) -> Result<(), Self::Error> {
        self.encode_i64(value as i64)
    }

    fn encode_i32(&mut self, value: i32) -> Result<(), Self::Error> {
        self.encode_i64(value as i64)
    }

    fn encode_i64(&mut self, value: i64) -> Result<(), Self::Error> {
        if value >= 0 {
            self.encode_header(0, value as u64);
        } else {
            self.encode_header(1, (-1 - value) as u64);
        }
        Ok(())
    }

    fn encode_i128(&mut self, value: i128) -> Result<(), Self::Error> {
        if value >= 0 {
            if value > u64::MAX as i128 {
                return Err(EverparseError::Overflow);
            }
            self.encode_header(0, value as u64);
        } else {
            let min_cbor = -(u64::MAX as i128) - 1;
            if value < min_cbor {
                return Err(EverparseError::Overflow);
            }
            let raw_value = (-1i128 - value) as u64;
            self.encode_header(1, raw_value);
        }
        Ok(())
    }

    fn encode_bstr(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.encode_header(2, data.len() as u64);
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn encode_bstr_header(&mut self, len: u64) -> Result<(), Self::Error> {
        self.encode_header(2, len);
        Ok(())
    }

    fn encode_bstr_indefinite_begin(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0x5f);
        Ok(())
    }

    fn encode_tstr(&mut self, data: &str) -> Result<(), Self::Error> {
        self.encode_header(3, data.len() as u64);
        self.buffer.extend_from_slice(data.as_bytes());
        Ok(())
    }

    fn encode_tstr_header(&mut self, len: u64) -> Result<(), Self::Error> {
        self.encode_header(3, len);
        Ok(())
    }

    fn encode_tstr_indefinite_begin(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0x7f);
        Ok(())
    }

    fn encode_array(&mut self, len: usize) -> Result<(), Self::Error> {
        self.encode_header(4, len as u64);
        Ok(())
    }

    fn encode_array_indefinite_begin(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0x9f);
        Ok(())
    }

    fn encode_map(&mut self, len: usize) -> Result<(), Self::Error> {
        self.encode_header(5, len as u64);
        Ok(())
    }

    fn encode_map_indefinite_begin(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0xbf);
        Ok(())
    }

    fn encode_tag(&mut self, tag: u64) -> Result<(), Self::Error> {
        self.encode_header(6, tag);
        Ok(())
    }

    fn encode_bool(&mut self, value: bool) -> Result<(), Self::Error> {
        self.buffer.push(if value { 0xf5 } else { 0xf4 });
        Ok(())
    }

    fn encode_null(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0xf6);
        Ok(())
    }

    fn encode_undefined(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0xf7);
        Ok(())
    }

    fn encode_simple(&mut self, value: CborSimple) -> Result<(), Self::Error> {
        match value {
            CborSimple::False => self.encode_bool(false),
            CborSimple::True => self.encode_bool(true),
            CborSimple::Null => self.encode_null(),
            CborSimple::Undefined => self.encode_undefined(),
            CborSimple::Unassigned(v) => {
                if v < 24 {
                    self.buffer.push(0xe0 | v);
                } else {
                    self.buffer.push(0xf8);
                    self.buffer.push(v);
                }
                Ok(())
            }
        }
    }

    fn encode_f16(&mut self, _value: f32) -> Result<(), Self::Error> {
        Err(EverparseError::NotSupported(
            "floating-point encoding not supported".to_string(),
        ))
    }

    fn encode_f32(&mut self, _value: f32) -> Result<(), Self::Error> {
        Err(EverparseError::NotSupported(
            "floating-point encoding not supported".to_string(),
        ))
    }

    fn encode_f64(&mut self, _value: f64) -> Result<(), Self::Error> {
        Err(EverparseError::NotSupported(
            "floating-point encoding not supported".to_string(),
        ))
    }

    fn encode_break(&mut self) -> Result<(), Self::Error> {
        self.buffer.push(0xff);
        Ok(())
    }

    fn encode_raw(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }
}
