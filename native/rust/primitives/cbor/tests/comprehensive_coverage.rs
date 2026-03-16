// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for CBOR primitives.

use cbor_primitives::{RawCbor, CborType, CborSimple, CborError};

#[test]
fn test_raw_cbor_as_i64() {
    // Test positive integers (major type 0)
    let cbor_0 = RawCbor::new(&[0x00]); // 0
    assert_eq!(cbor_0.try_as_i64(), Some(0));
    
    let cbor_23 = RawCbor::new(&[0x17]); // 23 
    assert_eq!(cbor_23.try_as_i64(), Some(23));
    
    let cbor_24 = RawCbor::new(&[0x18, 0x18]); // 24
    assert_eq!(cbor_24.try_as_i64(), Some(24));
    
    let cbor_256 = RawCbor::new(&[0x19, 0x01, 0x00]); // 256
    assert_eq!(cbor_256.try_as_i64(), Some(256));
    
    let cbor_65536 = RawCbor::new(&[0x1a, 0x00, 0x01, 0x00, 0x00]); // 65536
    assert_eq!(cbor_65536.try_as_i64(), Some(65536));
    
    // Test negative integers (major type 1)
    let cbor_neg1 = RawCbor::new(&[0x20]); // -1
    assert_eq!(cbor_neg1.try_as_i64(), Some(-1));
    
    let cbor_neg24 = RawCbor::new(&[0x37]); // -24
    assert_eq!(cbor_neg24.try_as_i64(), Some(-24));
    
    let cbor_neg25 = RawCbor::new(&[0x38, 0x18]); // -25
    assert_eq!(cbor_neg25.try_as_i64(), Some(-25));
    
    // Test non-integers
    let cbor_str = RawCbor::new(&[0x60]); // empty string
    assert_eq!(cbor_str.try_as_i64(), None);
    
    let cbor_bytes = RawCbor::new(&[0x40]); // empty bytes
    assert_eq!(cbor_bytes.try_as_i64(), None);
    
    // Test edge cases
    let empty = RawCbor::new(&[]);
    assert_eq!(empty.try_as_i64(), None);
    
    let truncated = RawCbor::new(&[0x18]); // missing byte after 0x18
    assert_eq!(truncated.try_as_i64(), None);
}

#[test]
fn test_raw_cbor_as_u64() {
    // Test unsigned integers (major type 0)
    let cbor_0 = RawCbor::new(&[0x00]);
    assert_eq!(cbor_0.try_as_u64(), Some(0));
    
    let cbor_max_u8 = RawCbor::new(&[0x18, 0xFF]);
    assert_eq!(cbor_max_u8.try_as_u64(), Some(255));
    
    let cbor_max_u16 = RawCbor::new(&[0x19, 0xFF, 0xFF]);
    assert_eq!(cbor_max_u16.try_as_u64(), Some(65535));
    
    let cbor_max_u32 = RawCbor::new(&[0x1a, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(cbor_max_u32.try_as_u64(), Some(u32::MAX as u64));
    
    let cbor_u64 = RawCbor::new(&[0x1b, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(cbor_u64.try_as_u64(), Some(u32::MAX as u64));
    
    // Test negative integers should return None
    let cbor_neg = RawCbor::new(&[0x20]); // -1
    assert_eq!(cbor_neg.try_as_u64(), None);
    
    // Test non-integers
    let cbor_str = RawCbor::new(&[0x60]);
    assert_eq!(cbor_str.try_as_u64(), None);
    
    // Test truncated
    let truncated = RawCbor::new(&[0x19, 0x01]); // missing second byte
    assert_eq!(truncated.try_as_u64(), None);
}

#[test]
fn test_raw_cbor_as_bool() {
    // Test CBOR booleans
    let cbor_false = RawCbor::new(&[0xF4]);
    assert_eq!(cbor_false.try_as_bool(), Some(false));
    
    let cbor_true = RawCbor::new(&[0xF5]);
    assert_eq!(cbor_true.try_as_bool(), Some(true));
    
    // Test non-booleans
    let cbor_null = RawCbor::new(&[0xF6]);
    assert_eq!(cbor_null.try_as_bool(), None);
    
    let cbor_undefined = RawCbor::new(&[0xF7]);
    assert_eq!(cbor_undefined.try_as_bool(), None);
    
    let cbor_int = RawCbor::new(&[0x00]);
    assert_eq!(cbor_int.try_as_bool(), None);
    
    let empty = RawCbor::new(&[]);
    assert_eq!(empty.try_as_bool(), None);
}

#[test] 
fn test_raw_cbor_as_str() {
    // Test valid text strings (major type 3)
    let cbor_empty_str = RawCbor::new(&[0x60]); // ""
    assert_eq!(cbor_empty_str.try_as_str(), Some(""));
    
    let cbor_hello = RawCbor::new(&[0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f]); // "hello"
    assert_eq!(cbor_hello.try_as_str(), Some("hello"));
    
    let cbor_short = RawCbor::new(&[0x61, 0x41]); // "A"
    assert_eq!(cbor_short.try_as_str(), Some("A"));
    
    let cbor_long = RawCbor::new(&[0x78, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello" with length > 23
    assert_eq!(cbor_long.try_as_str(), Some("Hello"));
    
    // Test non-strings
    let cbor_bytes = RawCbor::new(&[0x45, 0x68, 0x65, 0x6c, 0x6c, 0x6f]); // byte string
    assert_eq!(cbor_bytes.try_as_str(), None);
    
    let cbor_int = RawCbor::new(&[0x00]);
    assert_eq!(cbor_int.try_as_str(), None);
    
    // Test invalid UTF-8
    let cbor_invalid_utf8 = RawCbor::new(&[0x62, 0xFF, 0xFE]); // invalid UTF-8
    assert_eq!(cbor_invalid_utf8.try_as_str(), None);
    
    // Test truncated
    let truncated = RawCbor::new(&[0x65, 0x68, 0x65]); // says length 5 but only has 2 bytes
    assert_eq!(truncated.try_as_str(), None);
    
    let empty = RawCbor::new(&[]);
    assert_eq!(empty.try_as_str(), None);
}

#[test]
fn test_raw_cbor_as_bstr() {
    // Test valid byte strings (major type 2)
    let cbor_empty_bstr = RawCbor::new(&[0x40]); // empty byte string
    assert_eq!(cbor_empty_bstr.try_as_bstr(), Some(&[][..]));
    
    let cbor_bytes = RawCbor::new(&[0x45, 0x01, 0x02, 0x03, 0x04, 0x05]); // 5 bytes
    assert_eq!(cbor_bytes.try_as_bstr(), Some(&[0x01, 0x02, 0x03, 0x04, 0x05][..]));
    
    let cbor_single = RawCbor::new(&[0x41, 0xFF]); // 1 byte
    assert_eq!(cbor_single.try_as_bstr(), Some(&[0xFF][..]));
    
    let cbor_long = RawCbor::new(&[0x58, 0x03, 0xAA, 0xBB, 0xCC]); // length > 23
    assert_eq!(cbor_long.try_as_bstr(), Some(&[0xAA, 0xBB, 0xCC][..]));
    
    // Test non-byte-strings
    let cbor_str = RawCbor::new(&[0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f]); // text string
    assert_eq!(cbor_str.try_as_bstr(), None);
    
    let cbor_int = RawCbor::new(&[0x00]);
    assert_eq!(cbor_int.try_as_bstr(), None);
    
    // Test truncated
    let truncated = RawCbor::new(&[0x45, 0x01, 0x02]); // says length 5 but only has 2 bytes
    assert_eq!(truncated.try_as_bstr(), None);
    
    let empty = RawCbor::new(&[]);
    assert_eq!(empty.try_as_bstr(), None);
}

#[test]
fn test_raw_cbor_major_type() {
    // Test all major types
    let cbor_uint = RawCbor::new(&[0x00]);
    assert_eq!(cbor_uint.major_type(), Some(0));
    
    let cbor_nint = RawCbor::new(&[0x20]);
    assert_eq!(cbor_nint.major_type(), Some(1));
    
    let cbor_bstr = RawCbor::new(&[0x40]);
    assert_eq!(cbor_bstr.major_type(), Some(2));
    
    let cbor_tstr = RawCbor::new(&[0x60]);
    assert_eq!(cbor_tstr.major_type(), Some(3));
    
    let cbor_array = RawCbor::new(&[0x80]);
    assert_eq!(cbor_array.major_type(), Some(4));
    
    let cbor_map = RawCbor::new(&[0xA0]);
    assert_eq!(cbor_map.major_type(), Some(5));
    
    let cbor_tag = RawCbor::new(&[0xC0]);
    assert_eq!(cbor_tag.major_type(), Some(6));
    
    let cbor_simple = RawCbor::new(&[0xE0]);
    assert_eq!(cbor_simple.major_type(), Some(7));
    
    let empty = RawCbor::new(&[]);
    assert_eq!(empty.major_type(), None);
}

#[test]
fn test_cbor_types() {
    // Test CborType enum variants
    assert_ne!(CborType::UnsignedInt, CborType::NegativeInt);
    assert_ne!(CborType::ByteString, CborType::TextString);
    assert_ne!(CborType::Array, CborType::Map);
    assert_ne!(CborType::Tag, CborType::Simple);
    assert_ne!(CborType::Float16, CborType::Float32);
    assert_ne!(CborType::Float32, CborType::Float64);
    assert_ne!(CborType::Bool, CborType::Null);
    assert_ne!(CborType::Null, CborType::Undefined);
    assert_ne!(CborType::Undefined, CborType::Break);
    
    // Test Clone
    let typ = CborType::UnsignedInt;
    let cloned = typ.clone();
    assert_eq!(typ, cloned);
    
    // Test Debug
    let debug_str = format!("{:?}", CborType::ByteString);
    assert_eq!(debug_str, "ByteString");
}

#[test]
fn test_cbor_simple() {
    // Test CborSimple enum variants
    assert_ne!(CborSimple::False, CborSimple::True);
    assert_ne!(CborSimple::True, CborSimple::Null);
    assert_ne!(CborSimple::Null, CborSimple::Undefined);
    assert_ne!(CborSimple::Unassigned(0), CborSimple::Unassigned(1));
    
    // Test Clone
    let simple = CborSimple::True;
    let cloned = simple.clone();
    assert_eq!(simple, cloned);
    
    // Test Debug
    let debug_str = format!("{:?}", CborSimple::Null);
    assert_eq!(debug_str, "Null");
}

#[test]
fn test_cbor_error() {
    // Test CborError variants
    let err1 = CborError::Custom("test".to_string());
    let err2 = CborError::UnexpectedEof;
    let err3 = CborError::UnexpectedType { expected: CborType::UnsignedInt, found: CborType::TextString };
    let err4 = CborError::Overflow;
    let err5 = CborError::InvalidUtf8;
    let err6 = CborError::InvalidSimple(255);
    
    assert_ne!(err1.to_string(), err2.to_string());
    assert_ne!(err2.to_string(), err3.to_string());
    assert_ne!(err3.to_string(), err4.to_string());
    assert_ne!(err4.to_string(), err5.to_string());
    assert_ne!(err5.to_string(), err6.to_string());
    
    // Test Debug
    let debug_str = format!("{:?}", CborError::UnexpectedEof);
    assert!(debug_str.contains("UnexpectedEof"));
    
    // Test Clone
    let cloned_err = err1.clone();
    assert_eq!(err1.to_string(), cloned_err.to_string());
}

#[test]
fn test_raw_cbor_edge_cases() {
    // Test additional info values 27, 28, 29, 30 (reserved/unassigned) 
    let cbor_reserved = RawCbor::new(&[0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // valid u64
    assert_eq!(cbor_reserved.try_as_u64(), Some(1));
    
    // Test out of range additional info
    let cbor_invalid_additional = RawCbor::new(&[0x1C]); // additional info 28 (reserved)
    assert_eq!(cbor_invalid_additional.try_as_u64(), None);
    
    // Test very large numbers
    let cbor_large_uint = RawCbor::new(&[0x1b, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // u64::MAX
    assert_eq!(cbor_large_uint.try_as_u64(), Some(u64::MAX));
    
    // This should fail to convert to i64 since it's > i64::MAX
    assert_eq!(cbor_large_uint.try_as_i64(), None);
    
    // Test largest negative number
    let cbor_large_neg = RawCbor::new(&[0x3b, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // -i64::MAX - 1 = i64::MIN
    assert_eq!(cbor_large_neg.try_as_i64(), Some(i64::MIN));
    
    // Test string with length that exceeds available bytes
    let cbor_bad_str_len = RawCbor::new(&[0x6A]); // says 10 bytes but no data
    assert_eq!(cbor_bad_str_len.try_as_str(), None);
    
    // Test byte string with length that exceeds available bytes
    let cbor_bad_bstr_len = RawCbor::new(&[0x4A]); // says 10 bytes but no data
    assert_eq!(cbor_bad_bstr_len.try_as_bstr(), None);
}

#[test]
fn test_raw_cbor_new() {
    // Test RawCbor::new with different inputs
    let empty = RawCbor::new(&[]);
    assert_eq!(empty.as_bytes(), &[]);
    
    let single_byte = RawCbor::new(&[0x00]);
    assert_eq!(single_byte.as_bytes(), &[0x00]);
    
    let multi_bytes = RawCbor::new(&[0x01, 0x02, 0x03]);
    assert_eq!(multi_bytes.as_bytes(), &[0x01, 0x02, 0x03]);
}

#[test]
fn test_raw_cbor_as_bytes() {
    let data = &[0x18, 0x2A];
    let cbor = RawCbor::new(data);
    assert_eq!(cbor.as_bytes(), data);
    
    // Test that as_bytes returns the exact same reference
    let slice1 = cbor.as_bytes();
    let slice2 = cbor.as_bytes();
    assert_eq!(slice1.as_ptr(), slice2.as_ptr());
}

#[test]
fn test_decode_uint_arg_coverage() {
    // Test different additional info values to get full decode_uint_arg coverage
    
    // Values 0-23: direct encoding
    for i in 0u8..=23 {
        let data = [i];
        let cbor = RawCbor::new(&data);
        assert_eq!(cbor.try_as_u64(), Some(i as u64));
    }
    
    // Value 24: next byte
    let cbor_24 = RawCbor::new(&[0x18, 0x64]); // 100
    assert_eq!(cbor_24.try_as_u64(), Some(100));
    
    // Value 25: next 2 bytes  
    let cbor_25 = RawCbor::new(&[0x19, 0x03, 0xE8]); // 1000
    assert_eq!(cbor_25.try_as_u64(), Some(1000));
    
    // Value 26: next 4 bytes
    let cbor_26 = RawCbor::new(&[0x1a, 0x00, 0x0F, 0x42, 0x40]); // 1000000
    assert_eq!(cbor_26.try_as_u64(), Some(1000000));
    
    // Value 27: next 8 bytes
    let cbor_27 = RawCbor::new(&[0x1b, 0x00, 0x00, 0x00, 0xE8, 0xD4, 0xA5, 0x10, 0x00]); // 1000000000000
    assert_eq!(cbor_27.try_as_u64(), Some(1000000000000));
    
    // Invalid additional info values (28-31 are invalid for integers)
    let cbor_invalid = RawCbor::new(&[0x1C]); // additional info 28
    assert_eq!(cbor_invalid.try_as_u64(), None);
    
    let cbor_invalid2 = RawCbor::new(&[0x1D]); // additional info 29  
    assert_eq!(cbor_invalid2.try_as_u64(), None);
    
    let cbor_invalid3 = RawCbor::new(&[0x1E]); // additional info 30
    assert_eq!(cbor_invalid3.try_as_u64(), None);
    
    let cbor_invalid4 = RawCbor::new(&[0x1F]); // additional info 31
    assert_eq!(cbor_invalid4.try_as_u64(), None);
}
