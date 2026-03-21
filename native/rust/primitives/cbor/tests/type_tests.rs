// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CBOR type enums (CborType, CborSimple) and error types.

use cbor_primitives::{CborError, CborSimple, CborType};

// ============================================================================
// CborType Tests
// ============================================================================

#[test]
fn test_cbor_type_all_variants() {
    // Verify all 15 variants exist
    let _: CborType = CborType::UnsignedInt;
    let _: CborType = CborType::NegativeInt;
    let _: CborType = CborType::ByteString;
    let _: CborType = CborType::TextString;
    let _: CborType = CborType::Array;
    let _: CborType = CborType::Map;
    let _: CborType = CborType::Tag;
    let _: CborType = CborType::Simple;
    let _: CborType = CborType::Float16;
    let _: CborType = CborType::Float32;
    let _: CborType = CborType::Float64;
    let _: CborType = CborType::Bool;
    let _: CborType = CborType::Null;
    let _: CborType = CborType::Undefined;
    let _: CborType = CborType::Break;
}

#[test]
fn test_cbor_type_clone() {
    let original = CborType::UnsignedInt;
    let cloned = original.clone();
    assert_eq!(original, cloned);

    let original = CborType::Map;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn test_cbor_type_copy() {
    let original = CborType::ByteString;
    let copied = original; // Copy semantics
    assert_eq!(original, copied);
}

#[test]
fn test_cbor_type_debug() {
    assert_eq!(format!("{:?}", CborType::UnsignedInt), "UnsignedInt");
    assert_eq!(format!("{:?}", CborType::NegativeInt), "NegativeInt");
    assert_eq!(format!("{:?}", CborType::ByteString), "ByteString");
    assert_eq!(format!("{:?}", CborType::TextString), "TextString");
    assert_eq!(format!("{:?}", CborType::Array), "Array");
    assert_eq!(format!("{:?}", CborType::Map), "Map");
    assert_eq!(format!("{:?}", CborType::Tag), "Tag");
    assert_eq!(format!("{:?}", CborType::Simple), "Simple");
    assert_eq!(format!("{:?}", CborType::Float16), "Float16");
    assert_eq!(format!("{:?}", CborType::Float32), "Float32");
    assert_eq!(format!("{:?}", CborType::Float64), "Float64");
    assert_eq!(format!("{:?}", CborType::Bool), "Bool");
    assert_eq!(format!("{:?}", CborType::Null), "Null");
    assert_eq!(format!("{:?}", CborType::Undefined), "Undefined");
    assert_eq!(format!("{:?}", CborType::Break), "Break");
}

#[test]
fn test_cbor_type_partial_eq() {
    assert_eq!(CborType::UnsignedInt, CborType::UnsignedInt);
    assert_eq!(CborType::Array, CborType::Array);
    assert_ne!(CborType::UnsignedInt, CborType::NegativeInt);
    assert_ne!(CborType::Array, CborType::Map);
    assert_ne!(CborType::Float16, CborType::Float32);
}

#[test]
fn test_cbor_type_eq() {
    // Eq requires reflexivity, symmetry, and transitivity
    let t1 = CborType::Map;
    let t2 = CborType::Map;
    let t3 = CborType::Map;

    // Reflexivity
    assert_eq!(t1, t1);

    // Symmetry
    assert_eq!(t1, t2);
    assert_eq!(t2, t1);

    // Transitivity
    assert_eq!(t1, t2);
    assert_eq!(t2, t3);
    assert_eq!(t1, t3);
}

// ============================================================================
// CborSimple Tests
// ============================================================================

#[test]
fn test_cbor_simple_all_variants() {
    // Verify all 5 variant types exist
    let _: CborSimple = CborSimple::False;
    let _: CborSimple = CborSimple::True;
    let _: CborSimple = CborSimple::Null;
    let _: CborSimple = CborSimple::Undefined;
    let _: CborSimple = CborSimple::Unassigned(0);
}

#[test]
fn test_cbor_simple_clone() {
    let original = CborSimple::True;
    let cloned = original.clone();
    assert_eq!(original, cloned);

    let original = CborSimple::Unassigned(42);
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn test_cbor_simple_copy() {
    let original = CborSimple::False;
    let copied = original; // Copy semantics
    assert_eq!(original, copied);
}

#[test]
fn test_cbor_simple_debug() {
    assert_eq!(format!("{:?}", CborSimple::False), "False");
    assert_eq!(format!("{:?}", CborSimple::True), "True");
    assert_eq!(format!("{:?}", CborSimple::Null), "Null");
    assert_eq!(format!("{:?}", CborSimple::Undefined), "Undefined");
    assert_eq!(
        format!("{:?}", CborSimple::Unassigned(10)),
        "Unassigned(10)"
    );
    assert_eq!(
        format!("{:?}", CborSimple::Unassigned(255)),
        "Unassigned(255)"
    );
}

#[test]
fn test_cbor_simple_partial_eq() {
    assert_eq!(CborSimple::False, CborSimple::False);
    assert_eq!(CborSimple::True, CborSimple::True);
    assert_eq!(CborSimple::Null, CborSimple::Null);
    assert_eq!(CborSimple::Undefined, CborSimple::Undefined);
    assert_eq!(CborSimple::Unassigned(42), CborSimple::Unassigned(42));

    assert_ne!(CborSimple::False, CborSimple::True);
    assert_ne!(CborSimple::Null, CborSimple::Undefined);
    assert_ne!(CborSimple::Unassigned(10), CborSimple::Unassigned(20));
}

#[test]
fn test_cbor_simple_eq() {
    // Eq requires reflexivity, symmetry, and transitivity
    let s1 = CborSimple::Unassigned(100);
    let s2 = CborSimple::Unassigned(100);
    let s3 = CborSimple::Unassigned(100);

    // Reflexivity
    assert_eq!(s1, s1);

    // Symmetry
    assert_eq!(s1, s2);
    assert_eq!(s2, s1);

    // Transitivity
    assert_eq!(s1, s2);
    assert_eq!(s2, s3);
    assert_eq!(s1, s3);
}

#[test]
fn test_cbor_simple_unassigned_range() {
    // Test various unassigned values across the valid range
    let _: CborSimple = CborSimple::Unassigned(0);
    let _: CborSimple = CborSimple::Unassigned(19);
    let _: CborSimple = CborSimple::Unassigned(24);
    let _: CborSimple = CborSimple::Unassigned(31);
    let _: CborSimple = CborSimple::Unassigned(32);
    let _: CborSimple = CborSimple::Unassigned(128);
    let _: CborSimple = CborSimple::Unassigned(255);
}

// ============================================================================
// CborError Tests
// ============================================================================

#[test]
fn test_cbor_error_all_variants() {
    // Verify all 6 variant types exist
    let _: CborError = CborError::UnexpectedType {
        expected: CborType::UnsignedInt,
        found: CborType::TextString,
    };
    let _: CborError = CborError::UnexpectedEof;
    let _: CborError = CborError::InvalidUtf8;
    let _: CborError = CborError::Overflow;
    let _: CborError = CborError::InvalidSimple(99);
    let _: CborError = CborError::Custom("test".to_string());
}

#[test]
fn test_cbor_error_clone() {
    let original = CborError::UnexpectedEof;
    let cloned = original.clone();
    assert_eq!(format!("{}", original), format!("{}", cloned));

    let original = CborError::Custom("test error".to_string());
    let cloned = original.clone();
    assert_eq!(format!("{}", original), format!("{}", cloned));
}

#[test]
fn test_cbor_error_debug() {
    let error = CborError::UnexpectedEof;
    let debug_output = format!("{:?}", error);
    assert!(debug_output.contains("UnexpectedEof"));

    let error = CborError::InvalidSimple(42);
    let debug_output = format!("{:?}", error);
    assert!(debug_output.contains("InvalidSimple"));
    assert!(debug_output.contains("42"));
}

#[test]
fn test_cbor_error_display_unexpected_type() {
    let error = CborError::UnexpectedType {
        expected: CborType::UnsignedInt,
        found: CborType::TextString,
    };
    let display = format!("{}", error);
    assert!(display.contains("unexpected CBOR type"));
    assert!(display.contains("expected"));
    assert!(display.contains("found"));
}

#[test]
fn test_cbor_error_display_unexpected_eof() {
    let error = CborError::UnexpectedEof;
    let display = format!("{}", error);
    assert_eq!(display, "unexpected end of CBOR data");
}

#[test]
fn test_cbor_error_display_invalid_utf8() {
    let error = CborError::InvalidUtf8;
    let display = format!("{}", error);
    assert_eq!(display, "invalid UTF-8 in CBOR text string");
}

#[test]
fn test_cbor_error_display_overflow() {
    let error = CborError::Overflow;
    let display = format!("{}", error);
    assert_eq!(display, "integer overflow in CBOR encoding/decoding");
}

#[test]
fn test_cbor_error_display_invalid_simple() {
    let error = CborError::InvalidSimple(99);
    let display = format!("{}", error);
    assert_eq!(display, "invalid CBOR simple value: 99");
}

#[test]
fn test_cbor_error_display_custom() {
    let error = CborError::Custom("custom error message".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "custom error message");
}

#[test]
fn test_cbor_error_is_std_error() {
    // Verify CborError implements std::error::Error
    fn assert_is_error<E: std::error::Error>(_: &E) {}

    assert_is_error(&CborError::UnexpectedEof);
    assert_is_error(&CborError::InvalidUtf8);
    assert_is_error(&CborError::Overflow);
    assert_is_error(&CborError::InvalidSimple(0));
    assert_is_error(&CborError::Custom("test".to_string()));
    assert_is_error(&CborError::UnexpectedType {
        expected: CborType::Array,
        found: CborType::Map,
    });
}

#[test]
fn test_cbor_error_trait_bounds() {
    // Verify CborError is Send + Sync + 'static
    fn assert_bounds<E: std::error::Error + Send + Sync + 'static>() {}
    assert_bounds::<CborError>();
}
