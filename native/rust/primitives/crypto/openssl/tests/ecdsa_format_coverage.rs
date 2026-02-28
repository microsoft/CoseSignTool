// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage tests for ECDSA signature format conversion (DER/fixed).

use cose_sign1_crypto_openssl::ecdsa_format::{der_to_fixed, fixed_to_der};

#[test]
fn test_der_to_fixed_p256_basic() {
    // Example DER-encoded ECDSA signature for P-256
    let der_sig = vec![
        0x30, 0x44, // SEQUENCE, length 0x44 (68)
        0x02, 0x20, // INTEGER, length 0x20 (32)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // r value (32 bytes)
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x02, 0x20, // INTEGER, length 0x20 (32)
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // s value (32 bytes)
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    ];
    
    let result = der_to_fixed(&der_sig, 64); // P-256 = 64 bytes total
    assert!(result.is_ok());
    
    let fixed = result.unwrap();
    assert_eq!(fixed.len(), 64);
}

#[test]
fn test_der_to_fixed_p384_basic() {
    // P-384 signature (48 bytes per component)
    let mut der_sig = vec![
        0x30, 0x62, // SEQUENCE, length 0x62 (98)
        0x02, 0x30, // INTEGER, length 0x30 (48)
    ];
    
    // Add 48 bytes for r
    let r_bytes: Vec<u8> = (1..=48).collect();
    der_sig.extend(r_bytes.clone());
    
    der_sig.extend(vec![0x02, 0x30]); // INTEGER, length 0x30 (48)
    
    // Add 48 bytes for s
    let s_bytes: Vec<u8> = (49..=96).collect();
    der_sig.extend(s_bytes.clone());
    
    let result = der_to_fixed(&der_sig, 96); // P-384 = 96 bytes total
    assert!(result.is_ok());
    
    let fixed = result.unwrap();
    assert_eq!(fixed.len(), 96);
}

#[test]
fn test_der_to_fixed_with_zero_padding() {
    // DER signature where r has leading zero byte (0x00 padding for positive integers)
    let der_sig = vec![
        0x30, 0x45, // SEQUENCE, length 0x45 (69)
        0x02, 0x21, // INTEGER, length 0x21 (33) - includes padding
        0x00, // Zero padding byte
        0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // r value with high bit set
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x02, 0x20, // INTEGER, length 0x20 (32)
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // s value
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    ];
    
    let result = der_to_fixed(&der_sig, 64);
    assert!(result.is_ok());
    
    let fixed = result.unwrap();
    assert_eq!(fixed.len(), 64);
    
    // r should be padded to 32 bytes, with the zero padding handled correctly
    let r = &fixed[0..32];
    assert_eq!(r[0], 0x80); // First byte should be 0x80, not 0x00
}

#[test]
fn test_der_to_fixed_with_short_values() {
    // DER signature with short r and s values that need padding
    let der_sig = vec![
        0x30, 0x06, // SEQUENCE, length 6
        0x02, 0x01, // INTEGER, length 1
        0x42,       // r = 0x42
        0x02, 0x01, // INTEGER, length 1
        0x43,       // s = 0x43
    ];
    
    let result = der_to_fixed(&der_sig, 64); // P-256
    assert!(result.is_ok());
    
    let fixed = result.unwrap();
    assert_eq!(fixed.len(), 64);
    
    // r should be zero-padded to 32 bytes
    let r = &fixed[0..32];
    assert_eq!(r[31], 0x42); // Last byte should be 0x42
    assert_eq!(r[30], 0x00); // Should be zero-padded
    
    // s should be zero-padded to 32 bytes
    let s = &fixed[32..64];
    assert_eq!(s[31], 0x43); // Last byte should be 0x43
    assert_eq!(s[30], 0x00); // Should be zero-padded
}

#[test]
fn test_fixed_to_der_basic() {
    // P-256 fixed signature (64 bytes total)
    let mut fixed = vec![];
    
    // r component (32 bytes)
    fixed.extend((1..=32).collect::<Vec<u8>>());
    
    // s component (32 bytes)
    fixed.extend((33..=64).collect::<Vec<u8>>());
    
    let result = fixed_to_der(&fixed);
    assert!(result.is_ok());
    
    let der = result.unwrap();
    
    // Should start with SEQUENCE tag
    assert_eq!(der[0], 0x30);
    
    // Should contain two INTEGER tags
    assert!(der.contains(&0x02));
    
    // Convert back to verify
    let roundtrip = der_to_fixed(&der, 64).unwrap();
    assert_eq!(roundtrip, fixed);
}

#[test]
fn test_fixed_to_der_with_high_bit_set() {
    // Fixed signature where r has high bit set (needs padding in DER)
    let mut fixed = vec![];
    
    // r component with high bit set
    let mut r = vec![0x80]; // High bit set
    r.extend(vec![0x00; 31]);
    fixed.extend(r);
    
    // s component normal
    fixed.extend((1..=32).collect::<Vec<u8>>());
    
    let result = fixed_to_der(&fixed);
    assert!(result.is_ok());
    
    let der = result.unwrap();
    
    // Verify roundtrip
    let roundtrip = der_to_fixed(&der, 64).unwrap();
    assert_eq!(roundtrip, fixed);
}

#[test]
fn test_fixed_to_der_leading_zeros() {
    // Fixed signature with leading zeros
    let mut fixed = vec![];
    
    // r component with leading zeros
    let mut r = vec![0x00, 0x00, 0x00, 0x42];
    r.extend(vec![0x00; 28]);
    fixed.extend(r);
    
    // s component with leading zeros
    let mut s = vec![0x00, 0x00, 0x43];
    s.extend(vec![0x00; 29]);
    fixed.extend(s);
    
    let result = fixed_to_der(&fixed);
    assert!(result.is_ok());
    
    let der = result.unwrap();
    
    // Convert back and check roundtrip
    let roundtrip = der_to_fixed(&der, 64).unwrap();
    assert_eq!(roundtrip, fixed);
}

#[test]
fn test_der_to_fixed_invalid_der() {
    // Invalid DER - doesn't start with SEQUENCE
    let invalid_der = vec![0x31, 0x10, 0x02, 0x01, 0x42, 0x02, 0x01, 0x43];
    let result = der_to_fixed(&invalid_der, 64);
    assert!(result.is_err());
    
    // Invalid DER - truncated
    let truncated_der = vec![0x30, 0x10]; // Claims length 16 but only 2 bytes total
    let result = der_to_fixed(&truncated_der, 64);
    assert!(result.is_err());
    
    // Invalid DER - empty
    let empty_der: Vec<u8> = vec![];
    let result = der_to_fixed(&empty_der, 64);
    assert!(result.is_err());
}

#[test]
fn test_fixed_to_der_invalid_length() {
    // Fixed signature with odd length
    let invalid_fixed = vec![0x42; 63]; // Should be even
    let result = fixed_to_der(&invalid_fixed);
    assert!(result.is_err());
}

#[test]
fn test_roundtrip_conversions() {
    // Test various fixed signatures roundtrip correctly
    let test_cases = vec![
        // All zeros
        vec![0x00; 64],
        // All ones
        vec![0x01; 64],
        // All max values
        vec![0xFF; 64],
        // Mixed values
        (0..64).collect(),
        // High bit patterns
        {
            let mut v = vec![0x80; 32];
            v.extend(vec![0x7F; 32]);
            v
        },
    ];
    
    for fixed_orig in test_cases {
        let der = fixed_to_der(&fixed_orig).unwrap();
        let fixed_converted = der_to_fixed(&der, 64).unwrap();
        assert_eq!(fixed_orig, fixed_converted);
    }
}

#[test]
fn test_different_curve_sizes() {
    // P-256 (64 bytes)
    let p256_fixed = vec![0x42; 64];
    let der = fixed_to_der(&p256_fixed).unwrap();
    let roundtrip = der_to_fixed(&der, 64).unwrap();
    assert_eq!(p256_fixed, roundtrip);
    
    // P-384 (96 bytes)
    let p384_fixed = vec![0x42; 96];
    let der = fixed_to_der(&p384_fixed).unwrap();
    let roundtrip = der_to_fixed(&der, 96).unwrap();
    assert_eq!(p384_fixed, roundtrip);
    
    // P-521 (132 bytes)
    let p521_fixed = vec![0x42; 132];
    let der = fixed_to_der(&p521_fixed).unwrap();
    let roundtrip = der_to_fixed(&der, 132).unwrap();
    assert_eq!(p521_fixed, roundtrip);
}

#[test]
fn test_malformed_der_structures() {
    // DER with wrong INTEGER count (only one INTEGER instead of two)
    let wrong_int_count = vec![
        0x30, 0x08, // SEQUENCE
        0x02, 0x04, 0x01, 0x02, 0x03, 0x04, // Only one INTEGER
    ];
    let result = der_to_fixed(&wrong_int_count, 64);
    assert!(result.is_err());
    
    // DER with non-INTEGER in sequence
    let non_integer = vec![
        0x30, 0x08, // SEQUENCE
        0x04, 0x01, 0x42, // OCTET STRING instead of INTEGER
        0x02, 0x01, 0x43, // INTEGER
    ];
    let result = der_to_fixed(&non_integer, 64);
    assert!(result.is_err());
    
    // DER with incorrect length encoding
    let wrong_length = vec![
        0x30, 0xFF, // SEQUENCE with impossible length
        0x02, 0x01, 0x42,
        0x02, 0x01, 0x43,
    ];
    let result = der_to_fixed(&wrong_length, 64);
    assert!(result.is_err());
}
