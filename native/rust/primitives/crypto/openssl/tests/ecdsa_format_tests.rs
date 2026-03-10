// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for ECDSA signature format conversion.

use cose_sign1_crypto_openssl::ecdsa_format;

#[test]
fn test_der_to_fixed_es256() {
    // DER signature: SEQUENCE { INTEGER r, INTEGER s }
    // For simplicity, using known values
    let r_bytes = vec![0x01; 32];
    let s_bytes = vec![0x02; 32];
    
    // Construct minimal DER signature
    let mut der_sig = vec![
        0x30, // SEQUENCE tag
        0x44, // Length: 68 bytes (2 + 32 + 2 + 32)
        0x02, // INTEGER tag
        0x20, // Length: 32 bytes
    ];
    der_sig.extend_from_slice(&r_bytes);
    der_sig.push(0x02); // INTEGER tag
    der_sig.push(0x20); // Length: 32 bytes
    der_sig.extend_from_slice(&s_bytes);
    
    // Convert to fixed format
    let result = ecdsa_format::der_to_fixed(&der_sig, 64);
    assert!(result.is_ok());
    
    let fixed_sig = result.unwrap();
    assert_eq!(fixed_sig.len(), 64);
    assert_eq!(&fixed_sig[0..32], &r_bytes[..]);
    assert_eq!(&fixed_sig[32..64], &s_bytes[..]);
}

#[test]
fn test_fixed_to_der() {
    // Fixed-length signature (r || s)
    let mut fixed_sig = vec![0x01; 32];
    fixed_sig.extend_from_slice(&vec![0x02; 32]);
    
    // Convert to DER
    let result = ecdsa_format::fixed_to_der(&fixed_sig);
    assert!(result.is_ok());
    
    let der_sig = result.unwrap();
    
    // Verify it's a valid SEQUENCE
    assert_eq!(der_sig[0], 0x30); // SEQUENCE tag
    
    // Should contain two INTEGERs
    let total_len = der_sig[1] as usize;
    assert!(total_len > 0);
    assert_eq!(der_sig.len(), 2 + total_len);
}

#[test]
fn test_der_to_fixed_with_leading_zero() {
    // DER encodes positive integers with a leading 0x00 if high bit is set
    let r_bytes = vec![0x00, 0x80, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 
                       0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let s_bytes = vec![0x00, 0x90, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 
                       0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    
    let mut der_sig = vec![
        0x30, // SEQUENCE
        0x46, // Length: 70 bytes
        0x02, // INTEGER
        0x21, // Length: 33 bytes (with leading 0x00)
    ];
    der_sig.extend_from_slice(&r_bytes);
    der_sig.push(0x02); // INTEGER
    der_sig.push(0x21); // Length: 33 bytes
    der_sig.extend_from_slice(&s_bytes);
    
    let result = ecdsa_format::der_to_fixed(&der_sig, 64);
    assert!(result.is_ok());
    
    let fixed_sig = result.unwrap();
    assert_eq!(fixed_sig.len(), 64);
    
    // Should have stripped the leading 0x00 from both r and s
    assert_eq!(fixed_sig[0], 0x80);
    assert_eq!(fixed_sig[32], 0x90);
}

#[test]
fn test_round_trip_conversion() {
    // Start with a fixed-length signature
    let mut original_fixed = vec![0xaa; 32];
    original_fixed.extend_from_slice(&vec![0xbb; 32]);
    
    // Convert to DER
    let der_sig = ecdsa_format::fixed_to_der(&original_fixed).unwrap();
    
    // Convert back to fixed
    let recovered_fixed = ecdsa_format::der_to_fixed(&der_sig, 64).unwrap();
    
    assert_eq!(original_fixed, recovered_fixed);
}

#[test]
fn test_der_to_fixed_invalid_sequence_tag() {
    // Wrong tag (0x31 instead of 0x30), with enough bytes (8+) to pass length check
    let der_sig = vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
    let result = ecdsa_format::der_to_fixed(&der_sig, 64);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("SEQUENCE"));
}

#[test]
fn test_der_to_fixed_too_short() {
    let der_sig = vec![0x30, 0x02]; // Too short to be valid
    let result = ecdsa_format::der_to_fixed(&der_sig, 64);
    assert!(result.is_err());
}

#[test]
fn test_fixed_to_der_odd_length() {
    let fixed_sig = vec![0x01; 33]; // Odd length (invalid)
    let result = ecdsa_format::fixed_to_der(&fixed_sig);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("even"));
}
