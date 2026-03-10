// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for CWT claims builder functionality.

use cose_sign1_headers::cwt_claims::{CwtClaims, CwtClaimValue};

#[test]
fn test_cwt_claims_empty_creation() {
    let claims = CwtClaims::new();
    
    // Empty claims should have all fields as None
    assert!(claims.issuer.is_none());
    assert!(claims.subject.is_none());
    assert!(claims.audience.is_none());
    assert!(claims.issued_at.is_none());
    assert!(claims.not_before.is_none());
    assert!(claims.expiration_time.is_none());
    assert!(claims.cwt_id.is_none());
    assert!(claims.custom_claims.is_empty());
}

#[test]
fn test_cwt_claims_to_cbor_bytes_empty() {
    let claims = CwtClaims::new();
    
    // Empty claims should serialize successfully
    let result = claims.to_cbor_bytes();
    assert!(result.is_ok(), "Empty claims CBOR encoding should succeed");
    
    let cbor_bytes = result.unwrap();
    assert!(!cbor_bytes.is_empty(), "CBOR bytes should not be empty");
}

#[test]
fn test_cwt_claims_builder_pattern() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("https://example.com".to_string());
    claims.subject = Some("user123".to_string());
    claims.audience = Some("audience1".to_string());
    claims.issued_at = Some(1640995200); // 2022-01-01 00:00:00 UTC
    claims.not_before = Some(1640995200);
    claims.expiration_time = Some(1672531200); // 2023-01-01 00:00:00 UTC
    claims.cwt_id = Some(b"cwt-id-123".to_vec());
    
    // Verify all fields are set correctly
    assert_eq!(claims.issuer, Some("https://example.com".to_string()));
    assert_eq!(claims.subject, Some("user123".to_string()));
    assert_eq!(claims.audience, Some("audience1".to_string()));
    assert_eq!(claims.issued_at, Some(1640995200));
    assert_eq!(claims.not_before, Some(1640995200));
    assert_eq!(claims.expiration_time, Some(1672531200));
    assert_eq!(claims.cwt_id, Some(b"cwt-id-123".to_vec()));
}

#[test]
fn test_cwt_claims_to_cbor_bytes_full() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("https://issuer.example".to_string());
    claims.subject = Some("subject-123".to_string());
    claims.audience = Some("audience-456".to_string());
    claims.issued_at = Some(1640995200);
    claims.not_before = Some(1640995200);
    claims.expiration_time = Some(1672531200);
    claims.cwt_id = Some(b"unique-cwt-id".to_vec());
    
    // Encode to CBOR
    let result = claims.to_cbor_bytes();
    assert!(result.is_ok(), "Full claims CBOR encoding should succeed");
    
    let cbor_bytes = result.unwrap();
    assert!(!cbor_bytes.is_empty(), "CBOR bytes should not be empty");
    assert!(cbor_bytes.len() > 10, "CBOR bytes should contain substantial data");
}

#[test]
fn test_cwt_claims_partial_fields() {
    // Test with only some claims set
    let mut claims = CwtClaims::new();
    claims.issuer = Some("https://partial.example".to_string());
    claims.expiration_time = Some(1672531200);
    
    let result = claims.to_cbor_bytes();
    assert!(result.is_ok(), "Partial claims CBOR encoding should succeed");
    
    let cbor_bytes = result.unwrap();
    assert!(!cbor_bytes.is_empty(), "Partial CBOR bytes should not be empty");
}

#[test]
fn test_cwt_claims_with_custom_claims() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("https://example.com".to_string());
    
    // Add custom string claim
    claims.custom_claims.insert(100, CwtClaimValue::Text("custom-value".to_string()));
    
    // Add custom number claim
    claims.custom_claims.insert(101, CwtClaimValue::Integer(42));
    
    // Add custom boolean claim
    claims.custom_claims.insert(102, CwtClaimValue::Bool(true));
    
    // Add custom bytes claim
    claims.custom_claims.insert(103, CwtClaimValue::Bytes(b"binary-data".to_vec()));
    
    // Test CBOR encoding with custom claims
    let result = claims.to_cbor_bytes();
    if let Err(ref e) = result {
        eprintln!("CBOR encoding failed: {:?}", e);
    }
    assert!(result.is_ok(), "Claims with custom values should encode successfully");
    
    // Verify standard claims
    assert_eq!(claims.issuer, Some("https://example.com".to_string()));
    
    // Verify custom claims
    assert_eq!(claims.custom_claims.len(), 4);
    assert_eq!(claims.custom_claims.get(&100), Some(&CwtClaimValue::Text("custom-value".to_string())));
    assert_eq!(claims.custom_claims.get(&101), Some(&CwtClaimValue::Integer(42)));
    assert_eq!(claims.custom_claims.get(&102), Some(&CwtClaimValue::Bool(true)));
    assert_eq!(claims.custom_claims.get(&103), Some(&CwtClaimValue::Bytes(b"binary-data".to_vec())));
}

#[test]
fn test_cwt_claims_edge_cases() {
    // Test empty string values
    let mut claims = CwtClaims::new();
    claims.issuer = Some("".to_string());
    claims.subject = Some("".to_string());
    claims.audience = Some("".to_string());
    
    let result = claims.to_cbor_bytes();
    assert!(result.is_ok(), "Empty string claims should encode successfully");
    
    // Test empty CWT ID
    claims.cwt_id = Some(Vec::new());
    let result = claims.to_cbor_bytes();
    assert!(result.is_ok(), "Empty CWT ID should encode successfully");
}

#[test]
fn test_cwt_claims_boundary_times() {
    // Test with Unix epoch timestamps
    let mut claims = CwtClaims::new();
    claims.issued_at = Some(0);
    claims.not_before = Some(0);
    claims.expiration_time = Some(0);
    
    let result = claims.to_cbor_bytes();
    assert!(result.is_ok(), "Epoch timestamp claims should encode successfully");
    
    // Test with maximum i64 timestamp
    let mut max_claims = CwtClaims::new();
    max_claims.issued_at = Some(i64::MAX);
    max_claims.not_before = Some(i64::MAX);
    max_claims.expiration_time = Some(i64::MAX);
    
    let result = max_claims.to_cbor_bytes();
    assert!(result.is_ok(), "Max timestamp claims should encode successfully");
}

#[test]
fn test_cwt_claims_large_custom_data() {
    let mut claims = CwtClaims::new();
    
    // Add large string custom claim
    let large_string = "x".repeat(10000);
    claims.custom_claims.insert(200, CwtClaimValue::Text(large_string.clone()));
    
    // Add large binary custom claim
    let large_binary = vec![0x42; 5000];
    claims.custom_claims.insert(201, CwtClaimValue::Bytes(large_binary.clone()));
    
    // Test encoding with large data
    let result = claims.to_cbor_bytes();
    assert!(result.is_ok(), "Large custom claims should encode successfully");
    
    // Verify data integrity
    assert_eq!(claims.custom_claims.get(&200), Some(&CwtClaimValue::Text(large_string)));
    assert_eq!(claims.custom_claims.get(&201), Some(&CwtClaimValue::Bytes(large_binary)));
}

#[test]
fn test_cwt_claims_unicode_strings() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("https://例え.テスト".to_string());
    claims.subject = Some("用户123".to_string());
    claims.audience = Some("👥🔒🌍".to_string());
    
    let result = claims.to_cbor_bytes();
    assert!(result.is_ok(), "Unicode string claims should encode successfully");
    
    assert_eq!(claims.issuer, Some("https://例え.テスト".to_string()));
    assert_eq!(claims.subject, Some("用户123".to_string()));
    assert_eq!(claims.audience, Some("👥🔒🌍".to_string()));
}

#[test]
fn test_cwt_claims_binary_id() {
    // Test various binary patterns in CWT ID
    let binary_patterns = vec![
        vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC], // Mixed binary
        vec![0x00; 32], // All zeros
        vec![0xFF; 32], // All ones
        (0u8..=255u8).collect(), // Full byte range
        vec![0xDE, 0xAD, 0xBE, 0xEF], // Common hex pattern
    ];
    
    for (i, pattern) in binary_patterns.iter().enumerate() {
        let mut claims = CwtClaims::new();
        claims.cwt_id = Some(pattern.clone());
        
        let result = claims.to_cbor_bytes();
        assert!(result.is_ok(), "Binary pattern {} should encode successfully", i);
        
        assert_eq!(claims.cwt_id, Some(pattern.clone()), "Binary pattern {} should be preserved", i);
    }
}

#[test]
fn test_cwt_claims_claim_key_ranges() {
    // Test various custom claim key ranges
    let mut claims = CwtClaims::new();
    
    // Positive keys
    claims.custom_claims.insert(1000, CwtClaimValue::Text("positive".to_string()));
    claims.custom_claims.insert(i64::MAX, CwtClaimValue::Integer(42));
    
    // Negative keys
    claims.custom_claims.insert(-1, CwtClaimValue::Bool(true));
    claims.custom_claims.insert(i64::MIN, CwtClaimValue::Integer(42));
    
    // Zero key
    claims.custom_claims.insert(0, CwtClaimValue::Bytes(b"zero".to_vec()));
    
    let result = claims.to_cbor_bytes();
    if let Err(ref e) = result {
        eprintln!("CBOR encoding failed: {:?}", e);
    }
    assert!(result.is_ok(), "Various claim key ranges should encode successfully");
    
    assert_eq!(claims.custom_claims.len(), 5);
}

#[test]
fn test_cwt_claims_serialization_deterministic() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("https://issuer.example".to_string());
    claims.subject = Some("subject".to_string());
    claims.audience = Some("audience".to_string());
    claims.issued_at = Some(1640995200);
    claims.not_before = Some(1640995200);
    claims.expiration_time = Some(1672531200);
    claims.cwt_id = Some(b"cwt-id".to_vec());
    
    // Encode multiple times
    let bytes1 = claims.to_cbor_bytes().unwrap();
    let bytes2 = claims.to_cbor_bytes().unwrap();
    
    // Should produce identical results
    assert_eq!(bytes1, bytes2, "CBOR encoding should be deterministic");
}

#[test]
fn test_cwt_claims_clone_and_modify() {
    let mut original = CwtClaims::new();
    original.issuer = Some("https://original.example".to_string());
    original.subject = Some("original-subject".to_string());
    
    let mut modified = original.clone();
    modified.issuer = Some("https://modified.example".to_string());
    modified.audience = Some("new-audience".to_string());
    
    // Original should remain unchanged
    assert_eq!(original.issuer, Some("https://original.example".to_string()));
    assert_eq!(original.subject, Some("original-subject".to_string()));
    assert!(original.audience.is_none());
    
    // Modified should have changes
    assert_eq!(modified.issuer, Some("https://modified.example".to_string()));
    assert_eq!(modified.subject, Some("original-subject".to_string()));
    assert_eq!(modified.audience, Some("new-audience".to_string()));
}

#[test]
fn test_cwt_claims_debug_display() {
    let mut claims = CwtClaims::new();
    claims.issuer = Some("https://debug.example".to_string());
    claims.subject = Some("debug-subject".to_string());
    
    let debug_string = format!("{:?}", claims);
    assert!(debug_string.contains("issuer"));
    assert!(debug_string.contains("debug.example"));
    assert!(debug_string.contains("subject"));
    assert!(debug_string.contains("debug-subject"));
}

#[test]
fn test_cwt_claims_default_subject() {
    // Verify the default subject constant
    assert_eq!(CwtClaims::DEFAULT_SUBJECT, "unknown.intent");
    
    let mut claims = CwtClaims::new();
    claims.subject = Some(CwtClaims::DEFAULT_SUBJECT.to_string());
    
    let result = claims.to_cbor_bytes();
    assert!(result.is_ok(), "Default subject should encode successfully");
    
    assert_eq!(claims.subject, Some("unknown.intent".to_string()));
}

#[test]
fn test_cwt_claim_value_types() {
    // Test all CwtClaimValue enum variants (except Float which isn't supported by CBOR encoder)
    let text_value = CwtClaimValue::Text("hello".to_string());
    let int_value = CwtClaimValue::Integer(42);
    let bytes_value = CwtClaimValue::Bytes(b"binary".to_vec());
    let bool_value = CwtClaimValue::Bool(true);
    
    // Test clone and debug
    let cloned_text = text_value.clone();
    assert_eq!(text_value, cloned_text);
    
    let debug_str = format!("{:?}", int_value);
    assert!(debug_str.contains("Integer"));
    assert!(debug_str.contains("42"));
    
    // Test all variants work
    assert_eq!(text_value, CwtClaimValue::Text("hello".to_string()));
    assert_eq!(int_value, CwtClaimValue::Integer(42));
    assert_eq!(bytes_value, CwtClaimValue::Bytes(b"binary".to_vec()));
    assert_eq!(bool_value, CwtClaimValue::Bool(true));
}

#[test]
fn test_cwt_claims_concurrent_modification() {
    use std::thread;
    use std::sync::{Arc, Mutex};
    
    let claims = Arc::new(Mutex::new(CwtClaims::new()));
    
    let handles: Vec<_> = (0..4).map(|i| {
        let claims = claims.clone();
        thread::spawn(move || {
            let mut claims = claims.lock().unwrap();
            claims.custom_claims.insert(i, CwtClaimValue::Integer(i));
        })
    }).collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    let final_claims = claims.lock().unwrap();
    assert_eq!(final_claims.custom_claims.len(), 4);
    
    for i in 0..4 {
        assert_eq!(final_claims.custom_claims.get(&i), Some(&CwtClaimValue::Integer(i)));
    }
}

#[test]
fn test_cwt_claims_memory_efficiency() {
    // Test that empty claims don't take excessive memory
    let empty_claims = CwtClaims::new();
    let size = std::mem::size_of_val(&empty_claims);
    
    // Should be reasonable for the struct size
    assert!(size < 1000, "Empty claims should not take excessive memory");
    
    // Test with many custom claims
    let mut large_claims = CwtClaims::new();
    for i in 0..100 {
        large_claims.custom_claims.insert(i, CwtClaimValue::Integer(i));
    }
    
    assert_eq!(large_claims.custom_claims.len(), 100);
    
    // Should still encode successfully
    let result = large_claims.to_cbor_bytes();
    assert!(result.is_ok(), "Large claims should encode successfully");
}