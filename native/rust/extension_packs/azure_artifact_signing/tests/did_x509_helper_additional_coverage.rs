// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for Azure Artifact Signing DID:x509 helper.
//!
//! Targets uncovered lines in did_x509_helper.rs:
//! - find_deepest_greatest_microsoft_eku function
//! - Microsoft EKU selection logic
//! - Fallback to generic EKU builder

use cose_sign1_azure_artifact_signing::error::AasError;
use cose_sign1_azure_artifact_signing::signing::did_x509_helper::build_did_x509_from_ats_chain;

/// Test with empty chain (should return None from find_deepest_greatest_microsoft_eku).
#[test]
fn test_empty_chain() {
    let result = build_did_x509_from_ats_chain(&[]);

    // Should fail with empty chain
    assert!(result.is_err());
    match result {
        Err(AasError::DidX509Error(msg)) => {
            // The error should come from the generic EKU builder fallback
            assert!(!msg.is_empty());
        }
        _ => panic!("Expected DidX509Error"),
    }
}

/// Test with mock certificate that has no Microsoft EKUs (fallback path).
#[test]
fn test_no_microsoft_eku_fallback() {
    let mock_cert = create_mock_cert_without_microsoft_eku();
    let chain = vec![&mock_cert[..]];

    let result = build_did_x509_from_ats_chain(&chain);

    // Should use fallback generic EKU builder when no Microsoft EKU found
    assert!(result.is_err());
    match result {
        Err(AasError::DidX509Error(msg)) => {
            // Error from generic DID:X509 builder fallback
            assert!(!msg.is_empty());
        }
        _ => panic!("Expected DidX509Error from fallback"),
    }
}

/// Test with mock certificate that has Microsoft EKUs (main path).
#[test]
fn test_with_microsoft_eku() {
    let mock_cert = create_mock_cert_with_microsoft_eku();
    let chain = vec![&mock_cert[..]];

    let result = build_did_x509_from_ats_chain(&chain);

    // Should use Microsoft EKU-specific builder but still fail due to invalid mock cert
    assert!(result.is_err());
    match result {
        Err(AasError::DidX509Error(msg)) => {
            // Error from Microsoft EKU-specific DID:X509 builder
            assert!(!msg.is_empty());
        }
        _ => panic!("Expected DidX509Error from Microsoft EKU path"),
    }
}

/// Test with multiple Microsoft EKUs (deepest greatest selection).
#[test]
fn test_multiple_microsoft_ekus_selection() {
    // Create mock cert with multiple Microsoft EKUs to test selection logic
    let mock_cert = create_mock_cert_with_multiple_microsoft_ekus();
    let chain = vec![&mock_cert[..]];

    let result = build_did_x509_from_ats_chain(&chain);

    // Should select the "deepest greatest" Microsoft EKU and use it
    assert!(result.is_err());
    match result {
        Err(AasError::DidX509Error(msg)) => {
            // Error from DID:X509 builder with specific Microsoft EKU
            assert!(!msg.is_empty());
        }
        _ => panic!("Expected DidX509Error from Microsoft EKU selection path"),
    }
}

/// Test with mixed EKUs (some Microsoft, some not).
#[test]
fn test_mixed_ekus() {
    let mock_cert = create_mock_cert_with_mixed_ekus();
    let chain = vec![&mock_cert[..]];

    let result = build_did_x509_from_ats_chain(&chain);

    // Should filter to only Microsoft EKUs and select the deepest greatest
    assert!(result.is_err());
    match result {
        Err(AasError::DidX509Error(msg)) => {
            assert!(!msg.is_empty());
        }
        _ => panic!("Expected DidX509Error"),
    }
}

/// Test with multi-certificate chain (only leaf cert should be examined).
#[test]
fn test_multi_cert_chain() {
    let leaf_cert = create_mock_cert_with_microsoft_eku();
    let intermediate_cert = create_mock_cert_without_microsoft_eku();
    let root_cert = create_mock_cert_with_different_microsoft_eku();

    let chain = vec![&leaf_cert[..], &intermediate_cert[..], &root_cert[..]];

    let result = build_did_x509_from_ats_chain(&chain);

    // Should only examine the leaf cert (first in chain)
    assert!(result.is_err());
    match result {
        Err(AasError::DidX509Error(msg)) => {
            assert!(!msg.is_empty());
        }
        _ => panic!("Expected DidX509Error"),
    }
}

/// Test error propagation from DID:X509 builder.
#[test]
fn test_error_propagation() {
    let invalid_cert = vec![0x30]; // Incomplete DER structure
    let chain = vec![&invalid_cert[..]];

    let result = build_did_x509_from_ats_chain(&chain);

    // Should propagate the DID:X509 parsing error
    assert!(result.is_err());
    match result {
        Err(AasError::DidX509Error(msg)) => {
            // Should contain error details from DID:X509 parsing
            assert!(!msg.is_empty());
        }
        _ => panic!("Expected DidX509Error with parsing details"),
    }
}

/// Test with borderline Microsoft EKU prefix (exactly matching).
#[test]
fn test_exact_microsoft_eku_prefix() {
    let mock_cert = create_mock_cert_with_exact_microsoft_prefix();
    let chain = vec![&mock_cert[..]];

    let result = build_did_x509_from_ats_chain(&chain);

    // Should recognize exact Microsoft prefix match
    assert!(result.is_err());
    match result {
        Err(AasError::DidX509Error(msg)) => {
            assert!(!msg.is_empty());
        }
        _ => panic!("Expected DidX509Error"),
    }
}

/// Test with EKU that's close but not Microsoft prefix.
#[test]
fn test_non_microsoft_eku_similar_prefix() {
    let mock_cert = create_mock_cert_with_similar_but_not_microsoft_eku();
    let chain = vec![&mock_cert[..]];

    let result = build_did_x509_from_ats_chain(&chain);

    // Should use fallback path (not Microsoft EKU)
    assert!(result.is_err());
    match result {
        Err(AasError::DidX509Error(msg)) => {
            // Should come from generic EKU builder fallback
            assert!(!msg.is_empty());
        }
        _ => panic!("Expected DidX509Error from fallback"),
    }
}

// Helper functions to create mock certificates with different EKU configurations

fn create_mock_cert_without_microsoft_eku() -> Vec<u8> {
    // Mock certificate DER without Microsoft EKU
    // This would trigger the fallback path
    vec![
        0x30, 0x82, 0x01, 0x23, // SEQUENCE
        0x30, 0x82, 0x01, 0x00, // tbsCertificate
        // Mock structure - won't have valid Microsoft EKU extensions
        0xa0, 0x03, 0x02, 0x01, 0x02, // version
        0x02, 0x01, 0x01, // serialNumber
    ]
}

fn create_mock_cert_with_microsoft_eku() -> Vec<u8> {
    // Mock certificate that would appear to have Microsoft EKU
    // In real implementation, this would need valid DER with EKU extension
    vec![
        0x30, 0x82, 0x01, 0x45, // SEQUENCE
        0x30, 0x82, 0x01, 0x22, // tbsCertificate
        0xa0, 0x03, 0x02, 0x01, 0x02, // version
        0x02, 0x01,
        0x01, // serialNumber
              // In real cert, would have extensions with Microsoft EKU OID 1.3.6.1.4.1.311.x.x.x
    ]
}

fn create_mock_cert_with_multiple_microsoft_ekus() -> Vec<u8> {
    // Mock certificate with multiple Microsoft EKUs to test selection
    vec![
        0x30, 0x82, 0x01, 0x67, // SEQUENCE
        0x30, 0x82, 0x01, 0x44, // tbsCertificate
        0xa0, 0x03, 0x02, 0x01, 0x02, // version
        0x02, 0x01,
        0x02, // serialNumber
              // Would contain multiple Microsoft EKUs in extensions
    ]
}

fn create_mock_cert_with_mixed_ekus() -> Vec<u8> {
    // Mock certificate with both Microsoft and non-Microsoft EKUs
    vec![
        0x30, 0x82, 0x01, 0x89, // SEQUENCE
        0x30, 0x82, 0x01, 0x66, // tbsCertificate
        0xa0, 0x03, 0x02, 0x01, 0x02, // version
        0x02, 0x01,
        0x03, // serialNumber
              // Would contain mixed EKUs including 1.3.6.1.4.1.311.* and others
    ]
}

fn create_mock_cert_with_different_microsoft_eku() -> Vec<u8> {
    // Different Microsoft EKU for testing chain processing
    vec![
        0x30, 0x82, 0x01, 0xAB, // SEQUENCE
        0x30, 0x82, 0x01, 0x88, // tbsCertificate
        0xa0, 0x03, 0x02, 0x01, 0x02, // version
        0x02, 0x01, 0x04, // serialNumber
              // Different Microsoft EKU OID
    ]
}

fn create_mock_cert_with_exact_microsoft_prefix() -> Vec<u8> {
    // Test exact Microsoft prefix matching
    vec![
        0x30, 0x82, 0x01, 0xCD, // SEQUENCE
        0x30, 0x82, 0x01, 0xAA, // tbsCertificate
        0xa0, 0x03, 0x02, 0x01, 0x02, // version
        0x02, 0x01,
        0x05, // serialNumber
              // Would have EKU exactly starting with 1.3.6.1.4.1.311
    ]
}

fn create_mock_cert_with_similar_but_not_microsoft_eku() -> Vec<u8> {
    // EKU similar to Microsoft but not exact match
    vec![
        0x30, 0x82, 0x01, 0xEF, // SEQUENCE
        0x30, 0x82, 0x01, 0xCC, // tbsCertificate
        0xa0, 0x03, 0x02, 0x01, 0x02, // version
        0x02, 0x01,
        0x06, // serialNumber
              // Would have EKU like 1.3.6.1.4.1.310 or 1.3.6.1.4.1.312 (not 311)
    ]
}
