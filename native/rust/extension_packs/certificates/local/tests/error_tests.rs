// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CertLocalError.

use cose_sign1_certificates_local::error::CertLocalError;
use crypto_primitives::CryptoError;

#[test]
fn test_key_generation_failed_display() {
    let error = CertLocalError::KeyGenerationFailed("RSA key generation failed".to_string());
    let display_str = format!("{}", error);
    assert_eq!(display_str, "key generation failed: RSA key generation failed");
}

#[test]
fn test_certificate_creation_failed_display() {
    let error = CertLocalError::CertificateCreationFailed("X.509 encoding failed".to_string());
    let display_str = format!("{}", error);
    assert_eq!(display_str, "certificate creation failed: X.509 encoding failed");
}

#[test]
fn test_invalid_options_display() {
    let error = CertLocalError::InvalidOptions("Missing subject name".to_string());
    let display_str = format!("{}", error);
    assert_eq!(display_str, "invalid options: Missing subject name");
}

#[test]
fn test_unsupported_algorithm_display() {
    let error = CertLocalError::UnsupportedAlgorithm("DSA not supported".to_string());
    let display_str = format!("{}", error);
    assert_eq!(display_str, "unsupported algorithm: DSA not supported");
}

#[test]
fn test_io_error_display() {
    let error = CertLocalError::IoError("File not found: cert.pem".to_string());
    let display_str = format!("{}", error);
    assert_eq!(display_str, "I/O error: File not found: cert.pem");
}

#[test]
fn test_load_failed_display() {
    let error = CertLocalError::LoadFailed("Invalid PFX format".to_string());
    let display_str = format!("{}", error);
    assert_eq!(display_str, "load failed: Invalid PFX format");
}

#[test]
fn test_error_trait_implementation() {
    let error = CertLocalError::KeyGenerationFailed("test error".to_string());
    
    // Test that it implements std::error::Error
    let error_trait: &dyn std::error::Error = &error;
    assert_eq!(error_trait.to_string(), "key generation failed: test error");
    
    // Test source() returns None (no nested errors in our implementation)
    assert!(error_trait.source().is_none());
}

#[test]
fn test_debug_implementation() {
    let error = CertLocalError::CertificateCreationFailed("debug test".to_string());
    let debug_str = format!("{:?}", error);
    assert!(debug_str.contains("CertificateCreationFailed"));
    assert!(debug_str.contains("debug test"));
}

#[test]
fn test_from_crypto_error_signing_failed() {
    let crypto_error = CryptoError::SigningFailed("ECDSA signing failed".to_string());
    let cert_error: CertLocalError = crypto_error.into();
    
    match cert_error {
        CertLocalError::KeyGenerationFailed(msg) => {
            assert!(msg.contains("ECDSA signing failed"));
        }
        _ => panic!("Expected KeyGenerationFailed variant"),
    }
}

#[test]
fn test_from_crypto_error_invalid_key() {
    let crypto_error = CryptoError::InvalidKey("RSA key too small".to_string());
    let cert_error: CertLocalError = crypto_error.into();
    
    match cert_error {
        CertLocalError::KeyGenerationFailed(msg) => {
            assert!(msg.contains("RSA key too small"));
        }
        _ => panic!("Expected KeyGenerationFailed variant"),
    }
}

#[test]
fn test_from_crypto_error_unsupported_algorithm() {
    let crypto_error = CryptoError::UnsupportedAlgorithm(-7); // ES256 algorithm ID
    let cert_error: CertLocalError = crypto_error.into();
    
    match cert_error {
        CertLocalError::KeyGenerationFailed(msg) => {
            assert!(msg.contains("unsupported algorithm: -7"));
        }
        _ => panic!("Expected KeyGenerationFailed variant"),
    }
}

#[test]
fn test_from_crypto_error_verification_failed() {
    let crypto_error = CryptoError::VerificationFailed("Invalid signature".to_string());
    let cert_error: CertLocalError = crypto_error.into();
    
    match cert_error {
        CertLocalError::KeyGenerationFailed(msg) => {
            assert!(msg.contains("Invalid signature"));
        }
        _ => panic!("Expected KeyGenerationFailed variant"),
    }
}

#[test]
fn test_all_error_variants_display() {
    let errors = vec![
        CertLocalError::KeyGenerationFailed("key gen".to_string()),
        CertLocalError::CertificateCreationFailed("cert create".to_string()),
        CertLocalError::InvalidOptions("invalid opts".to_string()),
        CertLocalError::UnsupportedAlgorithm("unsupported alg".to_string()),
        CertLocalError::IoError("io err".to_string()),
        CertLocalError::LoadFailed("load fail".to_string()),
    ];

    let expected_prefixes = [
        "key generation failed:",
        "certificate creation failed:",
        "invalid options:",
        "unsupported algorithm:",
        "I/O error:",
        "load failed:",
    ];

    for (error, expected_prefix) in errors.iter().zip(expected_prefixes.iter()) {
        let display_str = format!("{}", error);
        assert!(display_str.starts_with(expected_prefix), 
                "Error '{}' should start with '{}'", display_str, expected_prefix);
    }
}

#[test]
fn test_error_variants_with_empty_message() {
    let errors = vec![
        CertLocalError::KeyGenerationFailed(String::new()),
        CertLocalError::CertificateCreationFailed(String::new()),
        CertLocalError::InvalidOptions(String::new()),
        CertLocalError::UnsupportedAlgorithm(String::new()),
        CertLocalError::IoError(String::new()),
        CertLocalError::LoadFailed(String::new()),
    ];

    // All should display without panicking, even with empty messages
    for error in errors {
        let display_str = format!("{}", error);
        assert!(!display_str.is_empty());
        assert!(display_str.contains(":"));
    }
}

#[test]
fn test_error_variants_with_special_characters() {
    let special_msg = "Error with special chars: \n\t\r\"'\\";
    let errors = vec![
        CertLocalError::KeyGenerationFailed(special_msg.to_string()),
        CertLocalError::CertificateCreationFailed(special_msg.to_string()),
        CertLocalError::InvalidOptions(special_msg.to_string()),
        CertLocalError::UnsupportedAlgorithm(special_msg.to_string()),
        CertLocalError::IoError(special_msg.to_string()),
        CertLocalError::LoadFailed(special_msg.to_string()),
    ];

    // All should handle special characters without issues
    for error in errors {
        let display_str = format!("{}", error);
        assert!(display_str.contains(special_msg));
    }
}

#[test]
fn test_error_send_sync_traits() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    
    assert_send::<CertLocalError>();
    assert_sync::<CertLocalError>();
}

#[test]
fn test_crypto_error_conversion_chain() {
    // Test that we can convert through the chain: String -> CryptoError -> CertLocalError
    let original_msg = "Original crypto error message";
    let crypto_error = CryptoError::SigningFailed(original_msg.to_string());
    let cert_error: CertLocalError = crypto_error.into();
    
    let final_display = format!("{}", cert_error);
    assert!(final_display.contains(original_msg));
    assert!(final_display.starts_with("key generation failed:"));
}

#[test]
fn test_error_equality_by_display() {
    let error1 = CertLocalError::LoadFailed("same message".to_string());
    let error2 = CertLocalError::LoadFailed("same message".to_string());
    
    // CertLocalError doesn't implement PartialEq, but we can compare via display
    assert_eq!(format!("{}", error1), format!("{}", error2));
    
    let error3 = CertLocalError::LoadFailed("different message".to_string());
    assert_ne!(format!("{}", error1), format!("{}", error3));
}

#[test]
fn test_error_variant_discriminants() {
    // Test that different error variants produce different displays
    let msg = "same message";
    let errors = vec![
        CertLocalError::KeyGenerationFailed(msg.to_string()),
        CertLocalError::CertificateCreationFailed(msg.to_string()),
        CertLocalError::InvalidOptions(msg.to_string()),
        CertLocalError::UnsupportedAlgorithm(msg.to_string()),
        CertLocalError::IoError(msg.to_string()),
        CertLocalError::LoadFailed(msg.to_string()),
    ];

    let displays: Vec<String> = errors.iter().map(|e| format!("{}", e)).collect();
    
    // All displays should be different despite same message
    for i in 0..displays.len() {
        for j in i + 1..displays.len() {
            assert_ne!(displays[i], displays[j], 
                      "Error variants {} and {} should have different displays", i, j);
        }
    }
}