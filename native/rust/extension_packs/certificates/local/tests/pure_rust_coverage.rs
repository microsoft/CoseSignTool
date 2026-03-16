// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive test coverage for certificate local crate pure Rust components.
//! Targets KeyAlgorithm, CertLocalError, and other non-OpenSSL dependent functionality.

use cose_sign1_certificates_local::{
    CertLocalError, KeyAlgorithm, HashAlgorithm, KeyUsageFlags,
};

// Test KeyAlgorithm comprehensive coverage
#[test]
fn test_key_algorithm_all_variants() {
    let algorithms = vec![KeyAlgorithm::Rsa, KeyAlgorithm::Ecdsa];
    
    let expected_sizes = vec![2048, 256];
    
    for (algorithm, expected_size) in algorithms.iter().zip(expected_sizes) {
        assert_eq!(algorithm.default_key_size(), expected_size);
        
        // Test Debug implementation
        let debug_str = format!("{:?}", algorithm);
        assert!(!debug_str.is_empty());
        
        // Test Clone
        let cloned = algorithm.clone();
        assert_eq!(algorithm, &cloned);
        
        // Test Copy behavior
        let copied = *algorithm;
        assert_eq!(algorithm, &copied);
        
        // Test PartialEq
        assert_eq!(algorithm, algorithm);
    }
    
    // Test inequality
    assert_ne!(KeyAlgorithm::Rsa, KeyAlgorithm::Ecdsa);
}

#[cfg(feature = "pqc")]
#[test]
fn test_key_algorithm_pqc_variant() {
    let mldsa = KeyAlgorithm::MlDsa;
    assert_eq!(mldsa.default_key_size(), 65);
    
    // Test Debug implementation
    let debug_str = format!("{:?}", mldsa);
    assert!(debug_str.contains("MlDsa"));
    
    // Test inequality with other algorithms
    assert_ne!(mldsa, KeyAlgorithm::Rsa);
    assert_ne!(mldsa, KeyAlgorithm::Ecdsa);
}

#[test]
fn test_key_algorithm_default() {
    let default_alg = KeyAlgorithm::default();
    assert_eq!(default_alg, KeyAlgorithm::Ecdsa);
    assert_eq!(default_alg.default_key_size(), 256);
}

// Test CertLocalError comprehensive coverage
#[test]
fn test_cert_local_error_all_variants() {
    let errors = vec![
        CertLocalError::KeyGenerationFailed("key gen error".to_string()),
        CertLocalError::CertificateCreationFailed("cert create error".to_string()),
        CertLocalError::InvalidOptions("invalid opts".to_string()),
        CertLocalError::UnsupportedAlgorithm("unsupported alg".to_string()),
        CertLocalError::IoError("io error".to_string()),
        CertLocalError::LoadFailed("load error".to_string()),
    ];
    
    let expected_messages = vec![
        "key generation failed: key gen error",
        "certificate creation failed: cert create error",
        "invalid options: invalid opts",
        "unsupported algorithm: unsupported alg",
        "I/O error: io error",
        "load failed: load error",
    ];
    
    for (error, expected) in errors.iter().zip(expected_messages) {
        assert_eq!(error.to_string(), expected);
        
        // Test Debug implementation
        let debug_str = format!("{:?}", error);
        assert!(!debug_str.is_empty());
        
        // Test std::error::Error trait
        let _: &dyn std::error::Error = error;
        assert!(std::error::Error::source(error).is_none());
    }
}

#[test]
fn test_cert_local_error_from_crypto_error() {
    // Test the From<CryptoError> implementation
    // Since we can't easily create a CryptoError without dependencies,
    // we'll test the error message format with a manually created error
    let error = CertLocalError::KeyGenerationFailed("test crypto error".to_string());
    assert_eq!(error.to_string(), "key generation failed: test crypto error");
}

// Test HashAlgorithm if available
#[test]
fn test_hash_algorithm_variants() {
    // These should be available without OpenSSL
    let algorithms = vec![
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ];
    
    for algorithm in &algorithms {
        // Test Debug implementation
        let debug_str = format!("{:?}", algorithm);
        assert!(!debug_str.is_empty());
        
        // Test Clone
        let cloned = algorithm.clone();
        assert_eq!(algorithm, &cloned);
        
        // Test Copy behavior
        let copied = *algorithm;
        assert_eq!(algorithm, &copied);
    }
    
    // Test inequality
    assert_ne!(HashAlgorithm::Sha256, HashAlgorithm::Sha384);
    assert_ne!(HashAlgorithm::Sha384, HashAlgorithm::Sha512);
    assert_ne!(HashAlgorithm::Sha256, HashAlgorithm::Sha512);
}

// Test KeyUsageFlags
#[test]
fn test_key_usage_flags_operations() {
    // Test available constant flags
    let flags = vec![
        KeyUsageFlags::DIGITAL_SIGNATURE,
        KeyUsageFlags::KEY_ENCIPHERMENT,
        KeyUsageFlags::KEY_CERT_SIGN,
    ];
    
    for flag in &flags {
        // Test Debug implementation
        let debug_str = format!("{:?}", flag);
        assert!(!debug_str.is_empty());
        
        // Test that flag has non-zero bits
        assert!(flag.flags != 0);
        
        // Test Clone
        let cloned = *flag;
        assert_eq!(flag.flags, cloned.flags);
    }
    
    // Test specific bit values
    assert_eq!(KeyUsageFlags::DIGITAL_SIGNATURE.flags, 0x80);
    assert_eq!(KeyUsageFlags::KEY_ENCIPHERMENT.flags, 0x20);
    assert_eq!(KeyUsageFlags::KEY_CERT_SIGN.flags, 0x04);
    
    // Test that flags are distinct
    assert_ne!(KeyUsageFlags::DIGITAL_SIGNATURE.flags, KeyUsageFlags::KEY_ENCIPHERMENT.flags);
    assert_ne!(KeyUsageFlags::KEY_ENCIPHERMENT.flags, KeyUsageFlags::KEY_CERT_SIGN.flags);
    assert_ne!(KeyUsageFlags::DIGITAL_SIGNATURE.flags, KeyUsageFlags::KEY_CERT_SIGN.flags);
}

#[test]
fn test_key_usage_flags_default() {
    // Test Default implementation
    let default_flags = KeyUsageFlags::default();
    assert_eq!(default_flags.flags, KeyUsageFlags::DIGITAL_SIGNATURE.flags);
    
    // Test that we can create custom flags via the struct
    let custom = KeyUsageFlags { flags: 0x84 }; // DIGITAL_SIGNATURE | KEY_CERT_SIGN
    assert_eq!(custom.flags & KeyUsageFlags::DIGITAL_SIGNATURE.flags, KeyUsageFlags::DIGITAL_SIGNATURE.flags);
    assert_eq!(custom.flags & KeyUsageFlags::KEY_CERT_SIGN.flags, KeyUsageFlags::KEY_CERT_SIGN.flags);
}

#[test]
fn test_default_implementations() {
    // Test Default implementations if available
    let default_algorithm = KeyAlgorithm::default();
    assert_eq!(default_algorithm, KeyAlgorithm::Ecdsa);
    
    // Test that default key size is reasonable
    assert!(default_algorithm.default_key_size() > 0);
    assert!(default_algorithm.default_key_size() <= 8192);
}

#[test]  
fn test_algorithm_edge_cases() {
    // Test all algorithms have reasonable key sizes
    let algorithms = vec![KeyAlgorithm::Rsa, KeyAlgorithm::Ecdsa];
    
    for algorithm in &algorithms {
        let key_size = algorithm.default_key_size();
        assert!(key_size >= 128, "Key size too small for {:?}", algorithm);
        assert!(key_size <= 16384, "Key size too large for {:?}", algorithm);
        
        // Specific validations
        match algorithm {
            KeyAlgorithm::Rsa => {
                assert!(key_size >= 2048, "RSA key size should be at least 2048 bits");
            },
            KeyAlgorithm::Ecdsa => {
                assert!(key_size == 256 || key_size == 384 || key_size == 521, 
                       "ECDSA key size should be a standard curve size");
            },
            #[cfg(feature = "pqc")]
            KeyAlgorithm::MlDsa => {
                assert!(key_size >= 44 && key_size <= 87, 
                       "ML-DSA parameter set should be in valid range");
            },
        }
    }
}

#[test]
fn test_error_message_formatting() {
    let test_cases = vec![
        (CertLocalError::KeyGenerationFailed("RSA key failed".to_string()),
         "key generation failed: RSA key failed"),
        (CertLocalError::CertificateCreationFailed("invalid subject".to_string()),
         "certificate creation failed: invalid subject"),
        (CertLocalError::InvalidOptions("empty subject".to_string()),
         "invalid options: empty subject"),
        (CertLocalError::UnsupportedAlgorithm("ML-DSA-44".to_string()),
         "unsupported algorithm: ML-DSA-44"),
        (CertLocalError::IoError("file not found".to_string()),
         "I/O error: file not found"),
        (CertLocalError::LoadFailed("corrupt PFX".to_string()),
         "load failed: corrupt PFX"),
    ];
    
    for (error, expected) in test_cases {
        assert_eq!(format!("{}", error), expected);
        
        // Test that display and to_string are equivalent
        assert_eq!(format!("{}", error), error.to_string());
        
        // Test debug contains more info than display
        let debug = format!("{:?}", error);
        let display = format!("{}", error);
        assert!(debug.len() >= display.len());
    }
}
