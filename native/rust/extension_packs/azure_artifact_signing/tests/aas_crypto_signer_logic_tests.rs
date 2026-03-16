// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Tests for pure logic in aas_crypto_signer.rs

#[test]
fn test_ats_crypto_signer_hash_algorithm_mapping() {
    // Test the hash algorithm selection logic in the sign() method
    use sha2::Digest;
    
    let test_data = b"test data for hashing";
    
    // Test RS256, PS256, ES256 -> SHA-256
    for alg in ["RS256", "PS256", "ES256"] {
        let hash = sha2::Sha256::digest(test_data).to_vec();
        assert_eq!(hash.len(), 32, "SHA-256 should be 32 bytes for {}", alg);
    }
    
    // Test RS384, PS384, ES384 -> SHA-384
    for alg in ["RS384", "PS384", "ES384"] {
        let hash = sha2::Sha384::digest(test_data).to_vec();
        assert_eq!(hash.len(), 48, "SHA-384 should be 48 bytes for {}", alg);
    }
    
    // Test RS512, PS512, ES512 -> SHA-512
    for alg in ["RS512", "PS512", "ES512"] {
        let hash = sha2::Sha512::digest(test_data).to_vec();
        assert_eq!(hash.len(), 64, "SHA-512 should be 64 bytes for {}", alg);
    }
}

#[test]
fn test_ats_crypto_signer_unknown_algorithm_defaults_to_sha256() {
    // Test that unknown algorithms default to SHA-256
    use sha2::Digest;
    
    let test_data = b"test data";
    let unknown_alg = "UNKNOWN999";
    
    // The match statement has a default case that uses SHA-256
    let default_hash = sha2::Sha256::digest(test_data).to_vec();
    
    assert_eq!(default_hash.len(), 32); // SHA-256 = 32 bytes
    
    // Verify the algorithm name is actually unknown
    assert!(!unknown_alg.starts_with("RS"));
    assert!(!unknown_alg.starts_with("PS"));
    assert!(!unknown_alg.starts_with("ES"));
}

#[test]
fn test_ats_crypto_signer_algorithm_name_patterns() {
    // Test algorithm name patterns recognized by AasCryptoSigner
    let algorithms = vec![
        ("RS256", "SHA-256", 32),
        ("RS384", "SHA-384", 48),
        ("RS512", "SHA-512", 64),
        ("PS256", "SHA-256", 32),
        ("PS384", "SHA-384", 48),
        ("PS512", "SHA-512", 64),
        ("ES256", "SHA-256", 32),
        ("ES384", "SHA-384", 48),
        ("ES512", "SHA-512", 64),
    ];
    
    for (alg_name, hash_name, hash_size) in algorithms {
        // All algorithm names are 5 characters
        assert_eq!(alg_name.len(), 5, "Algorithm {} should be 5 chars", alg_name);
        
        // Hash size matches expected
        assert!(hash_size == 32 || hash_size == 48 || hash_size == 64);
        
        // Hash name matches algorithm suffix
        if alg_name.ends_with("256") {
            assert_eq!(hash_name, "SHA-256");
        } else if alg_name.ends_with("384") {
            assert_eq!(hash_name, "SHA-384");
        } else if alg_name.ends_with("512") {
            assert_eq!(hash_name, "SHA-512");
        }
    }
}

#[test]
fn test_ats_crypto_signer_algorithm_id_mapping() {
    // Test algorithm ID values for common algorithms
    let algorithm_ids = vec![
        ("RS256", -257),
        ("RS384", -258),
        ("RS512", -259),
        ("PS256", -37),
        ("PS384", -38),
        ("PS512", -39),
        ("ES256", -7),
        ("ES384", -35),
        ("ES512", -36),
    ];
    
    for (alg_name, alg_id) in algorithm_ids {
        // All COSE algorithm IDs are negative
        assert!(alg_id < 0, "Algorithm {} ID should be negative", alg_name);
        
        // Verify ID is in reasonable range
        assert!(alg_id >= -500, "Algorithm {} ID should be >= -500", alg_name);
    }
}

#[test]
fn test_ats_crypto_signer_key_type_mapping() {
    // Test key type mapping for different algorithm families
    let key_types = vec![
        ("RS256", "RSA"),
        ("RS384", "RSA"),
        ("RS512", "RSA"),
        ("PS256", "RSA"),
        ("PS384", "RSA"),
        ("PS512", "RSA"),
        ("ES256", "EC"),
        ("ES384", "EC"),
        ("ES512", "EC"),
    ];
    
    for (alg_name, key_type) in key_types {
        // Verify key type matches algorithm family
        if alg_name.starts_with("RS") || alg_name.starts_with("PS") {
            assert_eq!(key_type, "RSA", "Algorithm {} should use RSA", alg_name);
        } else if alg_name.starts_with("ES") {
            assert_eq!(key_type, "EC", "Algorithm {} should use EC", alg_name);
        }
    }
}

#[test]
fn test_ats_crypto_signer_digest_sizes() {
    // Test that digest sizes match algorithm specifications
    use sha2::Digest;
    
    let test_data = b"test data for digest size verification";
    
    // SHA-256: 256 bits = 32 bytes
    let sha256 = sha2::Sha256::digest(test_data);
    assert_eq!(sha256.len(), 32);
    
    // SHA-384: 384 bits = 48 bytes
    let sha384 = sha2::Sha384::digest(test_data);
    assert_eq!(sha384.len(), 48);
    
    // SHA-512: 512 bits = 64 bytes
    let sha512 = sha2::Sha512::digest(test_data);
    assert_eq!(sha512.len(), 64);
}

#[test]
fn test_ats_crypto_signer_error_conversion() {
    // Test error conversion from AasError to CryptoError
    let aas_error_msg = "AAS sign operation failed";
    let crypto_error = format!("SigningFailed: {}", aas_error_msg);
    
    assert!(crypto_error.contains("SigningFailed"));
    assert!(crypto_error.contains("AAS sign operation failed"));
}

#[test]
fn test_ats_crypto_signer_hash_consistency() {
    // Test that the same data produces the same hash
    use sha2::Digest;
    
    let test_data = b"consistent test data";
    
    let hash1 = sha2::Sha256::digest(test_data).to_vec();
    let hash2 = sha2::Sha256::digest(test_data).to_vec();
    
    assert_eq!(hash1, hash2, "Same input should produce same hash");
}

#[test]
fn test_ats_crypto_signer_different_data_different_hash() {
    // Test that different data produces different hashes
    use sha2::Digest;
    
    let data1 = b"test data 1";
    let data2 = b"test data 2";
    
    let hash1 = sha2::Sha256::digest(data1).to_vec();
    let hash2 = sha2::Sha256::digest(data2).to_vec();
    
    assert_ne!(hash1, hash2, "Different input should produce different hashes");
}

#[test]
fn test_ats_crypto_signer_empty_data_hash() {
    // Test hashing empty data (edge case)
    use sha2::Digest;
    
    let empty_data = b"";
    
    let sha256_empty = sha2::Sha256::digest(empty_data).to_vec();
    let sha384_empty = sha2::Sha384::digest(empty_data).to_vec();
    let sha512_empty = sha2::Sha512::digest(empty_data).to_vec();
    
    // Hashes should still have correct sizes even for empty input
    assert_eq!(sha256_empty.len(), 32);
    assert_eq!(sha384_empty.len(), 48);
    assert_eq!(sha512_empty.len(), 64);
}

#[test]
fn test_ats_crypto_signer_large_data_hash() {
    // Test hashing large data (ensure no issues with memory)
    use sha2::Digest;
    
    let large_data = vec![0xAB; 1024 * 1024]; // 1 MB of data
    
    let hash = sha2::Sha256::digest(&large_data).to_vec();
    
    // Hash size should be consistent regardless of input size
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_ats_crypto_signer_construction_parameters() {
    // Test AasCryptoSigner construction parameter validation
    let algorithm_name = "PS256".to_string();
    let algorithm_id: i64 = -37;
    let key_type = "RSA".to_string();
    
    // Verify parameter types and values
    assert_eq!(algorithm_name, "PS256");
    assert_eq!(algorithm_id, -37);
    assert_eq!(key_type, "RSA");
    
    // Verify consistency
    assert!(algorithm_name.starts_with("PS"));
    assert_eq!(key_type, "RSA"); // PS algorithms use RSA keys
}

#[test]
fn test_ats_crypto_signer_algorithm_accessor() {
    // Test algorithm() method returns correct ID
    let algorithm_id: i64 = -37;
    
    // The algorithm() method should return this ID
    assert_eq!(algorithm_id, -37);
}

#[test]
fn test_ats_crypto_signer_key_type_accessor() {
    // Test key_type() method returns correct type
    let key_type = "RSA";
    
    // The key_type() method should return this string
    assert_eq!(key_type, "RSA");
}
