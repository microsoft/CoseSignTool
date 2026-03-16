// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for COSE algorithm constants and values.

use cose_sign1_primitives::algorithms::{
    COSE_SIGN1_TAG, EDDSA, ES256, ES384, ES512, LARGE_PAYLOAD_THRESHOLD, PS256, PS384, PS512,
    RS256, RS384, RS512,
};

#[test]
fn test_es256_constant() {
    assert_eq!(ES256, -7);
}

#[test]
fn test_es384_constant() {
    assert_eq!(ES384, -35);
}

#[test]
fn test_es512_constant() {
    assert_eq!(ES512, -36);
}

#[test]
fn test_eddsa_constant() {
    assert_eq!(EDDSA, -8);
}

#[test]
fn test_ps256_constant() {
    assert_eq!(PS256, -37);
}

#[test]
fn test_ps384_constant() {
    assert_eq!(PS384, -38);
}

#[test]
fn test_ps512_constant() {
    assert_eq!(PS512, -39);
}

#[test]
fn test_rs256_constant() {
    assert_eq!(RS256, -257);
}

#[test]
fn test_rs384_constant() {
    assert_eq!(RS384, -258);
}

#[test]
fn test_rs512_constant() {
    assert_eq!(RS512, -259);
}

#[test]
fn test_large_payload_threshold() {
    assert_eq!(LARGE_PAYLOAD_THRESHOLD, 85_000);
}

#[test]
fn test_cose_sign1_tag() {
    assert_eq!(COSE_SIGN1_TAG, 18);
}

#[test]
fn test_ecdsa_algorithms_are_negative() {
    assert!(ES256 < 0);
    assert!(ES384 < 0);
    assert!(ES512 < 0);
}

#[test]
fn test_rsa_algorithms_are_negative() {
    assert!(PS256 < 0);
    assert!(PS384 < 0);
    assert!(PS512 < 0);
    assert!(RS256 < 0);
    assert!(RS384 < 0);
    assert!(RS512 < 0);
}

#[test]
fn test_eddsa_algorithm_is_negative() {
    assert!(EDDSA < 0);
}

#[test]
fn test_algorithm_values_are_unique() {
    let algorithms = vec![ES256, ES384, ES512, EDDSA, PS256, PS384, PS512, RS256, RS384, RS512];
    
    for (i, &alg1) in algorithms.iter().enumerate() {
        for (j, &alg2) in algorithms.iter().enumerate() {
            if i != j {
                assert_ne!(alg1, alg2, "Algorithms at positions {} and {} are not unique", i, j);
            }
        }
    }
}

#[test]
fn test_ecdsa_p256_family() {
    // ES256 uses SHA-256
    assert_eq!(ES256, -7);
}

#[test]
fn test_ecdsa_p384_family() {
    // ES384 uses SHA-384
    assert_eq!(ES384, -35);
}

#[test]
fn test_ecdsa_p521_family() {
    // ES512 uses SHA-512 (note: curve is P-521, not P-512)
    assert_eq!(ES512, -36);
}

#[test]
fn test_pss_family() {
    // PSS algorithms with different hash sizes
    assert_eq!(PS256, -37);
    assert_eq!(PS384, -38);
    assert_eq!(PS512, -39);
}

#[test]
fn test_pkcs1_family() {
    // PKCS#1 v1.5 algorithms with different hash sizes
    assert_eq!(RS256, -257);
    assert_eq!(RS384, -258);
    assert_eq!(RS512, -259);
}

#[test]
fn test_pkcs1_values_much_lower() {
    // RS* algorithms have much more negative values than PS*
    assert!(RS256 < PS256);
    assert!(RS384 < PS384);
    assert!(RS512 < PS512);
}

#[test]
fn test_large_payload_threshold_reasonable() {
    // Should be a reasonable size for streaming (85 KB)
    assert!(LARGE_PAYLOAD_THRESHOLD > 50_000);
    assert!(LARGE_PAYLOAD_THRESHOLD < 1_000_000);
}

#[test]
fn test_large_payload_threshold_type() {
    // Ensure it's u64 type
    let _threshold: u64 = LARGE_PAYLOAD_THRESHOLD;
}

#[test]
fn test_cose_sign1_tag_is_18() {
    // RFC 9052 specifies tag 18 for COSE_Sign1
    assert_eq!(COSE_SIGN1_TAG, 18u64);
}

#[test]
fn test_algorithm_sorting_order() {
    let mut algorithms = vec![RS256, PS256, ES256, EDDSA, ES384, ES512, PS384, PS512, RS384, RS512];
    algorithms.sort();
    
    // Most negative first
    assert_eq!(algorithms[0], RS512);
    assert_eq!(algorithms[1], RS384);
    assert_eq!(algorithms[2], RS256);
}

#[test]
fn test_es_algorithms_sequential() {
    // ES384 and ES512 are close together
    assert_eq!(ES384, -35);
    assert_eq!(ES512, -36);
    assert_eq!(ES512 - ES384, -1);
}

#[test]
fn test_ps_algorithms_sequential() {
    // PS algorithms are sequential
    assert_eq!(PS256, -37);
    assert_eq!(PS384, -38);
    assert_eq!(PS512, -39);
    assert_eq!(PS384 - PS256, -1);
    assert_eq!(PS512 - PS384, -1);
}

#[test]
fn test_rs_algorithms_sequential() {
    // RS algorithms are sequential
    assert_eq!(RS256, -257);
    assert_eq!(RS384, -258);
    assert_eq!(RS512, -259);
    assert_eq!(RS384 - RS256, -1);
    assert_eq!(RS512 - RS384, -1);
}

#[test]
fn test_es256_most_common() {
    // ES256 (-7) is typically the most common ECDSA algorithm
    assert_eq!(ES256, -7);
    assert!(ES256 > ES384);
    assert!(ES256 > ES512);
}

#[test]
fn test_eddsa_between_es256_and_es384() {
    assert!(EDDSA < ES256);
    assert!(EDDSA > ES384);
}

#[test]
fn test_algorithm_ranges() {
    // ECDSA algorithms in -7 to -36 range
    assert!(ES256 >= -36 && ES256 <= -7);
    assert!(ES384 >= -36 && ES384 <= -7);
    assert!(ES512 >= -36 && ES512 <= -7);
    
    // EdDSA in same range
    assert!(EDDSA >= -36 && EDDSA <= -7);
    
    // PSS algorithms in -37 to -39 range
    assert!(PS256 >= -39 && PS256 <= -37);
    assert!(PS384 >= -39 && PS384 <= -37);
    assert!(PS512 >= -39 && PS512 <= -37);
    
    // PKCS1 algorithms below -250
    assert!(RS256 < -250);
    assert!(RS384 < -250);
    assert!(RS512 < -250);
}

#[test]
fn test_large_payload_threshold_exact_value() {
    // Verify the exact documented value
    assert_eq!(LARGE_PAYLOAD_THRESHOLD, 85_000);
}

#[test]
fn test_payload_threshold_comparison() {
    let small_payload = 1_000u64;
    let medium_payload = 50_000u64;
    let large_payload = 100_000u64;
    
    assert!(small_payload < LARGE_PAYLOAD_THRESHOLD);
    assert!(medium_payload < LARGE_PAYLOAD_THRESHOLD);
    assert!(large_payload > LARGE_PAYLOAD_THRESHOLD);
}

#[test]
fn test_algorithm_as_i64() {
    // Ensure algorithms can be used as i64
    let _alg: i64 = ES256;
    let _alg: i64 = PS256;
    let _alg: i64 = RS256;
}

#[test]
fn test_tag_as_u64() {
    // Ensure tag can be used as u64
    let _tag: u64 = COSE_SIGN1_TAG;
}

#[test]
fn test_threshold_as_u64() {
    // Ensure threshold can be used as u64
    let _threshold: u64 = LARGE_PAYLOAD_THRESHOLD;
}

#[test]
fn test_algorithm_match_patterns() {
    fn algorithm_name(alg: i64) -> &'static str {
        match alg {
            ES256 => "ES256",
            ES384 => "ES384",
            ES512 => "ES512",
            EDDSA => "EdDSA",
            PS256 => "PS256",
            PS384 => "PS384",
            PS512 => "PS512",
            RS256 => "RS256",
            RS384 => "RS384",
            RS512 => "RS512",
            _ => "unknown",
        }
    }
    
    assert_eq!(algorithm_name(ES256), "ES256");
    assert_eq!(algorithm_name(PS256), "PS256");
    assert_eq!(algorithm_name(RS256), "RS256");
    assert_eq!(algorithm_name(EDDSA), "EdDSA");
    assert_eq!(algorithm_name(0), "unknown");
}

#[test]
fn test_hash_size_from_algorithm() {
    fn hash_size_bits(alg: i64) -> Option<u32> {
        match alg {
            ES256 | PS256 | RS256 => Some(256),
            ES384 | PS384 | RS384 => Some(384),
            ES512 | PS512 | RS512 => Some(512),
            _ => None,
        }
    }
    
    assert_eq!(hash_size_bits(ES256), Some(256));
    assert_eq!(hash_size_bits(ES384), Some(384));
    assert_eq!(hash_size_bits(ES512), Some(512));
    assert_eq!(hash_size_bits(PS256), Some(256));
    assert_eq!(hash_size_bits(RS256), Some(256));
    assert_eq!(hash_size_bits(EDDSA), None);
}

#[test]
fn test_algorithm_family_detection() {
    fn is_ecdsa(alg: i64) -> bool {
        matches!(alg, ES256 | ES384 | ES512)
    }
    
    fn is_rsa_pss(alg: i64) -> bool {
        matches!(alg, PS256 | PS384 | PS512)
    }
    
    fn is_rsa_pkcs1(alg: i64) -> bool {
        matches!(alg, RS256 | RS384 | RS512)
    }
    
    assert!(is_ecdsa(ES256));
    assert!(is_ecdsa(ES384));
    assert!(is_ecdsa(ES512));
    assert!(!is_ecdsa(PS256));
    
    assert!(is_rsa_pss(PS256));
    assert!(is_rsa_pss(PS384));
    assert!(is_rsa_pss(PS512));
    assert!(!is_rsa_pss(ES256));
    
    assert!(is_rsa_pkcs1(RS256));
    assert!(is_rsa_pkcs1(RS384));
    assert!(is_rsa_pkcs1(RS512));
    assert!(!is_rsa_pkcs1(ES256));
}

#[test]
fn test_cbor_tag_18_specification() {
    // Tag 18 is specifically designated for COSE_Sign1 in RFC 9052
    assert_eq!(COSE_SIGN1_TAG, 18);
    
    // Verify it can be used in tag encoding context
    let tag_value: u64 = COSE_SIGN1_TAG;
    assert_eq!(tag_value, 18);
}

#[test]
fn test_large_payload_threshold_in_bytes() {
    // Threshold is 85,000 bytes = 85 KB
    let threshold_kb = LARGE_PAYLOAD_THRESHOLD / 1_000;
    assert_eq!(threshold_kb, 85);
}

#[test]
fn test_algorithm_constants_immutable() {
    // These constants should be compile-time constants
    const _TEST_ES256: i64 = ES256;
    const _TEST_PS256: i64 = PS256;
    const _TEST_RS256: i64 = RS256;
    const _TEST_TAG: u64 = COSE_SIGN1_TAG;
    const _TEST_THRESHOLD: u64 = LARGE_PAYLOAD_THRESHOLD;
}
