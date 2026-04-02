// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for Windows certificate store loading.

use cose_sign1_certificates_local::error::CertLocalError;
use cose_sign1_certificates_local::loaders::windows_store::*;

// Mock CertStoreProvider for testing
struct MockCertStoreProvider {
    should_fail: bool,
    cert_data: StoreCertificate,
}

impl MockCertStoreProvider {
    fn new_success() -> Self {
        let cert_data = StoreCertificate {
            cert_der: vec![0x30, 0x82, 0x01, 0x23, 0x04, 0x05], // Mock DER cert
            private_key_der: Some(vec![0x30, 0x82, 0x01, 0x11, 0x02]), // Mock private key
        };
        Self {
            should_fail: false,
            cert_data,
        }
    }

    fn new_failure() -> Self {
        Self {
            should_fail: true,
            cert_data: StoreCertificate {
                cert_der: vec![],
                private_key_der: None,
            },
        }
    }

    fn new_no_private_key() -> Self {
        let cert_data = StoreCertificate {
            cert_der: vec![0x30, 0x82, 0x01, 0x23, 0x04, 0x05],
            private_key_der: None, // No private key
        };
        Self {
            should_fail: false,
            cert_data,
        }
    }
}

impl CertStoreProvider for MockCertStoreProvider {
    fn find_by_sha1_hash(
        &self,
        _thumb_bytes: &[u8],
        _store_name: StoreName,
        _store_location: StoreLocation,
    ) -> Result<StoreCertificate, CertLocalError> {
        if self.should_fail {
            Err(CertLocalError::LoadFailed(
                "Mock store provider failure".to_string(),
            ))
        } else {
            Ok(self.cert_data.clone())
        }
    }
}

#[test]
fn test_store_location_variants() {
    assert_eq!(StoreLocation::CurrentUser, StoreLocation::CurrentUser);
    assert_eq!(StoreLocation::LocalMachine, StoreLocation::LocalMachine);
    assert_ne!(StoreLocation::CurrentUser, StoreLocation::LocalMachine);
}

#[test]
fn test_store_name_variants() {
    assert_eq!(StoreName::My, StoreName::My);
    assert_eq!(StoreName::Root, StoreName::Root);
    assert_eq!(
        StoreName::CertificateAuthority,
        StoreName::CertificateAuthority
    );
    assert_ne!(StoreName::My, StoreName::Root);
}

#[test]
fn test_store_name_as_str() {
    assert_eq!(StoreName::My.as_str(), "MY");
    assert_eq!(StoreName::Root.as_str(), "ROOT");
    assert_eq!(StoreName::CertificateAuthority.as_str(), "CA");
}

#[test]
fn test_store_certificate_structure() {
    let cert = StoreCertificate {
        cert_der: vec![1, 2, 3, 4],
        private_key_der: Some(vec![5, 6, 7, 8]),
    };
    assert_eq!(cert.cert_der, vec![1, 2, 3, 4]);
    assert_eq!(cert.private_key_der, Some(vec![5, 6, 7, 8]));
}

#[test]
fn test_store_certificate_clone() {
    let original = StoreCertificate {
        cert_der: vec![1, 2, 3],
        private_key_der: None,
    };
    let cloned = original.clone();
    assert_eq!(cloned.cert_der, original.cert_der);
    assert_eq!(cloned.private_key_der, original.private_key_der);
}

#[test]
fn test_normalize_thumbprint_valid() {
    let input = "1234567890ABCDEF1234567890ABCDEF12345678";
    let result = normalize_thumbprint(input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), input);
}

#[test]
fn test_normalize_thumbprint_with_spaces() {
    let input = "12 34 56 78 90 AB CD EF 12 34 56 78 90 AB CD EF 12 34 56 78";
    let expected = "1234567890ABCDEF1234567890ABCDEF12345678";
    let result = normalize_thumbprint(input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), expected);
}

#[test]
fn test_normalize_thumbprint_with_colons() {
    let input = "12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78";
    let expected = "1234567890ABCDEF1234567890ABCDEF12345678";
    let result = normalize_thumbprint(input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), expected);
}

#[test]
fn test_normalize_thumbprint_with_dashes() {
    let input = "12-34-56-78-90-ab-cd-ef-12-34-56-78-90-ab-cd-ef-12-34-56-78";
    let expected = "1234567890ABCDEF1234567890ABCDEF12345678";
    let result = normalize_thumbprint(input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), expected);
}

#[test]
fn test_normalize_thumbprint_lowercase_to_uppercase() {
    let input = "abcdef1234567890abcdef1234567890abcdef12";
    let expected = "ABCDEF1234567890ABCDEF1234567890ABCDEF12";
    let result = normalize_thumbprint(input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), expected);
}

#[test]
fn test_normalize_thumbprint_mixed_case() {
    let input = "AbCdEf1234567890aBcDeF1234567890AbCdEf12";
    let expected = "ABCDEF1234567890ABCDEF1234567890ABCDEF12";
    let result = normalize_thumbprint(input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), expected);
}

#[test]
fn test_normalize_thumbprint_too_short() {
    let input = "123456789ABCDEF"; // Only 15 chars
    let result = normalize_thumbprint(input);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("Invalid SHA-1 thumbprint length"));
            assert!(msg.contains("expected 40 hex chars"));
            assert!(msg.contains("got 15"));
        }
        _ => panic!("Expected LoadFailed error"),
    }
}

#[test]
fn test_normalize_thumbprint_too_long() {
    let input = "1234567890ABCDEF1234567890ABCDEF123456789"; // 41 chars
    let result = normalize_thumbprint(input);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("Invalid SHA-1 thumbprint length"));
            assert!(msg.contains("expected 40 hex chars"));
            assert!(msg.contains("got 41"));
        }
        _ => panic!("Expected LoadFailed error"),
    }
}

#[test]
fn test_normalize_thumbprint_invalid_hex_chars() {
    let input = "123456789GABCDEF1234567890ABCDEF12345678"; // 'G' is not hex
    let result = normalize_thumbprint(input);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("Invalid SHA-1 thumbprint length"));
            assert!(msg.contains("got 39")); // 'G' filtered out
        }
        _ => panic!("Expected LoadFailed error"),
    }
}

#[test]
fn test_hex_decode_valid() {
    let input = "48656C6C6F"; // "Hello" in hex
    let result = hex_decode(input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), b"Hello");
}

#[test]
fn test_hex_decode_uppercase() {
    let input = "DEADBEEF";
    let result = hex_decode(input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn test_hex_decode_lowercase() {
    let input = "deadbeef";
    let result = hex_decode(input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn test_hex_decode_empty_string() {
    let input = "";
    let result = hex_decode(input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Vec::<u8>::new());
}

#[test]
fn test_hex_decode_odd_length() {
    let input = "ABC"; // Odd length
    let result = hex_decode(input);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("Hex string must have even length"));
        }
        _ => panic!("Expected LoadFailed error"),
    }
}

#[test]
fn test_hex_decode_invalid_hex() {
    let input = "ABCG"; // 'G' is not valid hex
    let result = hex_decode(input);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("Invalid hex"));
        }
        _ => panic!("Expected LoadFailed error"),
    }
}

#[test]
fn test_load_from_provider_success() {
    let provider = MockCertStoreProvider::new_success();
    let thumbprint = "1234567890ABCDEF1234567890ABCDEF12345678";

    let result = load_from_provider(
        &provider,
        thumbprint,
        StoreName::My,
        StoreLocation::CurrentUser,
    );

    assert!(result.is_ok());
    let cert = result.unwrap();
    assert_eq!(cert.cert_der, vec![0x30, 0x82, 0x01, 0x23, 0x04, 0x05]);
    assert!(cert.has_private_key());
}

#[test]
fn test_load_from_provider_no_private_key() {
    let provider = MockCertStoreProvider::new_no_private_key();
    let thumbprint = "1234567890ABCDEF1234567890ABCDEF12345678";

    let result = load_from_provider(
        &provider,
        thumbprint,
        StoreName::Root,
        StoreLocation::LocalMachine,
    );

    assert!(result.is_ok());
    let cert = result.unwrap();
    assert!(!cert.has_private_key());
}

#[test]
fn test_load_from_provider_invalid_thumbprint() {
    let provider = MockCertStoreProvider::new_success();
    let thumbprint = "INVALID_THUMBPRINT"; // Too short

    let result = load_from_provider(
        &provider,
        thumbprint,
        StoreName::My,
        StoreLocation::CurrentUser,
    );

    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("Invalid SHA-1 thumbprint length"));
        }
        _ => panic!("Expected LoadFailed error"),
    }
}

#[test]
fn test_load_from_provider_store_failure() {
    let provider = MockCertStoreProvider::new_failure();
    let thumbprint = "1234567890ABCDEF1234567890ABCDEF12345678";

    let result = load_from_provider(
        &provider,
        thumbprint,
        StoreName::My,
        StoreLocation::CurrentUser,
    );

    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("Mock store provider failure"));
        }
        _ => panic!("Expected LoadFailed error"),
    }
}

#[test]
fn test_load_from_provider_with_spaces_in_thumbprint() {
    let provider = MockCertStoreProvider::new_success();
    let thumbprint = "12 34 56 78 90 AB CD EF 12 34 56 78 90 AB CD EF 12 34 56 78";

    let result = load_from_provider(
        &provider,
        thumbprint,
        StoreName::CertificateAuthority,
        StoreLocation::LocalMachine,
    );

    assert!(result.is_ok());
}

#[test]
fn test_all_store_name_combinations() {
    let provider = MockCertStoreProvider::new_success();
    let thumbprint = "1234567890ABCDEF1234567890ABCDEF12345678";

    // Test all store name combinations
    for store_name in [
        StoreName::My,
        StoreName::Root,
        StoreName::CertificateAuthority,
    ] {
        for store_location in [StoreLocation::CurrentUser, StoreLocation::LocalMachine] {
            let result = load_from_provider(&provider, thumbprint, store_name, store_location);
            assert!(
                result.is_ok(),
                "Failed for {:?}/{:?}",
                store_name,
                store_location
            );
        }
    }
}

#[test]
#[cfg(not(all(target_os = "windows", feature = "windows-store")))]
fn test_windows_store_functions_without_feature() {
    // Test that Windows store functions return appropriate errors when feature is disabled or not on Windows
    let result = load_from_store_by_thumbprint(
        "1234567890ABCDEF1234567890ABCDEF12345678",
        StoreName::My,
        StoreLocation::CurrentUser,
    );

    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("Windows certificate store support requires"));
        }
        _ => panic!("Expected LoadFailed error"),
    }

    let result = load_from_store_by_thumbprint_default("1234567890ABCDEF1234567890ABCDEF12345678");
    assert!(result.is_err());
}

#[test]
fn test_sha1_thumbprint_byte_conversion() {
    let thumbprint = "1234567890ABCDEF1234567890ABCDEF12345678";
    let normalized = normalize_thumbprint(thumbprint).unwrap();
    let thumb_bytes = hex_decode(&normalized).unwrap();

    assert_eq!(thumb_bytes.len(), 20); // SHA-1 is 20 bytes
    assert_eq!(thumb_bytes[0], 0x12);
    assert_eq!(thumb_bytes[1], 0x34);
    assert_eq!(thumb_bytes[19], 0x78);
}

#[test]
fn test_normalize_thumbprint_preserves_original_in_error() {
    let input = "invalid thumbprint with spaces and letters XYZ";
    let result = normalize_thumbprint(input);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains(input)); // Original input should be in error message
        }
        _ => panic!("Expected LoadFailed error"),
    }
}
