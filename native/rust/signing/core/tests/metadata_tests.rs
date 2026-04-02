// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for metadata types.

use cose_sign1_signing::{CryptographicKeyType, SigningKeyMetadata, SigningServiceMetadata};

#[test]
fn test_cryptographic_key_type_variants() {
    assert_eq!(format!("{:?}", CryptographicKeyType::Rsa), "Rsa");
    assert_eq!(format!("{:?}", CryptographicKeyType::Ecdsa), "Ecdsa");
    assert_eq!(format!("{:?}", CryptographicKeyType::EdDsa), "EdDsa");
    assert_eq!(format!("{:?}", CryptographicKeyType::MlDsa), "MlDsa");
    assert_eq!(format!("{:?}", CryptographicKeyType::Other), "Other");
}

#[test]
fn test_cryptographic_key_type_equality() {
    assert_eq!(CryptographicKeyType::Rsa, CryptographicKeyType::Rsa);
    assert_ne!(CryptographicKeyType::Rsa, CryptographicKeyType::Ecdsa);
}

#[test]
fn test_signing_key_metadata_new() {
    let key_id = Some(vec![1, 2, 3, 4]);
    let algorithm = -7; // ES256
    let key_type = CryptographicKeyType::Ecdsa;
    let is_remote = false;

    let metadata = SigningKeyMetadata::new(key_id.clone(), algorithm, key_type, is_remote);

    assert_eq!(metadata.key_id, key_id);
    assert_eq!(metadata.algorithm, algorithm);
    assert_eq!(metadata.key_type, key_type);
    assert_eq!(metadata.is_remote, is_remote);
    assert!(metadata.additional_metadata.is_empty());
}

#[test]
fn test_signing_key_metadata_additional_metadata() {
    let mut metadata = SigningKeyMetadata::new(None, -7, CryptographicKeyType::Ecdsa, false);

    metadata
        .additional_metadata
        .insert("key1".to_string(), "value1".to_string());
    metadata
        .additional_metadata
        .insert("key2".to_string(), "value2".to_string());

    assert_eq!(metadata.additional_metadata.len(), 2);
    assert_eq!(
        metadata.additional_metadata.get("key1"),
        Some(&"value1".to_string())
    );
    assert_eq!(
        metadata.additional_metadata.get("key2"),
        Some(&"value2".to_string())
    );
}

#[test]
fn test_signing_service_metadata_new() {
    let service_name = "Test Service".to_string();
    let service_description = "A test signing service".to_string();

    let metadata = SigningServiceMetadata::new(service_name.clone(), service_description.clone());

    assert_eq!(metadata.service_name, service_name);
    assert_eq!(metadata.service_description, service_description);
    assert!(metadata.additional_metadata.is_empty());
}

#[test]
fn test_signing_service_metadata_additional_metadata() {
    let mut metadata =
        SigningServiceMetadata::new("Test Service".to_string(), "Description".to_string());

    metadata
        .additional_metadata
        .insert("version".to_string(), "1.0".to_string());
    metadata
        .additional_metadata
        .insert("provider".to_string(), "test".to_string());

    assert_eq!(metadata.additional_metadata.len(), 2);
    assert_eq!(
        metadata.additional_metadata.get("version"),
        Some(&"1.0".to_string())
    );
}

#[test]
fn test_signing_key_metadata_clone() {
    let metadata =
        SigningKeyMetadata::new(Some(vec![1, 2, 3]), -7, CryptographicKeyType::Ecdsa, true);

    let cloned = metadata.clone();
    assert_eq!(cloned.key_id, metadata.key_id);
    assert_eq!(cloned.algorithm, metadata.algorithm);
    assert_eq!(cloned.key_type, metadata.key_type);
    assert_eq!(cloned.is_remote, metadata.is_remote);
}
