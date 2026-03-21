// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CryptoSigner trait.

use crypto_primitives::CryptoSigner;

/// A mock key that records calls and returns deterministic results.
struct MockKey {
    algorithm: i64,
}

impl MockKey {
    fn new() -> Self {
        Self { algorithm: -7 }
    }
}

impl CryptoSigner for MockKey {
    fn key_id(&self) -> Option<&[u8]> {
        Some(b"mock-key-id")
    }

    fn key_type(&self) -> &str {
        "EC2"
    }

    fn algorithm(&self) -> i64 {
        self.algorithm
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, crypto_primitives::CryptoError> {
        // Return a deterministic "signature" based on input
        Ok(data.to_vec())
    }
}

#[test]
fn test_mock_key_properties() {
    let key = MockKey::new();
    assert_eq!(key.key_id(), Some(b"mock-key-id" as &[u8]));
    assert_eq!(key.key_type(), "EC2");
    assert_eq!(key.algorithm(), -7);
}

#[test]
fn test_mock_key_sign() {
    let key = MockKey::new();
    let data = b"test data";
    let result = key.sign(data);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), data.to_vec());
}
