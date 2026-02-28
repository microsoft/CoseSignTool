// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_certificates::signing::signing_key_provider::SigningKeyProvider;
use crypto_primitives::{CryptoError, CryptoSigner};

struct MockLocalProvider;

impl CryptoSigner for MockLocalProvider {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![])
    }

    fn algorithm(&self) -> i64 {
        -7
    }

    fn key_id(&self) -> Option<&[u8]> {
        None
    }

    fn key_type(&self) -> &str {
        "EC2"
    }
}

impl SigningKeyProvider for MockLocalProvider {
    fn is_remote(&self) -> bool {
        false
    }
}

struct MockRemoteProvider;

impl CryptoSigner for MockRemoteProvider {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![])
    }

    fn algorithm(&self) -> i64 {
        -7
    }

    fn key_id(&self) -> Option<&[u8]> {
        Some(b"remote-key-id")
    }

    fn key_type(&self) -> &str {
        "EC2"
    }
}

impl SigningKeyProvider for MockRemoteProvider {
    fn is_remote(&self) -> bool {
        true
    }
}

#[test]
fn test_local_provider_not_remote() {
    let provider = MockLocalProvider;
    assert!(!provider.is_remote());
}

#[test]
fn test_remote_provider_is_remote() {
    let provider = MockRemoteProvider;
    assert!(provider.is_remote());
}