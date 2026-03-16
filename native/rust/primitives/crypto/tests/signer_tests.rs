// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trait-level tests for crypto_primitives.

use crypto_primitives::{
    CryptoError, CryptoProvider, CryptoSigner, CryptoVerifier, NullCryptoProvider, SigningContext,
    VerifyingContext,
};

/// Mock signer for testing trait behavior.
struct MockSigner {
    algorithm: i64,
    key_type: String,
}

impl MockSigner {
    fn new(algorithm: i64, key_type: &str) -> Self {
        Self {
            algorithm,
            key_type: key_type.to_string(),
        }
    }
}

impl CryptoSigner for MockSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Mock signature: just return the input reversed
        Ok(data.iter().rev().copied().collect())
    }

    fn algorithm(&self) -> i64 {
        self.algorithm
    }

    fn key_type(&self) -> &str {
        &self.key_type
    }
}

/// Mock verifier for testing trait behavior.
struct MockVerifier {
    algorithm: i64,
}

impl MockVerifier {
    fn new(algorithm: i64) -> Self {
        Self { algorithm }
    }
}

impl CryptoVerifier for MockVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        // Mock verification: check if signature is data reversed
        let expected: Vec<u8> = data.iter().rev().copied().collect();
        Ok(signature == expected.as_slice())
    }

    fn algorithm(&self) -> i64 {
        self.algorithm
    }
}

/// Mock streaming signing context for testing.
struct MockSigningContext {
    buffer: Vec<u8>,
}

impl MockSigningContext {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }
}

impl SigningContext for MockSigningContext {
    fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError> {
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    fn finalize(self: Box<Self>) -> Result<Vec<u8>, CryptoError> {
        // Mock signature: return buffer reversed
        Ok(self.buffer.iter().rev().copied().collect())
    }
}

/// Mock streaming verifying context for testing.
struct MockVerifyingContext {
    buffer: Vec<u8>,
    expected_signature: Vec<u8>,
}

impl MockVerifyingContext {
    fn new(signature: &[u8]) -> Self {
        Self {
            buffer: Vec::new(),
            expected_signature: signature.to_vec(),
        }
    }
}

impl VerifyingContext for MockVerifyingContext {
    fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError> {
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    fn finalize(self: Box<Self>) -> Result<bool, CryptoError> {
        // Mock verification: check if signature is buffer reversed
        let expected: Vec<u8> = self.buffer.iter().rev().copied().collect();
        Ok(self.expected_signature == expected)
    }
}

/// Mock streaming signer that supports streaming.
struct MockStreamingSigner {
    algorithm: i64,
}

impl MockStreamingSigner {
    fn new(algorithm: i64) -> Self {
        Self { algorithm }
    }
}

impl CryptoSigner for MockStreamingSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(data.iter().rev().copied().collect())
    }

    fn algorithm(&self) -> i64 {
        self.algorithm
    }

    fn key_type(&self) -> &str {
        "MockStreaming"
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn sign_init(&self) -> Result<Box<dyn SigningContext>, CryptoError> {
        Ok(Box::new(MockSigningContext::new()))
    }
}

/// Mock streaming verifier that supports streaming.
struct MockStreamingVerifier {
    algorithm: i64,
}

impl MockStreamingVerifier {
    fn new(algorithm: i64) -> Self {
        Self { algorithm }
    }
}

impl CryptoVerifier for MockStreamingVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let expected: Vec<u8> = data.iter().rev().copied().collect();
        Ok(signature == expected.as_slice())
    }

    fn algorithm(&self) -> i64 {
        self.algorithm
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn verify_init(&self, signature: &[u8]) -> Result<Box<dyn VerifyingContext>, CryptoError> {
        Ok(Box::new(MockVerifyingContext::new(signature)))
    }
}

#[test]
fn test_signer_trait_basic() {
    let signer = MockSigner::new(-7, "EC");
    assert_eq!(signer.algorithm(), -7);
    assert_eq!(signer.key_type(), "EC");
    assert_eq!(signer.key_id(), None);
    assert!(!signer.supports_streaming());

    let data = b"hello world";
    let signature = signer.sign(data).expect("sign should succeed");
    assert_eq!(signature.len(), data.len());
    // Verify mock behavior: signature is data reversed
    let expected: Vec<u8> = data.iter().rev().copied().collect();
    assert_eq!(signature, expected);
}

#[test]
fn test_verifier_trait_basic() {
    let verifier = MockVerifier::new(-7);
    assert_eq!(verifier.algorithm(), -7);
    assert!(!verifier.supports_streaming());

    let data = b"hello world";
    let signature: Vec<u8> = data.iter().rev().copied().collect();

    let result = verifier.verify(data, &signature).expect("verify should succeed");
    assert!(result, "signature should be valid");

    // Wrong signature
    let wrong_sig = b"wrong signature";
    let result = verifier.verify(data, wrong_sig).expect("verify should succeed");
    assert!(!result, "wrong signature should be invalid");
}

#[test]
fn test_streaming_signer() {
    let signer = MockStreamingSigner::new(-7);
    assert!(signer.supports_streaming());

    let mut ctx = signer.sign_init().expect("sign_init should succeed");
    ctx.update(b"hello ").expect("update should succeed");
    ctx.update(b"world").expect("update should succeed");

    let signature = ctx.finalize().expect("finalize should succeed");

    // Verify mock behavior: signature is concatenated data reversed
    let expected: Vec<u8> = b"hello world".iter().rev().copied().collect();
    assert_eq!(signature, expected);
}

#[test]
fn test_streaming_verifier() {
    let verifier = MockStreamingVerifier::new(-7);
    assert!(verifier.supports_streaming());

    let data = b"hello world";
    let signature: Vec<u8> = data.iter().rev().copied().collect();

    let mut ctx = verifier
        .verify_init(&signature)
        .expect("verify_init should succeed");
    ctx.update(b"hello ").expect("update should succeed");
    ctx.update(b"world").expect("update should succeed");

    let result = ctx.finalize().expect("finalize should succeed");
    assert!(result, "signature should be valid");
}

#[test]
fn test_non_streaming_signer_returns_error() {
    let signer = MockSigner::new(-7, "EC");
    assert!(!signer.supports_streaming());

    let result = signer.sign_init();
    assert!(result.is_err());

    if let Err(CryptoError::UnsupportedOperation(msg)) = result {
        assert!(msg.contains("streaming not supported"));
    } else {
        panic!("expected UnsupportedOperation error");
    }
}

#[test]
fn test_non_streaming_verifier_returns_error() {
    let verifier = MockVerifier::new(-7);
    assert!(!verifier.supports_streaming());

    let result = verifier.verify_init(b"signature");
    assert!(result.is_err());

    if let Err(CryptoError::UnsupportedOperation(msg)) = result {
        assert!(msg.contains("streaming not supported"));
    } else {
        panic!("expected UnsupportedOperation error");
    }
}

#[test]
fn test_null_crypto_provider() {
    let provider = NullCryptoProvider;
    assert_eq!(provider.name(), "null");

    let signer_result = provider.signer_from_der(b"fake key");
    assert!(signer_result.is_err());
    if let Err(CryptoError::UnsupportedOperation(msg)) = signer_result {
        assert!(msg.contains("no crypto provider"));
    } else {
        panic!("expected UnsupportedOperation error");
    }

    let verifier_result = provider.verifier_from_der(b"fake key");
    assert!(verifier_result.is_err());
    if let Err(CryptoError::UnsupportedOperation(msg)) = verifier_result {
        assert!(msg.contains("no crypto provider"));
    } else {
        panic!("expected UnsupportedOperation error");
    }
}

#[test]
fn test_crypto_error_display() {
    let err = CryptoError::SigningFailed("test error".to_string());
    assert_eq!(err.to_string(), "signing failed: test error");

    let err = CryptoError::VerificationFailed("bad signature".to_string());
    assert_eq!(err.to_string(), "verification failed: bad signature");

    let err = CryptoError::InvalidKey("corrupted".to_string());
    assert_eq!(err.to_string(), "invalid key: corrupted");

    let err = CryptoError::UnsupportedAlgorithm(-999);
    assert_eq!(err.to_string(), "unsupported algorithm: -999");

    let err = CryptoError::UnsupportedOperation("not implemented".to_string());
    assert_eq!(err.to_string(), "unsupported operation: not implemented");
}

#[test]
fn test_algorithm_constants() {
    use crypto_primitives::algorithms::*;

    // Verify standard algorithm constants
    assert_eq!(ES256, -7);
    assert_eq!(ES384, -35);
    assert_eq!(ES512, -36);
    assert_eq!(EDDSA, -8);
    assert_eq!(PS256, -37);
    assert_eq!(PS384, -38);
    assert_eq!(PS512, -39);
    assert_eq!(RS256, -257);
    assert_eq!(RS384, -258);
    assert_eq!(RS512, -259);
}

#[test]
#[cfg(feature = "pqc")]
fn test_pqc_algorithm_constants() {
    use crypto_primitives::algorithms::*;

    assert_eq!(ML_DSA_44, -48);
    assert_eq!(ML_DSA_65, -49);
    assert_eq!(ML_DSA_87, -50);
}
