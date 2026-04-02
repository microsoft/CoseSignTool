// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for signer and header contribution.

use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};
use cose_sign1_signing::{
    CoseSigner, HeaderContributorContext, HeaderMergeStrategy, SigningContext,
};
use crypto_primitives::CryptoSigner;

#[test]
fn test_header_merge_strategy_variants() {
    assert_eq!(format!("{:?}", HeaderMergeStrategy::Fail), "Fail");
    assert_eq!(
        format!("{:?}", HeaderMergeStrategy::KeepExisting),
        "KeepExisting"
    );
    assert_eq!(format!("{:?}", HeaderMergeStrategy::Replace), "Replace");
    assert_eq!(format!("{:?}", HeaderMergeStrategy::Custom), "Custom");
}

#[test]
fn test_header_merge_strategy_equality() {
    assert_eq!(HeaderMergeStrategy::Fail, HeaderMergeStrategy::Fail);
    assert_ne!(HeaderMergeStrategy::Fail, HeaderMergeStrategy::Replace);
}

#[test]
fn test_header_merge_strategy_copy() {
    let strategy = HeaderMergeStrategy::KeepExisting;
    let copied = strategy;
    assert_eq!(strategy, copied);
}

#[test]
fn test_header_merge_strategy_all_variants_equality() {
    // Test all combinations to ensure complete equality coverage
    let strategies = [
        HeaderMergeStrategy::Fail,
        HeaderMergeStrategy::KeepExisting,
        HeaderMergeStrategy::Replace,
        HeaderMergeStrategy::Custom,
    ];

    for (i, &strategy1) in strategies.iter().enumerate() {
        for (j, &strategy2) in strategies.iter().enumerate() {
            if i == j {
                assert_eq!(strategy1, strategy2, "Strategy should equal itself");
            } else {
                assert_ne!(
                    strategy1, strategy2,
                    "Different strategies should not be equal"
                );
            }
        }
    }
}

// Mock crypto signer for testing
struct MockCryptoSigner {
    algorithm: i64,
    should_fail: bool,
}

impl MockCryptoSigner {
    fn new(algorithm: i64) -> Self {
        Self {
            algorithm,
            should_fail: false,
        }
    }

    fn with_failure(mut self) -> Self {
        self.should_fail = true;
        self
    }
}

impl CryptoSigner for MockCryptoSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, crypto_primitives::CryptoError> {
        if self.should_fail {
            return Err(crypto_primitives::CryptoError::SigningFailed(
                "Mock signing failure".to_string(),
            ));
        }

        // Return fake signature
        Ok(format!("signature-for-{}-bytes", data.len()).into_bytes())
    }

    fn algorithm(&self) -> i64 {
        self.algorithm
    }

    fn key_type(&self) -> &str {
        "ECDSA"
    }
}

#[test]
fn test_cose_signer_new() {
    let signer = Box::new(MockCryptoSigner::new(-7)); // ES256
    let mut protected = CoseHeaderMap::new();
    protected.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7)); // alg

    let mut unprotected = CoseHeaderMap::new();
    unprotected.insert(
        CoseHeaderLabel::Int(4),
        CoseHeaderValue::Bytes(b"key-id".to_vec().into()),
    ); // kid

    let cose_signer = CoseSigner::new(signer, protected.clone(), unprotected.clone());

    assert_eq!(cose_signer.signer().algorithm(), -7);
    // Check header contents instead of direct comparison since CoseHeaderMap doesn't implement PartialEq
    assert_eq!(
        cose_signer
            .protected_headers()
            .get(&CoseHeaderLabel::Int(1)),
        Some(&CoseHeaderValue::Int(-7))
    );
    assert_eq!(
        cose_signer
            .unprotected_headers()
            .get(&CoseHeaderLabel::Int(4)),
        Some(&CoseHeaderValue::Bytes(b"key-id".to_vec().into()))
    );
}

#[test]
fn test_cose_signer_accessor_methods() {
    let signer = Box::new(MockCryptoSigner::new(-35)); // ES384
    let mut protected = CoseHeaderMap::new();
    protected.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-35));

    let unprotected = CoseHeaderMap::new();

    let cose_signer = CoseSigner::new(signer, protected, unprotected);

    // Test signer accessor
    let crypto_signer = cose_signer.signer();
    assert_eq!(crypto_signer.algorithm(), -35);
    assert_eq!(crypto_signer.key_type(), "ECDSA");

    // Test header accessors - Check specific values instead of direct comparison
    let protected_headers = cose_signer.protected_headers();
    assert_eq!(
        protected_headers.get(&CoseHeaderLabel::Int(1)),
        Some(&CoseHeaderValue::Int(-35))
    );

    let unprotected_headers = cose_signer.unprotected_headers();
    assert!(unprotected_headers.is_empty());
}

#[test]
fn test_cose_signer_sign_payload_success() {
    let signer = Box::new(MockCryptoSigner::new(-7));
    let mut protected = CoseHeaderMap::new();
    protected.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));

    let cose_signer = CoseSigner::new(signer, protected, CoseHeaderMap::new());

    let payload = b"test payload";
    let result = cose_signer.sign_payload(payload, None);

    assert!(result.is_ok());
    let signature = result.unwrap();
    // Mock signer returns a predictable signature
    assert!(String::from_utf8_lossy(&signature).contains("signature-for-"));
}

#[test]
fn test_cose_signer_sign_payload_with_external_aad() {
    let signer = Box::new(MockCryptoSigner::new(-7));
    let mut protected = CoseHeaderMap::new();
    protected.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));

    let cose_signer = CoseSigner::new(signer, protected, CoseHeaderMap::new());

    let payload = b"test payload";
    let external_aad = b"external authenticated data";
    let result = cose_signer.sign_payload(payload, Some(external_aad));

    assert!(result.is_ok());
    let signature = result.unwrap();
    assert!(String::from_utf8_lossy(&signature).contains("signature-for-"));
}

#[test]
fn test_cose_signer_sign_payload_crypto_error() {
    let signer = Box::new(MockCryptoSigner::new(-7).with_failure());
    let mut protected = CoseHeaderMap::new();
    protected.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));

    let cose_signer = CoseSigner::new(signer, protected, CoseHeaderMap::new());

    let payload = b"test payload";
    let result = cose_signer.sign_payload(payload, None);

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Signing failed"));
    assert!(error.to_string().contains("Mock signing failure"));
}

#[test]
fn test_header_contributor_context_new() {
    let context = SigningContext::from_bytes(b"test payload".to_vec());
    let signer = MockCryptoSigner::new(-7);

    let contributor_context = HeaderContributorContext::new(&context, &signer);

    assert!(contributor_context
        .signing_context
        .payload_bytes()
        .is_some());
    assert_eq!(contributor_context.signing_key.algorithm(), -7);
}
