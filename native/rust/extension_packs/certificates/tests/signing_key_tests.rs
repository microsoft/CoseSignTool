// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_certificates::chain_sort_order::X509ChainSortOrder;
use cose_sign1_certificates::error::CertificateError;
use cose_sign1_certificates::signing::signing_key::CertificateSigningKey;
use cose_sign1_signing::{SigningKeyMetadata, SigningServiceKey};
use crypto_primitives::{CryptoError, CryptoSigner};

struct MockCertificateKey {
    cert: Vec<u8>,
    chain: Vec<Vec<u8>>,
}

impl CryptoSigner for MockCertificateKey {
    fn key_type(&self) -> &str {
        "EC2"
    }

    fn algorithm(&self) -> i64 {
        -7
    }

    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![])
    }
}

impl SigningServiceKey for MockCertificateKey {
    fn metadata(&self) -> &SigningKeyMetadata {
        use cose_sign1_signing::CryptographicKeyType;
        use std::sync::OnceLock;
        static METADATA: OnceLock<SigningKeyMetadata> = OnceLock::new();
        METADATA
            .get_or_init(|| SigningKeyMetadata::new(None, -7, CryptographicKeyType::Ecdsa, false))
    }
}

impl CertificateSigningKey for MockCertificateKey {
    fn get_signing_certificate(&self) -> Result<&[u8], CertificateError> {
        Ok(&self.cert)
    }

    fn get_certificate_chain(
        &self,
        sort_order: X509ChainSortOrder,
    ) -> Result<Vec<Vec<u8>>, CertificateError> {
        match sort_order {
            X509ChainSortOrder::LeafFirst => Ok(self.chain.clone()),
            X509ChainSortOrder::RootFirst => {
                let mut reversed = self.chain.clone();
                reversed.reverse();
                Ok(reversed)
            }
        }
    }
}

#[test]
fn test_get_signing_certificate() {
    let cert = vec![1, 2, 3];
    let key = MockCertificateKey {
        cert: cert.clone(),
        chain: vec![],
    };
    assert_eq!(key.get_signing_certificate().unwrap(), &cert[..]);
}

#[test]
fn test_get_certificate_chain_leaf_first() {
    let chain = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
    let key = MockCertificateKey {
        cert: vec![],
        chain: chain.clone(),
    };
    let result = key
        .get_certificate_chain(X509ChainSortOrder::LeafFirst)
        .unwrap();
    assert_eq!(result, chain);
}

#[test]
fn test_get_certificate_chain_root_first() {
    let chain = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
    let key = MockCertificateKey {
        cert: vec![],
        chain: chain.clone(),
    };
    let result = key
        .get_certificate_chain(X509ChainSortOrder::RootFirst)
        .unwrap();
    let expected = vec![vec![7, 8, 9], vec![4, 5, 6], vec![1, 2, 3]];
    assert_eq!(result, expected);
}
