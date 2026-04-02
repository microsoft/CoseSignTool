// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_certificates::chain_builder::ExplicitCertificateChainBuilder;
use cose_sign1_certificates::error::CertificateError;
use cose_sign1_certificates::signing::source::CertificateSource;

struct MockLocalSource {
    cert: Vec<u8>,
    chain_builder: ExplicitCertificateChainBuilder,
}

impl CertificateSource for MockLocalSource {
    fn get_signing_certificate(&self) -> Result<&[u8], CertificateError> {
        Ok(&self.cert)
    }

    fn has_private_key(&self) -> bool {
        true
    }

    fn get_chain_builder(
        &self,
    ) -> &dyn cose_sign1_certificates::chain_builder::CertificateChainBuilder {
        &self.chain_builder
    }
}

struct MockRemoteSource {
    cert: Vec<u8>,
    chain_builder: ExplicitCertificateChainBuilder,
}

impl CertificateSource for MockRemoteSource {
    fn get_signing_certificate(&self) -> Result<&[u8], CertificateError> {
        Ok(&self.cert)
    }

    fn has_private_key(&self) -> bool {
        false
    }

    fn get_chain_builder(
        &self,
    ) -> &dyn cose_sign1_certificates::chain_builder::CertificateChainBuilder {
        &self.chain_builder
    }
}

#[test]
fn test_local_source_has_private_key() {
    let source = MockLocalSource {
        cert: vec![1, 2, 3],
        chain_builder: ExplicitCertificateChainBuilder::new(vec![]),
    };
    assert!(source.has_private_key());
    assert_eq!(source.get_signing_certificate().unwrap(), &[1, 2, 3]);
}

#[test]
fn test_remote_source_no_private_key() {
    let source = MockRemoteSource {
        cert: vec![4, 5, 6],
        chain_builder: ExplicitCertificateChainBuilder::new(vec![]),
    };
    assert!(!source.has_private_key());
    assert_eq!(source.get_signing_certificate().unwrap(), &[4, 5, 6]);
}

#[test]
fn test_source_chain_builder() {
    let chain = vec![vec![1, 2, 3], vec![4, 5, 6]];
    let source = MockLocalSource {
        cert: vec![1, 2, 3],
        chain_builder: ExplicitCertificateChainBuilder::new(chain.clone()),
    };
    let builder = source.get_chain_builder();
    let result = builder.build_chain(&[]).unwrap();
    assert_eq!(result, chain);
}
