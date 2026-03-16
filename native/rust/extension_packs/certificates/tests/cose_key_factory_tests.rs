// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_certificates::cose_key_factory::{HashAlgorithm, X509CertificateCoseKeyFactory};

#[test]
fn test_get_hash_algorithm_for_key_size() {
    assert_eq!(
        X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(2048, false),
        HashAlgorithm::Sha256
    );
    
    assert_eq!(
        X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(3072, false),
        HashAlgorithm::Sha384
    );
    
    assert_eq!(
        X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(4096, false),
        HashAlgorithm::Sha512
    );
    
    // EC P-521 should use SHA-384 regardless of key size
    assert_eq!(
        X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(521, true),
        HashAlgorithm::Sha384
    );
}

#[test]
fn test_hash_algorithm_cose_ids() {
    assert_eq!(HashAlgorithm::Sha256.cose_algorithm_id(), -16);
    assert_eq!(HashAlgorithm::Sha384.cose_algorithm_id(), -43);
    assert_eq!(HashAlgorithm::Sha512.cose_algorithm_id(), -44);
}
