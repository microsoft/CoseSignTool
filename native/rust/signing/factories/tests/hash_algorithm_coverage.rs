// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional test coverage for HashAlgorithm methods.

use cose_sign1_factories::indirect::HashAlgorithm;

#[test]
fn test_hash_algorithm_cose_algorithm_id_sha256() {
    let alg = HashAlgorithm::Sha256;
    assert_eq!(alg.cose_algorithm_id(), -16);
}

#[test]
fn test_hash_algorithm_cose_algorithm_id_sha384() {
    let alg = HashAlgorithm::Sha384;
    assert_eq!(alg.cose_algorithm_id(), -43);
}

#[test]
fn test_hash_algorithm_cose_algorithm_id_sha512() {
    let alg = HashAlgorithm::Sha512;
    assert_eq!(alg.cose_algorithm_id(), -44);
}

#[test]
fn test_hash_algorithm_name_sha256() {
    let alg = HashAlgorithm::Sha256;
    assert_eq!(alg.name(), "sha-256");
}

#[test]
fn test_hash_algorithm_name_sha384() {
    let alg = HashAlgorithm::Sha384;
    assert_eq!(alg.name(), "sha-384");
}

#[test]
fn test_hash_algorithm_name_sha512() {
    let alg = HashAlgorithm::Sha512;
    assert_eq!(alg.name(), "sha-512");
}
