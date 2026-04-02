// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Edge-case coverage for cose_sign1_factories: FactoryError Display,
//! std::error::Error, DirectSignatureOptions, IndirectSignatureOptions,
//! and HashAlgorithm.

use cose_sign1_factories::direct::DirectSignatureOptions;
use cose_sign1_factories::indirect::{HashAlgorithm, IndirectSignatureOptions};
use cose_sign1_factories::FactoryError;

// ---------- FactoryError Display ----------

#[test]
fn error_display_all_variants() {
    let cases: Vec<(FactoryError, &str)> = vec![
        (FactoryError::SigningFailed("s".into()), "Signing failed: s"),
        (
            FactoryError::VerificationFailed("v".into()),
            "Verification failed: v",
        ),
        (FactoryError::InvalidInput("i".into()), "Invalid input: i"),
        (FactoryError::CborError("c".into()), "CBOR error: c"),
        (
            FactoryError::TransparencyFailed("t".into()),
            "Transparency failed: t",
        ),
        (
            FactoryError::PayloadTooLargeForEmbedding(200, 100),
            "Payload too large for embedding: 200 bytes (max 100)",
        ),
    ];
    for (err, expected) in cases {
        assert_eq!(format!("{err}"), expected);
    }
}

#[test]
fn error_implements_std_error() {
    let err = FactoryError::CborError("x".into());
    let trait_obj: &dyn std::error::Error = &err;
    assert!(trait_obj.source().is_none());
}

// ---------- DirectSignatureOptions ----------

#[test]
fn direct_options_defaults() {
    let opts = DirectSignatureOptions::new();
    assert!(opts.embed_payload);
    assert!(opts.additional_data.is_empty());
    assert!(!opts.disable_transparency);
    assert!(opts.fail_on_transparency_error);
    assert!(opts.max_embed_size.is_none());
}

#[test]
fn direct_options_builder_chain() {
    let opts = DirectSignatureOptions::new()
        .with_embed_payload(false)
        .with_additional_data(vec![1, 2, 3])
        .with_max_embed_size(1024)
        .with_disable_transparency(true);
    assert!(!opts.embed_payload);
    assert_eq!(opts.additional_data, vec![1, 2, 3]);
    assert_eq!(opts.max_embed_size, Some(1024));
    assert!(opts.disable_transparency);
}

#[test]
fn direct_options_debug() {
    let opts = DirectSignatureOptions::new();
    let dbg = format!("{:?}", opts);
    assert!(dbg.contains("DirectSignatureOptions"));
}

// ---------- IndirectSignatureOptions ----------

#[test]
fn indirect_options_defaults() {
    let opts = IndirectSignatureOptions::new();
    assert_eq!(opts.payload_hash_algorithm, HashAlgorithm::Sha256);
    assert!(opts.payload_location.is_none());
}

#[test]
fn indirect_options_builder_chain() {
    let opts = IndirectSignatureOptions::new()
        .with_hash_algorithm(HashAlgorithm::Sha384)
        .with_payload_location("https://example.com/payload");
    assert_eq!(opts.payload_hash_algorithm, HashAlgorithm::Sha384);
    assert_eq!(
        opts.payload_location.as_deref(),
        Some("https://example.com/payload")
    );
}

// ---------- HashAlgorithm ----------

#[test]
fn hash_algorithm_cose_ids() {
    assert_eq!(HashAlgorithm::Sha256.cose_algorithm_id(), -16);
    assert_eq!(HashAlgorithm::Sha384.cose_algorithm_id(), -43);
    assert_eq!(HashAlgorithm::Sha512.cose_algorithm_id(), -44);
}

#[test]
fn hash_algorithm_names() {
    assert_eq!(HashAlgorithm::Sha256.name(), "sha-256");
    assert_eq!(HashAlgorithm::Sha384.name(), "sha-384");
    assert_eq!(HashAlgorithm::Sha512.name(), "sha-512");
}

#[test]
fn hash_algorithm_default_is_sha256() {
    assert_eq!(HashAlgorithm::default(), HashAlgorithm::Sha256);
}
