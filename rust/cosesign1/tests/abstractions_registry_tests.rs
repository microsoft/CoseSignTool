// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `cosesign1_abstractions` registry/glue.
//!
//! `cosesign1` integrates with `cosesign1_abstractions` to resolve keys and run
//! validators. These tests validate the registry behavior and error mapping.

mod common;

use common::*;
use cosesign1_abstractions::{MessageValidatorId, SigningKeyProviderId};

/// Exercises provider registry lookup/sorting and error mapping for x5c provider.
#[test]
fn key_provider_registry_and_x5c_provider_error_paths_are_exercised() {
    let _provider_id: SigningKeyProviderId = cosesign1_x509::X5C_PROVIDER_ID;

    // Provider name lookup.
    assert_eq!(
        cosesign1_abstractions::provider_name(cosesign1_x509::X5C_PROVIDER_ID),
        Some(cosesign1_x509::X5C_PROVIDER_NAME)
    );
    assert!(cosesign1_abstractions::provider_name(SigningKeyProviderId(uuid::uuid!(
        "22222222-2222-2222-2222-222222222222"
    )))
    .is_none());

    // Exercise providers_ordered sorting path.
    let regs = cosesign1_abstractions::providers_ordered();
    assert!(!regs.is_empty());

    // ResolvedSigningKey constructors.
    let _ = cosesign1_abstractions::ResolvedSigningKey::new(vec![1, 2, 3]);
    let _ = cosesign1_abstractions::ResolvedSigningKey::with_material(vec![1, 2, 3], Box::new(vec![4u8]));

    // No x5c -> no provider matched.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let parsed = cosesign1::parse_cose_sign1(&cose).unwrap();
    match cosesign1_abstractions::resolve_signing_key(&parsed) {
        Err(cosesign1_abstractions::ResolvePublicKeyError::NoProviderMatched) => {}
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("expected NoProviderMatched"),
    }

    // Bad x5c element type -> provider failed.
    let unprotected_bad_x5c: Vec<(TestCborKey, TestCborValue)> = vec![(
        TestCborKey::Int(33),
        TestCborValue::Array(vec![TestCborValue::Int(1)]),
    )];
    let cose2 = encode_cose_sign1(false, &protected, &unprotected_bad_x5c, Some(b"hello"), &[0u8; 64]);
    let parsed2 = cosesign1::parse_cose_sign1(&cose2).unwrap();
    match cosesign1_abstractions::resolve_signing_key(&parsed2) {
        Err(cosesign1_abstractions::ResolvePublicKeyError::ProviderFailed { .. }) => {}
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("expected ProviderFailed"),
    }

    // Empty x5c array.
    let unprotected_empty_x5c: Vec<(TestCborKey, TestCborValue)> =
        vec![(TestCborKey::Int(33), TestCborValue::Array(vec![]))];
    let cose3 = encode_cose_sign1(false, &protected, &unprotected_empty_x5c, Some(b"hello"), &[0u8; 64]);
    let parsed3 = cosesign1::parse_cose_sign1(&cose3).unwrap();
    match cosesign1_abstractions::resolve_signing_key(&parsed3) {
        Err(cosesign1_abstractions::ResolvePublicKeyError::ProviderFailed { .. }) => {}
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("expected ProviderFailed"),
    }

    // Empty leaf bytes.
    let unprotected_empty_leaf: Vec<(TestCborKey, TestCborValue)> = vec![(
        TestCborKey::Int(33),
        TestCborValue::Array(vec![TestCborValue::Bytes(vec![])]),
    )];
    let cose4 = encode_cose_sign1(false, &protected, &unprotected_empty_leaf, Some(b"hello"), &[0u8; 64]);
    let parsed4 = cosesign1::parse_cose_sign1(&cose4).unwrap();
    match cosesign1_abstractions::resolve_signing_key(&parsed4) {
        Err(cosesign1_abstractions::ResolvePublicKeyError::ProviderFailed { .. }) => {}
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("expected ProviderFailed"),
    }
}

/// MST validator returns `Ok(None)` when enabled but unconfigured.
#[test]
fn mst_message_validator_validate_returns_none_when_unconfigured() {
    let _mst_id: MessageValidatorId = cosesign1_mst::MST_VALIDATOR_ID;

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let sig_ok = cosesign1_abstractions::ValidationResult::success("Signature", Default::default());
    let ctx = cosesign1_abstractions::MessageValidationContext {
        cose_bytes: &msg.bytes,
        parsed: &msg.parsed,
        payload_to_verify: None,
        signature_result: Some(&sig_ok),
    };

    let res = cosesign1_abstractions::run_validator_by_id(cosesign1_mst::MST_VALIDATOR_ID, &ctx, None).unwrap();
    assert!(res.is_none());
}

/// x5c chain message validator returns `Ok(None)` for early-return conditions.
#[test]
fn x5c_chain_message_validator_early_returns_are_exercised() {
    let _validator_id: MessageValidatorId = cosesign1_x509::X5C_CHAIN_VALIDATOR_ID;

    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());
    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let sig_ok = cosesign1_abstractions::ValidationResult::success("Signature", Default::default());
    let sig_bad =
        cosesign1_abstractions::ValidationResult::failure_message("Signature", "bad", Some("BAD".to_string()));

    // signature_result missing => Ok(None)
    let ctx_none = cosesign1_abstractions::MessageValidationContext {
        cose_bytes: &msg.bytes,
        parsed: &msg.parsed,
        payload_to_verify: None,
        signature_result: None,
    };
    assert!(cosesign1_abstractions::run_validator_by_id(cosesign1_x509::X5C_CHAIN_VALIDATOR_ID, &ctx_none, None)
        .unwrap()
        .is_none());

    // signature_result present but invalid => Ok(None)
    let ctx_bad = cosesign1_abstractions::MessageValidationContext {
        signature_result: Some(&sig_bad),
        ..ctx_none
    };
    assert!(cosesign1_abstractions::run_validator_by_id(cosesign1_x509::X5C_CHAIN_VALIDATOR_ID, &ctx_bad, None)
        .unwrap()
        .is_none());

    // signature_result valid but no options => Ok(None)
    let ctx_ok = cosesign1_abstractions::MessageValidationContext {
        signature_result: Some(&sig_ok),
        ..ctx_none
    };
    assert!(cosesign1_abstractions::run_validator_by_id(cosesign1_x509::X5C_CHAIN_VALIDATOR_ID, &ctx_ok, None)
        .unwrap()
        .is_none());
}

/// `run_validator_by_id` returns the `ValidatorFailed` error variant on type mismatch.
#[test]
fn run_validator_by_id_error_variant_is_exercised() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());
    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let sig_ok = cosesign1_abstractions::ValidationResult::success("Signature", Default::default());
    let ctx = cosesign1_abstractions::MessageValidationContext {
        cose_bytes: &msg.bytes,
        parsed: &msg.parsed,
        payload_to_verify: None,
        signature_result: Some(&sig_ok),
    };

    let err = cosesign1_abstractions::run_validator_by_id(
        cosesign1_x509::X5C_CHAIN_VALIDATOR_ID,
        &ctx,
        Some(&cosesign1_abstractions::OpaqueOptions::new(())),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        cosesign1_abstractions::RunValidatorError::ValidatorFailed { .. }
    ));
}
