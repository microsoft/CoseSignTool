// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the verification pipeline (`CoseSign1::verify`).
//!
//! The pipeline orchestrates:
//! - signature verification
//! - message validators (x509 chain validation, MST validation)
//! - metadata reporting about what ran

mod common;

use common::*;
use cosesign1::VerificationSettings;
use cosesign1_abstractions::MessageValidatorId;

/// Ensures the pipeline returns early when signature is required and invalid.
#[test]
fn verify_pipeline_returns_early_when_signature_required_and_invalid() {
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    // Require signature; provide an invalid public key override.
    let res = msg.verify(None, Some(b"not-a-key"), &VerificationSettings::default());
    assert!(!res.is_valid);
}

/// Ensures pipeline succeeds when signature verifies and there are no validators.
#[test]
fn verify_pipeline_with_required_signature_can_succeed_without_validators() {
    // Ensure the x509 crate is linked so its inventory registrations are present.
    let _provider_id: cosesign1_abstractions::SigningKeyProviderId = cosesign1_x509::X5C_PROVIDER_ID;

    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der);
    let cose = sign_es256(true, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify(None, None, &VerificationSettings::default());
    assert!(res.is_valid, "{res:?}");
}

/// Ensures `Ok(None)` validators are treated as not-run.
#[test]
fn verify_pipeline_records_validator_not_run_when_it_returns_none() {
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let settings = VerificationSettings::default()
        .without_cose_signature()
        .with_validator(cosesign1_mst::MST_VALIDATOR_ID);

    let res = msg.verify(None, None, &settings);
    assert!(res.is_valid, "{res:?}");
    assert_eq!(
        res.metadata.get("signature.verified").map(|s| s.as_str()),
        Some("false")
    );
    assert_eq!(
        res.metadata.get("validator.mst.ran").map(|s| s.as_str()),
        Some("false")
    );
}

/// Ensures the x5c chain validator can run and be recorded by the pipeline.
#[test]
fn verification_pipeline_runs_x5c_chain_validator() {
    let _validator_id: MessageValidatorId = cosesign1_x509::X5C_CHAIN_VALIDATOR_ID;

    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());

    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut chain = cosesign1_x509::X509ChainVerifyOptions::default();
    chain.trust_mode = cosesign1_x509::X509TrustMode::CustomRoots;
    chain.revocation_mode = cosesign1_x509::X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![cert_der];

    let settings = VerificationSettings::default()
        .with_validator_options(cosesign1_x509::x5c_chain_validation_options(chain));

    let res = msg.verify(None, None, &settings);
    assert!(res.is_valid, "{res:?}");
    assert_eq!(
        res.metadata.get("signature.verified").map(|s| s.as_str()),
        Some("true")
    );
}

/// Ensures x5c validator skips when signature didn't run/failed or options are missing.
#[test]
fn x5c_chain_validator_skips_when_signature_not_run_or_failed_or_options_missing() {
    let _validator_id: MessageValidatorId = cosesign1_x509::X5C_CHAIN_VALIDATOR_ID;

    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());
    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut chain = cosesign1_x509::X509ChainVerifyOptions::default();
    chain.trust_mode = cosesign1_x509::X509TrustMode::CustomRoots;
    chain.revocation_mode = cosesign1_x509::X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![cert_der.clone()];

    // Signature not run -> validator not applicable.
    let settings = VerificationSettings::default()
        .without_cose_signature()
        .with_validator_options(cosesign1_x509::x5c_chain_validation_options(chain.clone()));
    let res = msg.verify(None, None, &settings);
    assert_eq!(
        res.metadata.get("validator.x5c_chain.ran").map(|s| s.as_str()),
        Some("false")
    );

    // Options missing -> validator not applicable even if signature succeeds.
    let settings2 = VerificationSettings::default().with_validator(cosesign1_x509::X5C_CHAIN_VALIDATOR_ID);
    let res2 = msg.verify(None, None, &settings2);
    assert_eq!(
        res2.metadata.get("validator.x5c_chain.ran").map(|s| s.as_str()),
        Some("false")
    );

    // Signature fails -> validator not applicable.
    let mut tampered = cose.clone();
    *tampered.last_mut().unwrap() ^= 0x01;
    let tampered = cosesign1::CoseSign1::from_bytes(&tampered).unwrap();
    let settings3 = VerificationSettings::default()
        .with_validator_options(cosesign1_x509::x5c_chain_validation_options(chain));
    let res3 = tampered.verify(None, None, &settings3);
    // Signature required and failed -> verify() returns early before recording validator ran-state.
    assert!(res3.metadata.get("validator.x5c_chain.ran").is_none());
}

/// Exercises validator error mapping and x5c decoding error branches.
#[test]
fn x5c_chain_validator_error_paths_are_exercised() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());
    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    // Wrong options type.
    let settings = VerificationSettings::default().with_validator_options((
        cosesign1_x509::X5C_CHAIN_VALIDATOR_ID,
        cosesign1_abstractions::OpaqueOptions::new(()),
    ));
    let res = msg.verify(None, Some(cert_der.as_slice()), &settings);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MESSAGE_VALIDATOR_ERROR")));

    // Missing x5c header after a successful signature -> validator not applicable.
    let unprotected_no_x5c: Vec<(TestCborKey, TestCborValue)> = vec![(TestCborKey::Int(99), TestCborValue::Int(1))];
    let cose2 = sign_es256(false, Some(b"hello"), None, &protected, &unprotected_no_x5c, &signing_key);
    let msg2 = cosesign1::CoseSign1::from_bytes(&cose2).unwrap();

    let mut chain = cosesign1_x509::X509ChainVerifyOptions::default();
    chain.trust_mode = cosesign1_x509::X509TrustMode::CustomRoots;
    chain.revocation_mode = cosesign1_x509::X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![cert_der.clone()];

    let settings2 = VerificationSettings::default().with_validator_options(cosesign1_x509::x5c_chain_validation_options(chain));
    let res2 = msg2.verify(None, Some(cert_der.as_slice()), &settings2);
    assert_eq!(
        res2.metadata.get("validator.x5c_chain.ran").map(|s| s.as_str()),
        Some("false")
    );

    // x5c has a non-bstr element.
    let unprotected_bad_x5c: Vec<(TestCborKey, TestCborValue)> = vec![(
        TestCborKey::Int(33),
        TestCborValue::Array(vec![TestCborValue::Int(1)]),
    )];
    let cose3 = sign_es256(false, Some(b"hello"), None, &protected, &unprotected_bad_x5c, &signing_key);
    let msg3 = cosesign1::CoseSign1::from_bytes(&cose3).unwrap();

    let mut chain = cosesign1_x509::X509ChainVerifyOptions::default();
    chain.trust_mode = cosesign1_x509::X509TrustMode::CustomRoots;
    chain.revocation_mode = cosesign1_x509::X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![cert_der.clone()];
    let settings3 = VerificationSettings::default().with_validator_options(cosesign1_x509::x5c_chain_validation_options(chain));

    let res3 = msg3.verify(None, Some(cert_der.as_slice()), &settings3);
    assert!(!res3.is_valid);
    assert!(res3
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MESSAGE_VALIDATOR_ERROR")));
}

/// Missing validator IDs are surfaced as pipeline errors.
#[test]
fn verification_pipeline_reports_missing_validator_as_error() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());

    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let bogus = MessageValidatorId(uuid::uuid!("11111111-1111-1111-1111-111111111111"));
    let settings = VerificationSettings::default().with_validator(bogus);

    let res = msg.verify(None, Some(cert_der.as_slice()), &settings);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MESSAGE_VALIDATOR_ERROR")));
}

/// Pipeline can skip signature verification and attempt MST validation.
#[test]
fn verification_pipeline_can_skip_signature_and_run_mst_validator() {
    let _mst_id: MessageValidatorId = cosesign1_mst::MST_VALIDATOR_ID;

    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der);

    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let settings = VerificationSettings::default()
        .without_cose_signature()
        .with_validator_options(cosesign1_mst::mst_message_validation_options(
            Default::default(),
            Default::default(),
        ));

    let res = msg.verify(None, None, &settings);
    assert_eq!(
        res.metadata.get("signature.verified").map(|s| s.as_str()),
        Some("false")
    );
    assert!(!res.is_valid);
}

/// MST validator is skipped if unconfigured and errors on wrong options type.
#[test]
fn mst_validator_skips_when_unconfigured_and_errors_on_wrong_options_type() {
    let _mst_id: MessageValidatorId = cosesign1_mst::MST_VALIDATOR_ID;
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der);
    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    // Enabled but not configured -> validator should report ran=false.
    let settings = VerificationSettings::default()
        .without_cose_signature()
        .with_validator(cosesign1_mst::MST_VALIDATOR_ID);
    let res = msg.verify(None, None, &settings);
    assert_eq!(
        res.metadata.get("validator.mst.ran").map(|s| s.as_str()),
        Some("false")
    );

    // Wrong options type -> message validator error.
    let settings2 = VerificationSettings::default().without_cose_signature().with_validator_options((
        cosesign1_mst::MST_VALIDATOR_ID,
        cosesign1_abstractions::OpaqueOptions::new(()),
    ));
    let res2 = msg.verify(None, None, &settings2);
    assert!(!res2.is_valid);
    assert!(res2
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MESSAGE_VALIDATOR_ERROR")));
}

/// Ensures validator registrations have stable names.
#[test]
fn validator_name_methods_are_exercised() {
    let _mst_id: MessageValidatorId = cosesign1_mst::MST_VALIDATOR_ID;
    let _x5c_id: MessageValidatorId = cosesign1_x509::X5C_CHAIN_VALIDATOR_ID;

    let regs = cosesign1_abstractions::validators_ordered();
    assert!(regs
        .iter()
        .any(|r| r.validator.name() == cosesign1_mst::MST_VALIDATOR_NAME));
    assert!(regs
        .iter()
        .any(|r| r.validator.name() == cosesign1_x509::X5C_CHAIN_VALIDATOR_NAME));
}
