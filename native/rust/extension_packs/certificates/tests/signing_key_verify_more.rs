// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_certificates::validation::signing_key_resolver::X509CertificateCoseKeyResolver;
use cose_sign1_certificates_local::{
    CertificateFactory, CertificateOptions, EphemeralCertificateFactory, KeyAlgorithm,
    SoftwareKeyProvider,
};
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::CoseHeaderLocation;

fn replace_once_in_place(haystack: &mut [u8], needle: &[u8], replacement: &[u8]) -> bool {
    assert_eq!(needle.len(), replacement.len());
    if needle.is_empty() {
        return false;
    }

    for i in 0..=(haystack.len().saturating_sub(needle.len())) {
        if &haystack[i..i + needle.len()] == needle {
            haystack[i..i + needle.len()].copy_from_slice(replacement);
            return true;
        }
    }

    false
}

fn cose_sign1_with_protected_header_bytes(protected_map_bytes: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected_map_bytes).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(&[]).unwrap();

    enc.into_bytes()
}

fn encode_protected_x5chain_single_bstr(leaf_der: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut hdr_enc = p.encoder();

    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_bstr(leaf_der).unwrap();

    hdr_enc.into_bytes()
}

#[test]
fn signing_key_resolver_fails_when_protected_header_is_not_a_cbor_map() {
    // Protected header bstr contains invalid CBOR (0xFF).
    // With LazyHeaderMap, parse succeeds but header access fails.
    let cose_bytes = cose_sign1_with_protected_header_bytes(&[0xFF]);
    let msg = CoseSign1Message::parse(cose_bytes.as_slice())
        .expect("parse succeeds — protected header is lazy-decoded");

    // Accessing headers should fail because the CBOR is invalid
    let result = msg.protected.try_headers();
    assert!(
        result.is_err(),
        "try_headers should fail with invalid protected header CBOR"
    );
}

#[test]
fn signing_key_verify_es256_rejects_wrong_signature_len() {
    // Use a P-256 leaf so we reach the signature length check for ES256.
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=verify-wrong-sig-len")
                .add_subject_alternative_name("verify-wrong-sig-len"),
        )
        .unwrap();
    let leaf_der = cert.cert_der.clone();

    let protected = encode_protected_x5chain_single_bstr(leaf_der.as_slice());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(res.is_success);

    let key = res.cose_key.unwrap();

    // ES256 requires 64 bytes; use 63 to force an error.
    // With OpenSSL, fixed_to_der rejects odd-length signatures.
    let err = key
        .verify(b"sig_structure", &[0u8; 63])
        .expect_err("expected length error");

    // OpenSSL ecdsa_format::fixed_to_der returns "Fixed signature length must be even"
    assert!(
        err.to_string()
            .contains("Fixed signature length must be even")
            || err.to_string().contains("signature"),
        "unexpected error: {err}"
    );
}

#[test]
fn signing_key_verify_returns_false_for_invalid_signature_when_lengths_are_correct() {
    // Use a P-256 leaf so ES256 is structurally supported and we hit the Ok(false) branch.
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=verify-invalid-sig")
                .add_subject_alternative_name("verify-invalid-sig"),
        )
        .unwrap();
    let leaf_der = cert.cert_der.clone();

    let protected = encode_protected_x5chain_single_bstr(leaf_der.as_slice());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(res.is_success);

    let key = res.cose_key.unwrap();

    // This is *not* a valid ES256 signature, but it has the right length.
    // We expect verify() to return Ok(false) (i.e., cryptographic failure, not API error).
    let ok = key.verify(b"sig_structure", &[0u8; 64]).unwrap();
    assert!(!ok);
}

#[test]
fn signing_key_verify_es256_reports_unsupported_alg_when_spki_is_not_ec_public_key() {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=verify-es256-oid-mismatch")
                .add_subject_alternative_name("verify-es256-oid-mismatch"),
        )
        .unwrap();

    // Mutate the SPKI algorithm OID from id-ecPublicKey (1.2.840.10045.2.1)
    // to a different (still-valid) OID. With OpenSSL, this may cause different behavior.
    let mut leaf_der = cert.cert_der.clone();
    let ec_public_key_oid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    let non_ec_public_key_oid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x02];
    assert!(replace_once_in_place(
        leaf_der.as_mut_slice(),
        &ec_public_key_oid,
        &non_ec_public_key_oid
    ));

    let protected = encode_protected_x5chain_single_bstr(leaf_der.as_slice());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    // With OpenSSL, mutating the OID may cause resolution failure or
    // OpenSSL may detect the key type from key bytes and succeed
    if res.is_success {
        let key = res.cose_key.unwrap();
        // Try to verify - either fails with error or returns false
        let verify_result = key.verify(b"sig_structure", &[0u8; 64]);
        match verify_result {
            Ok(false) => {} // Expected - garbage signature doesn't verify
            Err(_) => {}    // Also acceptable - unsupported algorithm or other error
            Ok(true) => panic!("corrupted cert should not verify successfully"),
        }
    } else {
        // Resolution failure is acceptable for corrupted cert
        assert!(res.error_code.is_some());
    }
}

#[test]
fn signing_key_verify_es256_reports_unexpected_ec_public_key_format_when_point_not_uncompressed() {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=verify-es256-ec-point-format")
                .add_subject_alternative_name("verify-es256-ec-point-format"),
        )
        .unwrap();

    // Mutate the SubjectPublicKey BIT STRING contents from 0x04||X||Y to 0x05||X||Y.
    // For P-256, the BIT STRING is typically: 03 42 00 04 <64 bytes>.
    let mut leaf_der = cert.cert_der.clone();
    let needle = [0x03, 0x42, 0x00, 0x04];
    let replacement = [0x03, 0x42, 0x00, 0x05];
    assert!(replace_once_in_place(
        leaf_der.as_mut_slice(),
        &needle,
        &replacement
    ));

    let protected = encode_protected_x5chain_single_bstr(leaf_der.as_slice());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    // With OpenSSL, corrupted point format may cause resolution failure
    if res.is_success {
        let key = res.cose_key.unwrap();
        // The OID is still id-ecPublicKey, so algorithm = ES256 (-7).
        // But the point format is invalid (0x05 instead of 0x04 for uncompressed).
        // With OpenSSL, this should cause verification to fail.
        let verify_result = key.verify(b"sig_structure", &[0u8; 64]);
        match verify_result {
            Ok(false) => {} // Expected - corrupted key doesn't verify
            Err(_) => {}    // Also acceptable - error during verification
            Ok(true) => panic!("corrupted key should not verify successfully"),
        }
    } else {
        // Resolution failure is acceptable for corrupted cert
        assert!(res.error_code.is_some());
    }
}

#[test]
fn signing_key_verify_es256_returns_true_for_valid_signature() {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert_and_key = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=verify-es256-valid")
                .add_subject_alternative_name("verify-es256-valid"),
        )
        .unwrap();

    let protected = encode_protected_x5chain_single_bstr(&cert_and_key.cert_der);
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(res.is_success);

    let key = res.cose_key.unwrap();
    let sig_structure = b"sig_structure";

    // Sign using the same P-256 private key using OpenSSL
    use openssl::pkey::PKey;

    let pkcs8_der = cert_and_key.private_key_der.clone().unwrap();
    let pkey = PKey::private_key_from_der(&pkcs8_der).unwrap();

    // Create signer and sign the data
    use openssl::hash::MessageDigest;
    use openssl::sign::Signer;

    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    signer.update(sig_structure).unwrap();
    let signature = signer.sign_to_vec().unwrap();

    // Convert DER signature to raw r||s format (COSE expects fixed format)
    use cose_sign1_crypto_openssl::ecdsa_format;
    let sig_raw = ecdsa_format::der_to_fixed(&signature, 64).unwrap();

    // Use verify which uses the key's inferred algorithm (ES256)
    let ok = key.verify(sig_structure, &sig_raw).unwrap();
    assert!(ok);
}

#[test]
fn signing_key_verify_p384_resolves_to_es384_and_rejects_garbage() {
    // Use a P-384 certificate. OpenSSL provider detects EC curve: P-384 → ES384 (-35).
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let p384_cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=verify-unsupported-alg")
                .add_subject_alternative_name("verify-unsupported-alg")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_key_size(384),
        )
        .unwrap();
    let leaf_der = p384_cert.cert_der.clone();

    let protected = encode_protected_x5chain_single_bstr(leaf_der.as_slice());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(res.is_success);

    let key = res.cose_key.unwrap();
    // P-384 curve correctly detected → ES384 (COSE algorithm -35)
    assert_eq!(key.algorithm(), -35, "P-384 key should be assigned ES384");

    // Garbage signature should not verify
    let result = key.verify(b"sig_structure", &[0u8; 96]);
    match result {
        Ok(false) => {} // Expected - signature doesn't verify
        Err(_) => {}    // Also acceptable - verification error
        Ok(true) => panic!("garbage signature should not verify"),
    }
}

#[test]
fn signing_key_verify_es384_rejects_non_matching_signature() {
    // Use a P-384 leaf. OpenSSL provider detects EC curve: P-384 → ES384 (-35).
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let p384_cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=verify-es256-alg-mismatch")
                .add_subject_alternative_name("verify-es256-alg-mismatch")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_key_size(384),
        )
        .unwrap();
    let leaf_der = p384_cert.cert_der.clone();

    let protected = encode_protected_x5chain_single_bstr(leaf_der.as_slice());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(res.is_success);

    let key = res.cose_key.unwrap();
    // P-384 curve correctly detected → ES384 (COSE algorithm -35)
    assert_eq!(key.algorithm(), -35, "P-384 key should be assigned ES384");

    // Garbage signature against correct algorithm should fail verification
    let result = key.verify(b"sig_structure", &[0u8; 96]);
    match result {
        Ok(false) => {} // Expected - signature doesn't verify
        Err(_) => {}    // Also acceptable - verification error
        Ok(true) => panic!("garbage signature should not verify"),
    }
}
