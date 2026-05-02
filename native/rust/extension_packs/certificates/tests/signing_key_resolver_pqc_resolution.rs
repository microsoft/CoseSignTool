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

fn cose_sign1_with_protected_x5chain_only(leaf_der: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;

    // Protected header map: { 33: bstr(cert_der) }
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_bstr(leaf_der).unwrap();
    let hdr_buf = hdr_enc.into_bytes();

    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();
    // protected: bstr(map)
    enc.encode_bstr(&hdr_buf).unwrap();
    // unprotected: {}
    enc.encode_map(0).unwrap();
    // payload: nil
    enc.encode_null().unwrap();
    // signature: empty bstr
    enc.encode_bstr(&[]).unwrap();

    enc.into_bytes()
}

#[test]
fn signing_key_resolver_can_resolve_non_p256_ec_keys_without_failing_resolution() {
    // This uses P-384 as a stand-in for "non-P256" (including PQC/unknown key types).
    // The key point: resolution should succeed and not be reported as an X509 parse failure.

    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let p384_cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=resolver-pqc-smoke")
                .add_subject_alternative_name("resolver-pqc-smoke")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_key_size(384),
        )
        .unwrap();
    let leaf_der = p384_cert.cert_der.clone();

    let cose_bytes = cose_sign1_with_protected_x5chain_only(leaf_der.as_slice());
    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(
        res.is_success,
        "expected resolution success, got error_code={:?} error_message={:?}",
        res.error_code, res.error_message
    );
    assert!(res.cose_key.is_some());
}

#[test]
fn signing_key_resolver_detects_p384_curve_and_assigns_es384() {
    // The OpenSSL provider detects the EC curve from the leaf certificate's public key
    // and assigns the correct COSE algorithm: P-384 → ES384 (-35).

    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let p384_cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=resolver-pqc-smoke")
                .add_subject_alternative_name("resolver-pqc-smoke")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_key_size(384),
        )
        .unwrap();
    let leaf_der = p384_cert.cert_der.clone();

    let cose_bytes = cose_sign1_with_protected_x5chain_only(leaf_der.as_slice());
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

    // Garbage signature against correct algorithm should not verify
    let result = key.verify(b"sig_structure", &[0u8; 96]);
    match result {
        Ok(false) => {} // Expected - signature doesn't verify
        Err(_) => {}    // Also acceptable - verification error
        Ok(true) => panic!("garbage signature should not verify"),
    }
}
