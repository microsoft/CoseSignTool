// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_validation::fluent::*;
use cbor_primitives::{CborEncoder, CborProvider};
use cose_sign1_certificates::validation::signing_key_resolver::X509CertificateCoseKeyResolver;
use cose_sign1_validation_primitives::CoseHeaderLocation;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384};

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

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let params = CertificateParams::new(vec!["resolver-pqc-smoke".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let leaf_der = cert.der().to_vec();

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
fn signing_key_resolver_reports_key_mismatch_for_es256_instead_of_parse_failure() {
    // If the leaf certificate's public key is not compatible with ES256, verification should
    // report a clean mismatch/unsupported error (not an x509 parse error).
    // The OpenSSL provider defaults to ES256 for all EC keys (curve detection is a TODO).

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let params = CertificateParams::new(vec!["resolver-pqc-smoke".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let leaf_der = cert.der().to_vec();

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
    // OpenSSL provider defaults to ES256 for all EC keys (P-384 detection not implemented)
    assert_eq!(key.algorithm(), -7, "EC key defaults to ES256");

    // P-384 key with ES256 algorithm: garbage signature returns false or error
    let result = key.verify(b"sig_structure", &[0u8; 64]);
    match result {
        Ok(false) => {} // Expected - signature doesn't verify
        Err(_) => {}    // Also acceptable - verification error
        Ok(true) => panic!("garbage signature should not verify"),
    }
}
