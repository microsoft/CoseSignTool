use cose_sign1_validation::fluent::*;
use cose_sign1_validation_certificates::signing_key_resolver::X509CertificateSigningKeyResolver;
use cose_sign1_validation_trust::CoseHeaderLocation;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P384_SHA384};
use tinycbor::{Encode, Encoder};

fn cose_sign1_with_protected_x5chain_only(leaf_der: &[u8]) -> Vec<u8> {
    // Minimal COSE_Sign1 bytes that contain an x5chain in the protected header.
    // Signature/payload don't matter for signing-key *resolution*.

    // Protected header map: { 33: bstr(cert_der) }
    let mut hdr_buf = vec![0u8; 4096];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(1).unwrap();
    (33i64).encode(&mut hdr_enc).unwrap();
    leaf_der.encode(&mut hdr_enc).unwrap();
    let used = hdr_len - hdr_enc.0.len();
    hdr_buf.truncate(used);

    let mut buf = vec![0u8; 4096 + leaf_der.len()];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();
    // protected: bstr(map)
    hdr_buf.as_slice().encode(&mut enc).unwrap();
    // unprotected: {}
    enc.map(0).unwrap();
    // payload: nil
    Option::<&[u8]>::None.encode(&mut enc).unwrap();
    // signature: empty bstr
    (&[] as &[u8]).encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
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
    let msg = CoseSign1::from_cbor(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateSigningKeyResolver;
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
    assert!(res.signing_key.is_some());
}

#[test]
fn signing_key_resolver_reports_key_mismatch_for_es256_instead_of_parse_failure() {
    // If the leaf certificate's public key is not compatible with ES256, verification should
    // report a clean mismatch/unsupported error (not an x509 parse error).

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let params = CertificateParams::new(vec!["resolver-pqc-smoke".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let leaf_der = cert.der().to_vec();

    let cose_bytes = cose_sign1_with_protected_x5chain_only(leaf_der.as_slice());
    let msg = CoseSign1::from_cbor(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateSigningKeyResolver;
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(res.is_success);

    let key = res.signing_key.unwrap();
    let err = key
        .verify(-7, b"sig_structure", &[0u8; 64])
        .expect_err("expected ES256 key mismatch error");

    assert!(
        err.contains("mismatch") || err.contains("unexpected_ec_public_key_len"),
        "unexpected error: {err}"
    );
}
