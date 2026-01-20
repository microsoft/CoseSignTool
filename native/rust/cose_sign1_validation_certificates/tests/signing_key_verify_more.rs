use cose_sign1_validation::fluent::*;
use cose_sign1_validation_certificates::signing_key_resolver::X509CertificateSigningKeyResolver;
use cose_sign1_validation_trust::CoseHeaderLocation;
use rcgen::{generate_simple_self_signed, CertificateParams, CertifiedKey, KeyPair, PKCS_ECDSA_P384_SHA384};
use tinycbor::{Encode, Encoder};

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
    let mut buf = vec![0u8; 4096 + protected_map_bytes.len()];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();
    protected_map_bytes.encode(&mut enc).unwrap();
    enc.map(0).unwrap();
    Option::<&[u8]>::None.encode(&mut enc).unwrap();
    (&[] as &[u8]).encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_protected_x5chain_single_bstr(leaf_der: &[u8]) -> Vec<u8> {
    let mut hdr_buf = vec![0u8; 4096 + leaf_der.len()];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());

    hdr_enc.map(1).unwrap();
    (33i64).encode(&mut hdr_enc).unwrap();
    leaf_der.encode(&mut hdr_enc).unwrap();

    let used = hdr_len - hdr_enc.0.len();
    hdr_buf.truncate(used);
    hdr_buf
}

#[test]
fn signing_key_resolver_fails_when_protected_header_is_not_a_cbor_map() {
    // Protected header bstr contains invalid CBOR (0xFF).
    let cose_bytes = cose_sign1_with_protected_header_bytes(&[0xFF]);
    let msg = CoseSign1::from_cbor(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateSigningKeyResolver;
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(!res.is_success);
    assert_eq!(res.error_code.as_deref(), Some("X5CHAIN_NOT_FOUND"));
    let msg = res.error_message.unwrap_or_default();
    assert!(
        msg.contains("header_map_decode_failed") || msg.contains("map"),
        "unexpected error message: {msg}"
    );
}

#[test]
fn signing_key_verify_es256_rejects_wrong_signature_len() {
    // Use a P-256 leaf so we reach the signature length check for ES256.
    let CertifiedKey { cert, .. } =
        generate_simple_self_signed(vec!["verify-wrong-sig-len".to_string()]).unwrap();
    let leaf_der = cert.der().as_ref().to_vec();

    let protected = encode_protected_x5chain_single_bstr(leaf_der.as_slice());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
    let msg = CoseSign1::from_cbor(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateSigningKeyResolver;
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(res.is_success);

    let key = res.signing_key.unwrap();

    // ES256 requires 64 bytes; use 63 to force the explicit error.
    let err = key
        .verify(-7, b"sig_structure", &[0u8; 63])
        .expect_err("expected length error");

    assert!(err.contains("unexpected_signature_len"), "unexpected error: {err}");
}

#[test]
fn signing_key_verify_returns_false_for_invalid_signature_when_lengths_are_correct() {
    // Use a P-256 leaf so ES256 is structurally supported and we hit the Ok(false) branch.
    let CertifiedKey { cert, .. } =
        generate_simple_self_signed(vec!["verify-invalid-sig".to_string()]).unwrap();
    let leaf_der = cert.der().as_ref().to_vec();

    let protected = encode_protected_x5chain_single_bstr(leaf_der.as_slice());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
    let msg = CoseSign1::from_cbor(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateSigningKeyResolver;
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(res.is_success);

    let key = res.signing_key.unwrap();

    // This is *not* a valid ES256 signature, but it has the right length.
    // We expect verify() to return Ok(false) (i.e., cryptographic failure, not API error).
    let ok = key.verify(-7, b"sig_structure", &[0u8; 64]).unwrap();
    assert!(!ok);
}

#[test]
fn signing_key_verify_es256_reports_algorithm_oid_mismatch_when_spki_is_not_ec_public_key() {
    let CertifiedKey { cert, .. } =
        generate_simple_self_signed(vec!["verify-es256-oid-mismatch".to_string()]).unwrap();

    // Mutate the SPKI algorithm OID from id-ecPublicKey (1.2.840.10045.2.1)
    // to a different (still-valid) OID so parsing succeeds but ES256 refuses the key.
    let mut leaf_der = cert.der().as_ref().to_vec();
    let ec_public_key_oid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    let non_ec_public_key_oid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x02];
    assert!(replace_once_in_place(
        leaf_der.as_mut_slice(),
        &ec_public_key_oid,
        &non_ec_public_key_oid
    ));

    let protected = encode_protected_x5chain_single_bstr(leaf_der.as_slice());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
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
        .expect_err("expected algorithm mismatch error");

    assert!(
        err.contains("certificate_public_key_alg_mismatch_for_es256"),
        "unexpected error: {err}"
    );
}

#[test]
fn signing_key_verify_es256_reports_unexpected_ec_public_key_format_when_point_not_uncompressed() {
    let CertifiedKey { cert, .. } = generate_simple_self_signed(vec![
        "verify-es256-ec-point-format".to_string(),
    ])
    .unwrap();

    // Mutate the SubjectPublicKey BIT STRING contents from 0x04||X||Y to 0x05||X||Y.
    // For P-256, the BIT STRING is typically: 03 42 00 04 <64 bytes>.
    let mut leaf_der = cert.der().as_ref().to_vec();
    let needle = [0x03, 0x42, 0x00, 0x04];
    let replacement = [0x03, 0x42, 0x00, 0x05];
    assert!(replace_once_in_place(
        leaf_der.as_mut_slice(),
        &needle,
        &replacement
    ));

    let protected = encode_protected_x5chain_single_bstr(leaf_der.as_slice());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
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
        .expect_err("expected EC key format error");

    assert!(
        err.contains("unexpected_ec_public_key_format_for_es256"),
        "unexpected error: {err}"
    );
}

#[test]
fn signing_key_verify_es256_returns_true_for_valid_signature() {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["verify-es256-valid".to_string()]).unwrap();

    let protected = encode_protected_x5chain_single_bstr(cert.der().as_ref());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
    let msg = CoseSign1::from_cbor(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateSigningKeyResolver;
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(res.is_success);

    let key = res.signing_key.unwrap();
    let sig_structure = b"sig_structure";

    // Sign using the same P-256 private key in fixed (r||s) format.
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = key_pair.serialize_der();
    let signer = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .unwrap();
    let sig = signer.sign(&rng, sig_structure).unwrap();

    let ok = key.verify(-7, sig_structure, sig.as_ref()).unwrap();
    assert!(ok);
}

#[test]
#[cfg(not(feature = "pqc-mldsa"))]
fn signing_key_verify_mldsa_returns_disabled_error_for_all_variants_when_feature_off() {
    let CertifiedKey { cert, .. } =
        generate_simple_self_signed(vec!["verify-mldsa-disabled".to_string()]).unwrap();

    let protected = encode_protected_x5chain_single_bstr(cert.der().as_ref());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
    let msg = CoseSign1::from_cbor(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateSigningKeyResolver;
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };
    let res = resolver.resolve(&msg, &opts);
    assert!(res.is_success);

    let key = res.signing_key.unwrap();

    for alg in [-48i64, -49i64, -50i64] {
        let err = key
            .verify(alg, b"sig_structure", &[0u8; 1])
            .expect_err("expected disabled ML-DSA error");
        assert!(
            err.contains("ml-dsa support is disabled"),
            "unexpected error for alg {alg}: {err}"
        );
    }
}

#[test]
fn signing_key_verify_returns_err_for_unsupported_alg() {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let params = CertificateParams::new(vec!["verify-unsupported-alg".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let leaf_der = cert.der().to_vec();

    let protected = encode_protected_x5chain_single_bstr(leaf_der.as_slice());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
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
        .verify(-999, b"sig_structure", &[0u8; 64])
        .expect_err("expected unsupported alg");

    assert!(err.contains("unsupported_alg"));
}

#[test]
fn signing_key_verify_es256_rejects_non_p256_certificate_key() {
    // Use a P-384 leaf so we exercise the ES256 fixed-curve enforcement.
    // (The cert is still `id-ecPublicKey`, but the uncompressed point is 97 bytes for P-384,
    // while ES256 requires P-256 with a 65-byte uncompressed point.)
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let params = CertificateParams::new(vec!["verify-es256-alg-mismatch".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let leaf_der = cert.der().to_vec();

    let protected = encode_protected_x5chain_single_bstr(leaf_der.as_slice());
    let cose_bytes = cose_sign1_with_protected_header_bytes(protected.as_slice());
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
        .expect_err("expected algorithm mismatch error");
    assert!(
        err.contains("unexpected_ec_public_key_len_for_es256"),
        "unexpected error: {err}"
    );
}
