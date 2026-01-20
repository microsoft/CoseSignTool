use cose_sign1_validation::fluent::*;
use cose_sign1_validation_certificates::pack::X509CertificateTrustPack;
use cose_sign1_validation_certificates::signing_key_resolver::X509CertificateSigningKeyResolver;
use cose_sign1_validation_trust::CoseHeaderLocation;
use rcgen::generate_simple_self_signed;
use tinycbor::{Encode, Encoder};

fn cose_sign1_with_headers(
    protected_map_bytes: &[u8],
    encode_unprotected_map: impl FnOnce(&mut Encoder<&mut [u8]>),
) -> Vec<u8> {
    let mut buf = vec![0u8; 8192 + protected_map_bytes.len()];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();
    protected_map_bytes.encode(&mut enc).unwrap();
    encode_unprotected_map(&mut enc);
    Option::<&[u8]>::None.encode(&mut enc).unwrap();
    (&[] as &[u8]).encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_protected_header_map(encode_entries: impl FnOnce(&mut Encoder<&mut [u8]>)) -> Vec<u8> {
    let mut hdr_buf = vec![0u8; 4096];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());

    encode_entries(&mut hdr_enc);

    let used = hdr_len - hdr_enc.0.len();
    hdr_buf.truncate(used);
    hdr_buf
}

fn protected_map_empty() -> Vec<u8> {
    encode_protected_header_map(|enc| {
        enc.map(0).unwrap();
    })
}

fn protected_map_x5chain_single_bstr(cert_der: &[u8]) -> Vec<u8> {
    encode_protected_header_map(|enc| {
        enc.map(1).unwrap();
        (33i64).encode(enc).unwrap();
        cert_der.encode(enc).unwrap();
    })
}

fn protected_map_x5chain_empty_array() -> Vec<u8> {
    encode_protected_header_map(|enc| {
        enc.map(1).unwrap();
        (33i64).encode(enc).unwrap();
        enc.array(0).unwrap();
    })
}

fn protected_map_x5chain_non_array_non_bstr() -> Vec<u8> {
    encode_protected_header_map(|enc| {
        enc.map(1).unwrap();
        (33i64).encode(enc).unwrap();
        (42i64).encode(enc).unwrap();
    })
}

fn protected_map_x5chain_array_with_non_bstr_item() -> Vec<u8> {
    encode_protected_header_map(|enc| {
        enc.map(1).unwrap();
        (33i64).encode(enc).unwrap();
        enc.array(1).unwrap();
        (42i64).encode(enc).unwrap();
    })
}

#[test]
fn certificates_trust_pack_name_is_stable() {
    let pack = X509CertificateTrustPack::default();
    assert_eq!(pack.name(), "X509CertificateTrustPack");
}

#[test]
fn signing_key_resolver_any_reads_x5chain_from_unprotected_header_when_missing_in_protected() {
    let cert = generate_simple_self_signed(vec!["unprotected-x5chain".to_string()]).unwrap();
    let leaf_der = cert.cert.der().as_ref().to_vec();

    let protected = protected_map_empty();

    let cose_bytes = cose_sign1_with_headers(protected.as_slice(), |enc| {
        enc.map(1).unwrap();
        (33i64).encode(enc).unwrap();
        leaf_der.as_slice().encode(enc).unwrap();
    });

    let msg = CoseSign1::from_cbor(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateSigningKeyResolver;
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Any,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(res.is_success, "expected success");
}

#[test]
fn signing_key_resolver_protected_errors_when_x5chain_only_in_unprotected() {
    let cert = generate_simple_self_signed(vec!["protected-only".to_string()]).unwrap();
    let leaf_der = cert.cert.der().as_ref().to_vec();

    let protected = protected_map_empty();

    let cose_bytes = cose_sign1_with_headers(protected.as_slice(), |enc| {
        enc.map(1).unwrap();
        (33i64).encode(enc).unwrap();
        leaf_der.as_slice().encode(enc).unwrap();
    });

    let msg = CoseSign1::from_cbor(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateSigningKeyResolver;
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(!res.is_success);
    assert_eq!(res.error_code.as_deref(), Some("X5CHAIN_NOT_FOUND"));
    let msg = res.error_message.clone().unwrap_or_default();
    assert!(msg.contains("protected header"), "unexpected message: {msg}");
}

#[test]
fn certificates_trust_pack_provides_default_trust_plan() {
    use cose_sign1_validation::fluent::CoseSign1TrustPack;

    let pack = X509CertificateTrustPack::default();
    let plan = pack
        .default_trust_plan()
        .expect("expected certificates pack to provide a default trust plan");
    assert!(!plan.required_facts().is_empty());
}

#[test]
fn signing_key_resolver_any_errors_when_x5chain_missing_in_both_headers() {
    let protected = protected_map_empty();

    let cose_bytes = cose_sign1_with_headers(protected.as_slice(), |enc| {
        enc.map(0).unwrap();
    });

    let msg = CoseSign1::from_cbor(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateSigningKeyResolver;
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Any,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(!res.is_success);
    assert_eq!(res.error_code.as_deref(), Some("X5CHAIN_NOT_FOUND"));
    let msg = res.error_message.clone().unwrap_or_default();
    assert!(
        msg.contains("protected or unprotected"),
        "unexpected message: {msg}"
    );
}

#[test]
fn signing_key_resolver_errors_when_x5chain_present_but_empty_array() {
    let protected = protected_map_x5chain_empty_array();
    let cose_bytes = cose_sign1_with_headers(protected.as_slice(), |enc| {
        enc.map(0).unwrap();
    });

    let msg = CoseSign1::from_cbor(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateSigningKeyResolver;
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(!res.is_success);
    assert_eq!(res.error_code.as_deref(), Some("X5CHAIN_EMPTY"));
}

#[test]
fn signing_key_resolver_errors_when_x5chain_value_is_neither_bstr_nor_array() {
    let protected = protected_map_x5chain_non_array_non_bstr();
    let cose_bytes = cose_sign1_with_headers(protected.as_slice(), |enc| {
        enc.map(0).unwrap();
    });

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
        msg.contains("x5chain_array") || msg.contains("array"),
        "unexpected message: {msg}"
    );
}

#[test]
fn signing_key_resolver_errors_when_x5chain_array_items_are_not_bstr() {
    let protected = protected_map_x5chain_array_with_non_bstr_item();
    let cose_bytes = cose_sign1_with_headers(protected.as_slice(), |enc| {
        enc.map(0).unwrap();
    });

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
        msg.contains("x5chain_item") || msg.contains("item"),
        "unexpected message: {msg}"
    );
}

#[test]
fn signing_key_resolver_errors_when_leaf_certificate_der_is_invalid() {
    let protected = protected_map_x5chain_single_bstr(b"not-a-der-cert");
    let cose_bytes = cose_sign1_with_headers(protected.as_slice(), |enc| {
        enc.map(0).unwrap();
    });

    let msg = CoseSign1::from_cbor(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateSigningKeyResolver;
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(!res.is_success);
    assert_eq!(res.error_code.as_deref(), Some("X509_PARSE_FAILED"));
}

#[cfg(not(feature = "pqc-mldsa"))]
#[test]
fn signing_key_verify_mldsa_returns_disabled_error_when_feature_is_off() {
    let cert = generate_simple_self_signed(vec!["mldsa-disabled".to_string()]).unwrap();
    let leaf_der = cert.cert.der().as_ref().to_vec();

    let protected = protected_map_x5chain_single_bstr(leaf_der.as_slice());
    let cose_bytes = cose_sign1_with_headers(protected.as_slice(), |enc| {
        enc.map(0).unwrap();
    });

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
        .verify(-48, b"sig_structure", &[0u8; 1])
        .expect_err("expected ML-DSA disabled error");

    assert!(err.contains("ml-dsa support is disabled"), "unexpected error: {err}");
}

#[test]
fn certificates_pack_default_trust_plan_is_present_and_compilable() {
    let pack = X509CertificateTrustPack::default();
    let plan = pack
        .default_trust_plan()
        .expect("cert pack should provide a default trust plan");

    // Basic sanity: the plan should have at least one required fact.
    assert!(!plan.required_facts().is_empty());
}
