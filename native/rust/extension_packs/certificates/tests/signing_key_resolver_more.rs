// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cbor_primitives_everparse::EverParseEncoder;
use cose_sign1_certificates::validation::pack::X509CertificateTrustPack;
use cose_sign1_certificates::validation::signing_key_resolver::X509CertificateCoseKeyResolver;
use cose_sign1_certificates_local::{
    CertificateFactory, CertificateOptions, EphemeralCertificateFactory, SoftwareKeyProvider,
};
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::CoseHeaderLocation;

fn cose_sign1_with_headers(
    protected_map_bytes: &[u8],
    encode_unprotected_map: impl FnOnce(&mut EverParseEncoder),
) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected_map_bytes).unwrap();
    encode_unprotected_map(&mut enc);
    enc.encode_null().unwrap();
    enc.encode_bstr(&[]).unwrap();

    enc.into_bytes()
}

fn encode_protected_header_map(encode_entries: impl FnOnce(&mut EverParseEncoder)) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut hdr_enc = p.encoder();

    encode_entries(&mut hdr_enc);

    hdr_enc.into_bytes()
}

fn protected_map_empty() -> Vec<u8> {
    encode_protected_header_map(|enc| {
        enc.encode_map(0).unwrap();
    })
}

fn protected_map_x5chain_single_bstr(cert_der: &[u8]) -> Vec<u8> {
    encode_protected_header_map(|enc| {
        enc.encode_map(1).unwrap();
        enc.encode_i64(33).unwrap();
        enc.encode_bstr(cert_der).unwrap();
    })
}

fn protected_map_x5chain_empty_array() -> Vec<u8> {
    encode_protected_header_map(|enc| {
        enc.encode_map(1).unwrap();
        enc.encode_i64(33).unwrap();
        enc.encode_array(0).unwrap();
    })
}

fn protected_map_x5chain_non_array_non_bstr() -> Vec<u8> {
    encode_protected_header_map(|enc| {
        enc.encode_map(1).unwrap();
        enc.encode_i64(33).unwrap();
        enc.encode_i64(42).unwrap();
    })
}

fn protected_map_x5chain_array_with_non_bstr_item() -> Vec<u8> {
    encode_protected_header_map(|enc| {
        enc.encode_map(1).unwrap();
        enc.encode_i64(33).unwrap();
        enc.encode_array(1).unwrap();
        enc.encode_i64(42).unwrap();
    })
}

#[test]
fn certificates_trust_pack_name_is_stable() {
    let pack = X509CertificateTrustPack::new(Default::default());
    assert_eq!(pack.name(), "X509CertificateTrustPack");
}

#[test]
fn signing_key_resolver_any_reads_x5chain_from_unprotected_header_when_missing_in_protected() {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=unprotected-x5chain")
                .add_subject_alternative_name("unprotected-x5chain"),
        )
        .unwrap();
    let leaf_der = cert.cert_der.clone();

    let protected = protected_map_empty();

    let cose_bytes = cose_sign1_with_headers(protected.as_slice(), |enc| {
        enc.encode_map(1).unwrap();
        enc.encode_i64(33).unwrap();
        enc.encode_bstr(leaf_der.as_slice()).unwrap();
    });

    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Any,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(res.is_success, "expected success");
}

#[test]
fn signing_key_resolver_protected_errors_when_x5chain_only_in_unprotected() {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=protected-only")
                .add_subject_alternative_name("protected-only"),
        )
        .unwrap();
    let leaf_der = cert.cert_der.clone();

    let protected = protected_map_empty();

    let cose_bytes = cose_sign1_with_headers(protected.as_slice(), |enc| {
        enc.encode_map(1).unwrap();
        enc.encode_i64(33).unwrap();
        enc.encode_bstr(leaf_der.as_slice()).unwrap();
    });

    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(!res.is_success);
    assert_eq!(res.error_code.as_deref(), Some("X5CHAIN_NOT_FOUND"));
    let msg = res.error_message.clone().unwrap_or_default();
    assert!(
        msg.contains("protected header"),
        "unexpected message: {msg}"
    );
}

#[test]
fn certificates_trust_pack_provides_default_trust_plan() {
    use cose_sign1_validation::fluent::CoseSign1TrustPack;

    let pack = X509CertificateTrustPack::new(Default::default());
    let plan = pack
        .default_trust_plan()
        .expect("expected certificates pack to provide a default trust plan");
    assert!(!plan.required_facts().is_empty());
}

#[test]
fn signing_key_resolver_any_errors_when_x5chain_missing_in_both_headers() {
    let protected = protected_map_empty();

    let cose_bytes = cose_sign1_with_headers(protected.as_slice(), |enc| {
        enc.encode_map(0).unwrap();
    });

    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
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
        enc.encode_map(0).unwrap();
    });

    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
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
        enc.encode_map(0).unwrap();
    });

    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
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
        enc.encode_map(0).unwrap();
    });

    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
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
        enc.encode_map(0).unwrap();
    });

    let msg = CoseSign1Message::parse(cose_bytes.as_slice()).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions {
        certificate_header_location: CoseHeaderLocation::Protected,
        ..Default::default()
    };

    let res = resolver.resolve(&msg, &opts);
    assert!(!res.is_success);
    assert_eq!(res.error_code.as_deref(), Some("X509_PARSE_FAILED"));
}

// Note: This test cannot work with the current design because:
// 1. The key's algorithm is inferred from the certificate's SPKI OID
// 2. The certificate library generates P-256 (ES256) certificates, not ML-DSA
// 3. verify_sig_structure uses the key's inferred algorithm, not an explicit one
// To test ML-DSA disabled behavior, we'd need actual ML-DSA certificates.
#[cfg(not(feature = "pqc-mldsa"))]
#[test]
#[ignore = "Cannot test ML-DSA without ML-DSA certificates from certificate library"]
fn signing_key_verify_mldsa_returns_disabled_error_when_feature_is_off() {
    // Left here as documentation of what the test was attempting to verify
}

#[test]
fn certificates_pack_default_trust_plan_is_present_and_compilable() {
    let pack = X509CertificateTrustPack::new(Default::default());
    let plan = pack
        .default_trust_plan()
        .expect("cert pack should provide a default trust plan");

    // Basic sanity: the plan should have at least one required fact.
    assert!(!plan.required_facts().is_empty());
}
