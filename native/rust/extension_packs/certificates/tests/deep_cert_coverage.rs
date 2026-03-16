// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for certificates pack.rs and certificate_header_contributor.rs.
//!
//! Targets uncovered lines in:
//! - validation/pack.rs: counter-signature paths, chain identity/validity iteration,
//!   chain trust well-formed logic, EKU extraction paths, key usage bit scanning,
//!   basic constraints, identity pinning denied path, produce() dispatch branches,
//!   and chain-trust summary fields.
//! - signing/certificate_header_contributor.rs: build_x5t / build_x5chain encoding
//!   and contribute_protected_headers / contribute_unprotected_headers via
//!   HeaderContributor trait.

use std::sync::Arc;

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_certificates::validation::facts::*;
use cose_sign1_certificates::validation::pack::{CertificateTrustOptions, X509CertificateTrustPack};
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, CoseSign1Message};
use cose_sign1_signing::{HeaderContributor, HeaderContributorContext, SigningContext};
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use crypto_primitives::{CryptoError, CryptoSigner};
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};

// ---------------------------------------------------------------------------
// Helper: generate a self-signed cert with specific extensions
// ---------------------------------------------------------------------------

/// Generate a real DER certificate with the requested extensions.
fn generate_cert_with_extensions(
    cn: &str,
    is_ca: Option<u8>,
    key_usages: &[KeyUsagePurpose],
    ekus: &[ExtendedKeyUsagePurpose],
) -> (Vec<u8>, KeyPair) {
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec![format!("{}.example", cn)]).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);

    if let Some(path_len) = is_ca {
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(path_len));
    } else {
        params.is_ca = IsCa::NoCa;
    }

    params.key_usages = key_usages.to_vec();
    params.extended_key_usages = ekus.to_vec();

    let cert = params.self_signed(&kp).unwrap();
    (cert.der().to_vec(), kp)
}

/// Generate a simple self-signed leaf certificate.
fn generate_leaf(cn: &str) -> (Vec<u8>, KeyPair) {
    generate_cert_with_extensions(cn, None, &[], &[])
}

/// Generate a CA cert with optional path length.
fn generate_ca(cn: &str, path_len: u8) -> (Vec<u8>, KeyPair) {
    generate_cert_with_extensions(
        cn,
        Some(path_len),
        &[KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        &[],
    )
}

// ---------------------------------------------------------------------------
// Helper: build a COSE_Sign1 message with an x5chain in the protected header
// ---------------------------------------------------------------------------

fn protected_map_with_x5chain(certs: &[&[u8]]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(2).unwrap();
    // alg: ES256
    enc.encode_i64(1).unwrap();
    enc.encode_i64(-7).unwrap();
    // x5chain
    enc.encode_i64(33).unwrap();
    enc.encode_array(certs.len()).unwrap();
    for c in certs {
        enc.encode_bstr(c).unwrap();
    }
    enc.into_bytes()
}

fn cose_sign1_from_protected(protected_map: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected_map).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
}

/// Build a COSE_Sign1 with DER certs in x5chain.
fn build_cose_with_chain(chain: &[&[u8]]) -> Vec<u8> {
    let pm = protected_map_with_x5chain(chain);
    cose_sign1_from_protected(&pm)
}

/// Create engine from pack + COSE bytes (also parses message).
fn engine_from(
    pack: X509CertificateTrustPack,
    cose: &[u8],
) -> TrustFactEngine {
    let msg = CoseSign1Message::parse(cose).unwrap();
    TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose.to_vec().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(msg))
}

/// Shorthand: primary signing key subject from cose bytes.
fn signing_key(cose: &[u8]) -> TrustSubject {
    let msg = TrustSubject::message(cose);
    TrustSubject::primary_signing_key(&msg)
}

// =========================================================================
// pack.rs — EKU extraction paths (lines 457-482)
// =========================================================================

#[test]
fn produce_eku_facts_with_code_signing() {
    let (cert, _kp) = generate_cert_with_extensions(
        "code-signer",
        None,
        &[KeyUsagePurpose::DigitalSignature],
        &[ExtendedKeyUsagePurpose::CodeSigning],
    );
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let eku = eng.get_fact_set::<X509SigningCertificateEkuFact>(&sk).unwrap();
    match eku {
        TrustFactSet::Available(v) => {
            let oids: Vec<&str> = v.iter().map(|f| f.oid_value.as_str()).collect();
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.3"), "expected code_signing OID, got {:?}", oids);
        }
        _ => panic!("expected Available EKU facts"),
    }
}

#[test]
fn produce_eku_facts_with_server_and_client_auth() {
    let (cert, _kp) = generate_cert_with_extensions(
        "auth-cert",
        None,
        &[KeyUsagePurpose::DigitalSignature],
        &[
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ],
    );
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let eku = eng.get_fact_set::<X509SigningCertificateEkuFact>(&sk).unwrap();
    match eku {
        TrustFactSet::Available(v) => {
            let oids: Vec<&str> = v.iter().map(|f| f.oid_value.as_str()).collect();
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.1"), "expected server_auth OID");
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.2"), "expected client_auth OID");
        }
        _ => panic!("expected Available EKU facts"),
    }
}

#[test]
fn produce_eku_facts_with_email_protection() {
    let (cert, _kp) = generate_cert_with_extensions(
        "email-cert",
        None,
        &[KeyUsagePurpose::DigitalSignature],
        &[ExtendedKeyUsagePurpose::EmailProtection],
    );
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let eku = eng.get_fact_set::<X509SigningCertificateEkuFact>(&sk).unwrap();
    match eku {
        TrustFactSet::Available(v) => {
            let oids: Vec<&str> = v.iter().map(|f| f.oid_value.as_str()).collect();
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.4"), "expected email_protection OID, got {:?}", oids);
        }
        _ => panic!("expected Available EKU facts"),
    }
}

#[test]
fn produce_eku_facts_with_time_stamping() {
    let (cert, _kp) = generate_cert_with_extensions(
        "ts-cert",
        None,
        &[KeyUsagePurpose::DigitalSignature],
        &[ExtendedKeyUsagePurpose::TimeStamping],
    );
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let eku = eng.get_fact_set::<X509SigningCertificateEkuFact>(&sk).unwrap();
    match eku {
        TrustFactSet::Available(v) => {
            let oids: Vec<&str> = v.iter().map(|f| f.oid_value.as_str()).collect();
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.8"), "expected time_stamping OID, got {:?}", oids);
        }
        _ => panic!("expected Available EKU facts"),
    }
}

#[test]
fn produce_eku_facts_with_ocsp_signing() {
    let (cert, _kp) = generate_cert_with_extensions(
        "ocsp-cert",
        None,
        &[KeyUsagePurpose::DigitalSignature],
        &[ExtendedKeyUsagePurpose::OcspSigning],
    );
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let eku = eng.get_fact_set::<X509SigningCertificateEkuFact>(&sk).unwrap();
    match eku {
        TrustFactSet::Available(v) => {
            let oids: Vec<&str> = v.iter().map(|f| f.oid_value.as_str()).collect();
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.9"), "expected ocsp_signing OID, got {:?}", oids);
        }
        _ => panic!("expected Available EKU facts"),
    }
}

// =========================================================================
// pack.rs — Key usage bit scanning (lines 491-517)
// =========================================================================

#[test]
fn produce_key_usage_digital_signature() {
    let (cert, _kp) = generate_cert_with_extensions(
        "ds-cert",
        None,
        &[KeyUsagePurpose::DigitalSignature],
        &[],
    );
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let ku = eng.get_fact_set::<X509SigningCertificateKeyUsageFact>(&sk).unwrap();
    match ku {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(v[0].usages.contains(&"DigitalSignature".to_string()));
        }
        _ => panic!("expected Available key usage facts"),
    }
}

#[test]
fn produce_key_usage_key_cert_sign_and_crl_sign() {
    let (cert, _kp) = generate_ca("ca-ku", 0);
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let ku = eng.get_fact_set::<X509SigningCertificateKeyUsageFact>(&sk).unwrap();
    match ku {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(v[0].usages.contains(&"KeyCertSign".to_string()), "got {:?}", v[0].usages);
            assert!(v[0].usages.contains(&"CrlSign".to_string()), "got {:?}", v[0].usages);
        }
        _ => panic!("expected Available key usage facts"),
    }
}

#[test]
fn produce_key_usage_key_encipherment() {
    let (cert, _kp) = generate_cert_with_extensions(
        "ke-cert",
        None,
        &[KeyUsagePurpose::KeyEncipherment],
        &[],
    );
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let ku = eng.get_fact_set::<X509SigningCertificateKeyUsageFact>(&sk).unwrap();
    match ku {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(v[0].usages.contains(&"KeyEncipherment".to_string()), "got {:?}", v[0].usages);
        }
        _ => panic!("expected Available key usage facts"),
    }
}

#[test]
fn produce_key_usage_content_commitment() {
    let (cert, _kp) = generate_cert_with_extensions(
        "cc-cert",
        None,
        &[KeyUsagePurpose::ContentCommitment],
        &[],
    );
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let ku = eng.get_fact_set::<X509SigningCertificateKeyUsageFact>(&sk).unwrap();
    match ku {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            // ContentCommitment maps to NonRepudiation in RFC 5280.
            assert!(v[0].usages.contains(&"NonRepudiation".to_string()), "got {:?}", v[0].usages);
        }
        _ => panic!("expected Available key usage facts"),
    }
}

#[test]
fn produce_key_usage_key_agreement() {
    let (cert, _kp) = generate_cert_with_extensions(
        "ka-cert",
        None,
        &[KeyUsagePurpose::KeyAgreement],
        &[],
    );
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let ku = eng.get_fact_set::<X509SigningCertificateKeyUsageFact>(&sk).unwrap();
    match ku {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(v[0].usages.contains(&"KeyAgreement".to_string()), "got {:?}", v[0].usages);
        }
        _ => panic!("expected Available key usage facts"),
    }
}

// =========================================================================
// pack.rs — Basic constraints facts (lines 526-540)
// =========================================================================

#[test]
fn produce_basic_constraints_ca_with_path_length() {
    let (cert, _kp) = generate_ca("ca-bc", 3);
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let bc = eng
        .get_fact_set::<X509SigningCertificateBasicConstraintsFact>(&sk)
        .unwrap();
    match bc {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(v[0].is_ca);
            assert_eq!(v[0].path_len_constraint, Some(3));
        }
        _ => panic!("expected Available basic constraints facts"),
    }
}

#[test]
fn produce_basic_constraints_not_ca() {
    let (cert, _kp) = generate_leaf("leaf-bc");
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let bc = eng
        .get_fact_set::<X509SigningCertificateBasicConstraintsFact>(&sk)
        .unwrap();
    match bc {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(!v[0].is_ca);
        }
        _ => panic!("expected Available basic constraints facts"),
    }
}

// =========================================================================
// pack.rs — Chain identity facts with multi-element chain (lines 575-595)
// =========================================================================

#[test]
fn produce_chain_element_identity_and_validity_for_multi_cert_chain() {
    let (leaf, _) = generate_leaf("leaf.multi");
    let (root, _) = generate_ca("root.multi", 0);
    let cose = build_cose_with_chain(&[&leaf, &root]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let elems = eng.get_fact_set::<X509ChainElementIdentityFact>(&sk).unwrap();
    match elems {
        TrustFactSet::Available(mut v) => {
            v.sort_by_key(|e| e.index);
            assert_eq!(v.len(), 2);
            assert_eq!(v[0].index, 0);
            assert_eq!(v[1].index, 1);
            assert!(v[0].subject.contains("leaf.multi"));
            assert!(v[1].subject.contains("root.multi"));
        }
        _ => panic!("expected Available chain element identity facts"),
    }

    let validity = eng.get_fact_set::<X509ChainElementValidityFact>(&sk).unwrap();
    match validity {
        TrustFactSet::Available(mut v) => {
            v.sort_by_key(|e| e.index);
            assert_eq!(v.len(), 2);
            assert!(v[0].not_before_unix_seconds <= v[0].not_after_unix_seconds);
            assert!(v[1].not_before_unix_seconds <= v[1].not_after_unix_seconds);
        }
        _ => panic!("expected Available chain element validity facts"),
    }
}

// =========================================================================
// pack.rs — Chain identity missing when no cose_sign1_bytes (lines 554-562)
// =========================================================================

#[test]
fn chain_identity_missing_when_no_cose_bytes() {
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let engine = TrustFactEngine::new(vec![Arc::new(pack)]);
    let subject = TrustSubject::root("PrimarySigningKey", b"seed-no-bytes");

    let x5 = engine
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&subject)
        .unwrap();
    assert!(x5.is_missing(), "expected Missing for chain identity without cose bytes");

    let elems = engine
        .get_fact_set::<X509ChainElementIdentityFact>(&subject)
        .unwrap();
    assert!(elems.is_missing());

    let validity = engine
        .get_fact_set::<X509ChainElementValidityFact>(&subject)
        .unwrap();
    assert!(validity.is_missing());
}

// =========================================================================
// pack.rs — Chain identity missing when no x5chain in headers (lines 565-573)
// =========================================================================

#[test]
fn chain_identity_missing_when_no_x5chain_header() {
    // Build a COSE message with only an alg header, no x5chain.
    let p = EverParseCborProvider;
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(1).unwrap();
    hdr_enc.encode_i64(-7).unwrap();
    let pm = hdr_enc.into_bytes();

    let cose = cose_sign1_from_protected(&pm);
    let msg = CoseSign1Message::parse(&cose).unwrap();
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(msg));

    let sk = signing_key(&cose);

    let x5 = engine
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&sk)
        .unwrap();
    assert!(x5.is_missing(), "expected Missing when no x5chain");
}

// =========================================================================
// pack.rs — Chain trust well-formed logic (lines 630-672)
// =========================================================================

#[test]
fn chain_trust_trusted_when_well_formed_and_trust_embedded_enabled() {
    // A single self-signed cert: issuer == subject (well-formed root).
    let (cert, _) = generate_leaf("self-signed-trusted");
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::trust_embedded_chain_as_trusted();
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let ct = eng.get_fact_set::<X509ChainTrustedFact>(&sk).unwrap();
    match ct {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(v[0].chain_built);
            assert!(v[0].is_trusted, "self-signed cert should be trusted");
            assert_eq!(v[0].status_flags, 0);
            assert!(v[0].status_summary.is_none());
            assert_eq!(v[0].element_count, 1);
        }
        _ => panic!("expected Available chain trust"),
    }

    let skt = eng.get_fact_set::<CertificateSigningKeyTrustFact>(&sk).unwrap();
    match skt {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(v[0].chain_built);
            assert!(v[0].chain_trusted);
            assert_eq!(v[0].chain_status_flags, 0);
            assert!(v[0].chain_status_summary.is_none());
        }
        _ => panic!("expected Available signing key trust"),
    }
}

#[test]
fn chain_trust_not_well_formed_when_issuer_mismatch() {
    // Two self-signed certs that do NOT chain: issuer(0) != subject(1)
    let (c1, _) = generate_leaf("leaf-one");
    let (c2, _) = generate_leaf("leaf-two");
    let cose = build_cose_with_chain(&[&c1, &c2]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..Default::default()
    });
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let ct = eng.get_fact_set::<X509ChainTrustedFact>(&sk).unwrap();
    match ct {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(v[0].chain_built);
            assert!(!v[0].is_trusted);
            assert_eq!(v[0].status_flags, 1);
            assert_eq!(
                v[0].status_summary.as_deref(),
                Some("EmbeddedChainNotWellFormed")
            );
        }
        _ => panic!("expected Available chain trust"),
    }
}

#[test]
fn chain_trust_disabled_when_not_trusting_embedded() {
    let (cert, _) = generate_leaf("disabled-trust");
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions {
        trust_embedded_chain_as_trusted: false,
        ..Default::default()
    });
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let ct = eng.get_fact_set::<X509ChainTrustedFact>(&sk).unwrap();
    match ct {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(!v[0].is_trusted);
            assert_eq!(v[0].status_flags, 1);
            assert_eq!(
                v[0].status_summary.as_deref(),
                Some("TrustEvaluationDisabled")
            );
        }
        _ => panic!("expected Available chain trust"),
    }
}

// =========================================================================
// pack.rs — Chain trust missing when no chain present (lines 621-628)
// =========================================================================

#[test]
fn chain_trust_missing_when_chain_empty() {
    let p = EverParseCborProvider;
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(1).unwrap();
    hdr_enc.encode_i64(-7).unwrap();
    let pm = hdr_enc.into_bytes();
    let cose = cose_sign1_from_protected(&pm);
    let msg = CoseSign1Message::parse(&cose).unwrap();
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(msg));
    let sk = signing_key(&cose);

    let ct = engine.get_fact_set::<X509ChainTrustedFact>(&sk).unwrap();
    assert!(ct.is_missing(), "expected Missing when no x5chain");

    let skt = engine
        .get_fact_set::<CertificateSigningKeyTrustFact>(&sk)
        .unwrap();
    assert!(skt.is_missing());
}

// =========================================================================
// pack.rs — Signing cert facts missing without cose bytes (lines 393-397)
// =========================================================================

#[test]
fn signing_cert_facts_missing_without_cose_bytes() {
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let engine = TrustFactEngine::new(vec![Arc::new(pack)]);
    let subject = TrustSubject::root("PrimarySigningKey", b"no-cose");

    let id = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&subject)
        .unwrap();
    assert!(id.is_missing());

    let allowed = engine
        .get_fact_set::<X509SigningCertificateIdentityAllowedFact>(&subject)
        .unwrap();
    assert!(allowed.is_missing());

    let eku = engine
        .get_fact_set::<X509SigningCertificateEkuFact>(&subject)
        .unwrap();
    assert!(eku.is_missing());

    let ku = engine
        .get_fact_set::<X509SigningCertificateKeyUsageFact>(&subject)
        .unwrap();
    assert!(ku.is_missing());

    let bc = engine
        .get_fact_set::<X509SigningCertificateBasicConstraintsFact>(&subject)
        .unwrap();
    assert!(bc.is_missing());

    let alg = engine
        .get_fact_set::<X509PublicKeyAlgorithmFact>(&subject)
        .unwrap();
    assert!(alg.is_missing());
}

// =========================================================================
// pack.rs — Identity pinning denied (lines 413-423 allowed=false path)
// =========================================================================

#[test]
fn identity_pinning_denies_non_matching_thumbprint() {
    let (cert, _) = generate_leaf("deny-me");
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions {
        identity_pinning_enabled: true,
        allowed_thumbprints: vec!["0000000000000000000000000000000000000000000000000000000000000000".to_string()],
        ..Default::default()
    });
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let allowed = eng
        .get_fact_set::<X509SigningCertificateIdentityAllowedFact>(&sk)
        .unwrap();
    match allowed {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(!v[0].is_allowed, "thumbprint should be denied");
        }
        _ => panic!("expected Available identity allowed fact"),
    }
}

// =========================================================================
// pack.rs — Public key algorithm + PQC OID matching (lines 430-442)
// =========================================================================

#[test]
fn public_key_algorithm_fact_produced() {
    let (cert, _) = generate_leaf("alg-check");
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let alg = eng.get_fact_set::<X509PublicKeyAlgorithmFact>(&sk).unwrap();
    match alg {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            // EC key OID should contain 1.2.840.10045
            assert!(v[0].algorithm_oid.contains("1.2.840.10045"), "got OID: {}", v[0].algorithm_oid);
            assert!(!v[0].is_pqc);
        }
        _ => panic!("expected Available public key algorithm fact"),
    }
}

#[test]
fn pqc_oid_flag_set_when_matching() {
    let (cert, _) = generate_leaf("pqc-check");
    let cose = build_cose_with_chain(&[&cert]);

    // First discover the real OID.
    let pack1 = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng1 = engine_from(pack1, &cose);
    let sk = signing_key(&cose);
    let real_oid = match eng1.get_fact_set::<X509PublicKeyAlgorithmFact>(&sk).unwrap() {
        TrustFactSet::Available(v) => v[0].algorithm_oid.clone(),
        _ => panic!("need real OID"),
    };

    // Now pretend it's PQC by adding its OID to the list.
    let pack2 = X509CertificateTrustPack::new(CertificateTrustOptions {
        pqc_algorithm_oids: vec![real_oid.clone()],
        ..Default::default()
    });
    let eng2 = engine_from(pack2, &cose);
    let alg = eng2.get_fact_set::<X509PublicKeyAlgorithmFact>(&sk).unwrap();
    match alg {
        TrustFactSet::Available(v) => {
            assert!(v[0].is_pqc, "expected PQC flag set for OID {}", real_oid);
        }
        _ => panic!("expected Available"),
    }
}

// =========================================================================
// pack.rs — produce() dispatch for chain identity fact request (line 721)
// =========================================================================

#[test]
fn produce_dispatches_to_chain_identity_group_via_chain_element_identity_request() {
    let (cert, _) = generate_leaf("dispatch-chain-elem");
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    // Requesting X509ChainElementIdentityFact triggers the chain identity group.
    let elems = eng.get_fact_set::<X509ChainElementIdentityFact>(&sk).unwrap();
    match elems {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert_eq!(v[0].index, 0);
        }
        _ => panic!("expected Available chain element identity facts"),
    }
}

// =========================================================================
// pack.rs — chain trust facts via CertificateSigningKeyTrustFact dispatch (line 728)
// =========================================================================

#[test]
fn produce_dispatches_to_chain_trust_via_signing_key_trust_request() {
    let (cert, _) = generate_leaf("dispatch-skt");
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::trust_embedded_chain_as_trusted();
    let eng = engine_from(pack, &cose);
    let sk = signing_key(&cose);

    let skt = eng
        .get_fact_set::<CertificateSigningKeyTrustFact>(&sk)
        .unwrap();
    match skt {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(v[0].chain_built);
            assert!(v[0].chain_trusted);
        }
        _ => panic!("expected Available signing key trust"),
    }
}

// =========================================================================
// pack.rs — non-signing-key subjects produce Available(empty) (line 387-390)
// =========================================================================

#[test]
fn non_signing_key_subject_produces_empty_for_all_cert_facts() {
    let (cert, _) = generate_leaf("non-sk");
    let cose = build_cose_with_chain(&[&cert]);
    let pack = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    let eng = engine_from(pack, &cose);
    let msg_subject = TrustSubject::message(&cose);

    // Message subject is NOT a signing-key subject.
    let id = eng
        .get_fact_set::<X509SigningCertificateIdentityFact>(&msg_subject)
        .unwrap();
    match id {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        _ => panic!("expected Available(empty)"),
    }

    let x5 = eng
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&msg_subject)
        .unwrap();
    match x5 {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        _ => panic!("expected Available(empty)"),
    }

    let ct = eng
        .get_fact_set::<X509ChainTrustedFact>(&msg_subject)
        .unwrap();
    match ct {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        _ => panic!("expected Available(empty)"),
    }
}

// =========================================================================
// certificate_header_contributor.rs — build_x5t / build_x5chain encoding
// and contribute_protected_headers / contribute_unprotected_headers
// (lines 54-58, 77-86, 95-104)
// =========================================================================

fn generate_test_cert() -> Vec<u8> {
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
    let cert = params.self_signed(&kp).unwrap();
    cert.der().to_vec()
}

struct MockSigner;
impl CryptoSigner for MockSigner {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![1, 2, 3])
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn key_id(&self) -> Option<&[u8]> {
        None
    }
    fn key_type(&self) -> &str {
        "EC"
    }
}

use cose_sign1_certificates::signing::certificate_header_contributor::CertificateHeaderContributor;

#[test]
fn header_contributor_builds_x5t_and_x5chain_for_multi_cert_chain() {
    let leaf = generate_test_cert();
    let intermediate = generate_test_cert();
    let root = generate_test_cert();
    let chain: Vec<&[u8]> = vec![&leaf, &intermediate, &root];

    let contributor = CertificateHeaderContributor::new(&leaf, &chain).unwrap();
    let mut headers = CoseHeaderMap::new();
    let signing_ctx = SigningContext::from_bytes(vec![]);
    let signer = MockSigner;
    let ctx = HeaderContributorContext::new(&signing_ctx, &signer);

    contributor.contribute_protected_headers(&mut headers, &ctx);

    let x5t_label = CoseHeaderLabel::Int(CertificateHeaderContributor::X5T_LABEL);
    let x5chain_label = CoseHeaderLabel::Int(CertificateHeaderContributor::X5CHAIN_LABEL);

    // Both headers should be present.
    assert!(headers.get(&x5t_label).is_some(), "x5t missing");
    assert!(headers.get(&x5chain_label).is_some(), "x5chain missing");

    // Validate x5t is CBOR-encoded [alg_id, thumbprint].
    if let Some(CoseHeaderValue::Raw(x5t_bytes)) = headers.get(&x5t_label) {
        let mut dec = cose_sign1_primitives::provider::decoder(x5t_bytes);
        let arr_len = dec.decode_array_len().unwrap();
        assert_eq!(arr_len, Some(2), "x5t should be 2-element array");
        let alg = dec.decode_i64().unwrap();
        assert_eq!(alg, -16, "x5t alg should be SHA-256 = -16");
        let thumb = dec.decode_bstr().unwrap();
        assert_eq!(thumb.len(), 32, "SHA-256 thumbprint should be 32 bytes");
    } else {
        panic!("x5t should be Raw CBOR");
    }

    // Validate x5chain is CBOR array of 3 bstr.
    if let Some(CoseHeaderValue::Raw(x5c_bytes)) = headers.get(&x5chain_label) {
        let mut dec = cose_sign1_primitives::provider::decoder(x5c_bytes);
        let arr_len = dec.decode_array_len().unwrap();
        assert_eq!(arr_len, Some(3), "x5chain should have 3 certs");
        for _i in 0..3 {
            let cert_bytes = dec.decode_bstr().unwrap();
            assert!(!cert_bytes.is_empty());
        }
    } else {
        panic!("x5chain should be Raw CBOR");
    }
}

#[test]
fn header_contributor_unprotected_is_noop() {
    let cert = generate_test_cert();
    let chain: Vec<&[u8]> = vec![&cert];
    let contributor = CertificateHeaderContributor::new(&cert, &chain).unwrap();
    let mut headers = CoseHeaderMap::new();
    let signing_ctx = SigningContext::from_bytes(vec![]);
    let signer = MockSigner;
    let ctx = HeaderContributorContext::new(&signing_ctx, &signer);

    contributor.contribute_unprotected_headers(&mut headers, &ctx);
    assert!(headers.is_empty(), "unprotected headers should remain empty");
}

#[test]
fn header_contributor_empty_chain() {
    let cert = generate_test_cert();
    let chain: Vec<&[u8]> = vec![];
    let contributor = CertificateHeaderContributor::new(&cert, &chain).unwrap();
    let mut headers = CoseHeaderMap::new();
    let signing_ctx = SigningContext::from_bytes(vec![]);
    let signer = MockSigner;
    let ctx = HeaderContributorContext::new(&signing_ctx, &signer);

    contributor.contribute_protected_headers(&mut headers, &ctx);

    // x5chain should still be present as an empty CBOR array.
    let x5chain_label = CoseHeaderLabel::Int(CertificateHeaderContributor::X5CHAIN_LABEL);
    if let Some(CoseHeaderValue::Raw(x5c_bytes)) = headers.get(&x5chain_label) {
        let mut dec = cose_sign1_primitives::provider::decoder(x5c_bytes);
        let arr_len = dec.decode_array_len().unwrap();
        assert_eq!(arr_len, Some(0), "empty chain should produce 0-element array");
    } else {
        panic!("x5chain should be Raw CBOR");
    }
}

use cbor_primitives::CborDecoder;

#[test]
fn header_contributor_merge_strategy_is_replace() {
    let cert = generate_test_cert();
    let contributor = CertificateHeaderContributor::new(&cert, &[cert.as_slice()]).unwrap();
    assert!(matches!(
        contributor.merge_strategy(),
        cose_sign1_signing::HeaderMergeStrategy::Replace
    ));
}
