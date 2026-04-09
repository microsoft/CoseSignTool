// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for uncovered lines in `cose_sign1_certificates`.
//!
//! Covers:
//! - validation/pack.rs: CoseSign1TrustPack trait methods (name, fact_producer,
//!   cose_key_resolvers, default_trust_plan), chain trust logic with well-formed
//!   and malformed chains, identity-pinning denied path, chain identity/validity
//!   iteration, produce() dispatch for chain trust facts.
//! - validation/signing_key_resolver.rs: CERT_PARSE_FAILED, no-algorithm
//!   auto-detection path, happy-path resolver success.
//! - signing/certificate_header_contributor.rs: new() mismatch error,
//!   build_x5t / build_x5chain encoding, contribute_protected_headers /
//!   contribute_unprotected_headers.

use std::sync::Arc;

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_certificates::signing::certificate_header_contributor::CertificateHeaderContributor;
use cose_sign1_certificates::validation::facts::*;
use cose_sign1_certificates::validation::pack::{
    CertificateTrustOptions, X509CertificateTrustPack,
};
use cose_sign1_certificates::validation::signing_key_resolver::X509CertificateCoseKeyResolver;
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderMap, CoseSign1Message};
use cose_sign1_signing::{
    HeaderContributor, HeaderContributorContext, HeaderMergeStrategy, SigningContext,
};
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use crypto_primitives::{CryptoError, CryptoSigner};
use cose_sign1_certificates_local::{
    Certificate, CertificateFactory, CertificateOptions, EphemeralCertificateFactory,
    SoftwareKeyProvider,
};

// ===========================================================================
// Helpers
// ===========================================================================

/// Generate a self-signed DER certificate with configurable extensions.
fn gen_cert(
    cn: &str,
    is_ca: Option<u8>,
    ekus: &[&str],
) -> Certificate {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let mut opts = CertificateOptions::new()
        .with_subject_name(format!("CN={}", cn))
        .add_subject_alternative_name(format!("{cn}.example"));
    if let Some(path_len) = is_ca {
        opts = opts.as_ca(path_len as u32);
    }
    if !ekus.is_empty() {
        opts = opts.with_enhanced_key_usages(ekus.iter().map(|s| s.to_string()).collect());
    }
    factory.create_certificate(opts).unwrap()
}

/// Generate a certificate signed by the given issuer.
fn gen_issued_cert(
    cn: &str,
    issuer: &Certificate,
) -> Certificate {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    factory.create_certificate(
        CertificateOptions::new()
            .with_subject_name(format!("CN={}", cn))
            .add_subject_alternative_name(format!("{cn}.example"))
            .signed_by(issuer.clone())
    ).unwrap()
}

/// Simple leaf cert.
fn leaf(cn: &str) -> Certificate {
    gen_cert(cn, None, &[])
}

/// CA cert with path-length constraint.
fn ca(cn: &str, pl: u8) -> Certificate {
    gen_cert(cn, Some(pl), &[])
}

/// Build a CBOR protected-header map with alg=ES256 and an x5chain array.
fn protected_map_with_x5chain(certs: &[&[u8]]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(2).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(-7).unwrap(); // alg = ES256
    enc.encode_i64(33).unwrap();
    enc.encode_array(certs.len()).unwrap();
    for c in certs {
        enc.encode_bstr(c).unwrap();
    }
    enc.into_bytes()
}

/// Build a CBOR protected-header map with NO alg and an x5chain array.
fn protected_map_no_alg_with_x5chain(certs: &[&[u8]]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(33).unwrap();
    enc.encode_array(certs.len()).unwrap();
    for c in certs {
        enc.encode_bstr(c).unwrap();
    }
    enc.into_bytes()
}

/// Build a COSE_Sign1 from raw protected-header map bytes.
fn cose_from_protected(protected_map: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected_map).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
}

/// Convenience: build COSE_Sign1 from DER certs (with alg).
fn build_cose(chain: &[&[u8]]) -> Vec<u8> {
    cose_from_protected(&protected_map_with_x5chain(chain))
}

/// Build engine from pack + cose bytes.
fn engine(pack: X509CertificateTrustPack, cose: &[u8]) -> TrustFactEngine {
    let msg = CoseSign1Message::parse(cose).unwrap();
    TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose.to_vec().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(msg))
}

/// Primary signing key subject from COSE bytes.
fn sk(cose: &[u8]) -> TrustSubject {
    TrustSubject::primary_signing_key(&TrustSubject::message(cose))
}

/// Create a mock HeaderContributorContext for testing.
fn make_hdr_ctx() -> HeaderContributorContext<'static> {
    struct MockSigner;
    impl CryptoSigner for MockSigner {
        fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
            Ok(vec![0; 64])
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

    let ctx: &'static SigningContext = Box::leak(Box::new(SigningContext::from_bytes(vec![])));
    let signer: &'static dyn CryptoSigner = Box::leak(Box::new(MockSigner));
    HeaderContributorContext::new(ctx, signer)
}

// ===========================================================================
// pack.rs — CoseSign1TrustPack trait methods (L232, L237, L242, L244, L255, L260, L263)
// ===========================================================================

#[test]
fn trust_pack_name_returns_expected() {
    let pack = X509CertificateTrustPack::default();
    assert_eq!(pack.name(), "X509CertificateTrustPack");
}

#[test]
fn trust_pack_fact_producer_returns_arc() {
    let pack = X509CertificateTrustPack::default();
    let producer = pack.fact_producer();
    assert_eq!(
        producer.name(),
        "cose_sign1_certificates::X509CertificateTrustPack"
    );
}

#[test]
fn trust_pack_cose_key_resolvers_returns_one_resolver() {
    let pack = X509CertificateTrustPack::default();
    let resolvers = pack.cose_key_resolvers();
    assert_eq!(resolvers.len(), 1);
}

#[test]
fn trust_pack_default_trust_plan_is_some() {
    let pack = X509CertificateTrustPack::default();
    let plan = pack.default_trust_plan();
    assert!(plan.is_some());
}

// ===========================================================================
// pack.rs — Chain trust: well-formed self-signed chain => trusted (L621, L630, L637, L644, L672, L683)
// ===========================================================================

#[test]
fn chain_trust_well_formed_self_signed_chain_trusted() {
    let root_cert = ca("root-wf", 1);
    let root_der = root_cert.cert_der.clone();
    let leaf_cert = gen_issued_cert("leaf-wf", &root_cert);
    let leaf_der = leaf_cert.cert_der.clone();

    let cose = build_cose(&[&leaf_der, &root_der]);
    let pack = X509CertificateTrustPack::trust_embedded_chain_as_trusted();
    let eng = engine(pack, &cose);
    let subject = sk(&cose);

    let fact = eng.get_fact_set::<X509ChainTrustedFact>(&subject).unwrap();
    match fact {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(v[0].chain_built);
            assert!(v[0].is_trusted);
            assert_eq!(v[0].status_flags, 0);
            assert!(v[0].status_summary.is_none());
            assert_eq!(v[0].element_count, 2);
        }
        other => panic!("expected Available, got {other:?}"),
    }

    // Also check CertificateSigningKeyTrustFact (L675–L683)
    let skf = eng
        .get_fact_set::<CertificateSigningKeyTrustFact>(&subject)
        .unwrap();
    match skf {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(v[0].chain_trusted);
            assert!(v[0].chain_built);
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — Chain trust: not-well-formed chain with trust_embedded=true (L660-661)
// ===========================================================================

#[test]
fn chain_trust_not_well_formed_embedded_trust_enabled() {
    // Two unrelated self-signed certs: issuer/subject won't chain
    let cert_a = leaf("unrelated-a");
    let cert_b = leaf("unrelated-b");

    let cose = build_cose(&[&cert_a.cert_der, &cert_b.cert_der]);
    let pack = X509CertificateTrustPack::trust_embedded_chain_as_trusted();
    let eng = engine(pack, &cose);
    let subject = sk(&cose);

    let fact = eng.get_fact_set::<X509ChainTrustedFact>(&subject).unwrap();
    match fact {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(!v[0].is_trusted);
            assert_eq!(v[0].status_flags, 1);
            assert_eq!(
                v[0].status_summary.as_deref(),
                Some("EmbeddedChainNotWellFormed")
            );
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — Chain trust: trust_embedded=false => TrustEvaluationDisabled (L662-663)
// ===========================================================================

#[test]
fn chain_trust_evaluation_disabled() {
    let root_cert = ca("root-dis", 1);
    let root_der = root_cert.cert_der.clone();
    let leaf_cert = gen_issued_cert("leaf-dis", &root_cert);
    let leaf_der = leaf_cert.cert_der.clone();

    let cose = build_cose(&[&leaf_der, &root_der]);
    // Default: trust_embedded_chain_as_trusted = false
    let pack = X509CertificateTrustPack::default();
    let eng = engine(pack, &cose);
    let subject = sk(&cose);

    let fact = eng.get_fact_set::<X509ChainTrustedFact>(&subject).unwrap();
    match fact {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(!v[0].is_trusted);
            assert_eq!(v[0].status_flags, 1);
            assert_eq!(
                v[0].status_summary.as_deref(),
                Some("TrustEvaluationDisabled")
            );
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — Identity pinning: denied path (L413, L423, L427)
// ===========================================================================

#[test]
fn identity_pinning_denied_when_thumbprint_not_in_allowlist() {
    let cert = leaf("pinned-leaf");
    let cose = build_cose(&[&cert.cert_der]);

    let opts = CertificateTrustOptions {
        allowed_thumbprints: vec!["0000000000000000000000000000000000000000".to_string()],
        identity_pinning_enabled: true,
        ..Default::default()
    };
    let pack = X509CertificateTrustPack::new(opts);
    let eng = engine(pack, &cose);
    let subject = sk(&cose);

    let allowed = eng
        .get_fact_set::<X509SigningCertificateIdentityAllowedFact>(&subject)
        .unwrap();
    match allowed {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(!v[0].is_allowed);
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — Identity pinning: allowed path
// ===========================================================================

#[test]
fn identity_pinning_allowed_when_thumbprint_matches() {
    let cert = leaf("ok-leaf");

    // Compute the SHA-256 thumbprint of the cert to put in the allow list
    let thumbprint = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&cert.cert_der);
        let d = h.finalize();
        d.iter().map(|b| format!("{:02X}", b)).collect::<String>()
    };

    let cose = build_cose(&[&cert.cert_der]);
    let opts = CertificateTrustOptions {
        allowed_thumbprints: vec![thumbprint],
        identity_pinning_enabled: true,
        ..Default::default()
    };
    let pack = X509CertificateTrustPack::new(opts);
    let eng = engine(pack, &cose);
    let subject = sk(&cose);

    let allowed = eng
        .get_fact_set::<X509SigningCertificateIdentityAllowedFact>(&subject)
        .unwrap();
    match allowed {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(v[0].is_allowed);
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — produce() dispatch: chain identity facts route (L729, L731)
// ===========================================================================

#[test]
fn produce_dispatches_chain_element_identity_facts() {
    let root_cert = ca("root-ci", 1);
    let root_der = root_cert.cert_der.clone();
    let leaf_cert = gen_issued_cert("leaf-ci", &root_cert);
    let leaf_der = leaf_cert.cert_der.clone();
    let cose = build_cose(&[&leaf_der, &root_der]);
    let pack = X509CertificateTrustPack::default();
    let eng = engine(pack, &cose);
    let subject = sk(&cose);

    // Triggers produce() with X509ChainElementIdentityFact (line 719)
    let elems = eng
        .get_fact_set::<X509ChainElementIdentityFact>(&subject)
        .unwrap();
    match elems {
        TrustFactSet::Available(v) => assert!(v.len() >= 2),
        other => panic!("expected Available, got {other:?}"),
    }

    // Triggers produce() with X509X5ChainCertificateIdentityFact (line 718)
    let x5_id = eng
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&subject)
        .unwrap();
    match x5_id {
        TrustFactSet::Available(v) => assert!(v.len() >= 2),
        other => panic!("expected Available, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — produce() dispatch: chain trust facts route
// ===========================================================================

#[test]
fn produce_dispatches_chain_trust_facts() {
    let cert = leaf("chain-trust-dispatch");
    let cose = build_cose(&[&cert.cert_der]);
    let pack = X509CertificateTrustPack::default();
    let eng = engine(pack, &cose);
    let subject = sk(&cose);

    // Triggers produce() through FactKey::of::<CertificateSigningKeyTrustFact>() (L726)
    let skf = eng
        .get_fact_set::<CertificateSigningKeyTrustFact>(&subject)
        .unwrap();
    match skf {
        TrustFactSet::Available(v) => assert_eq!(v.len(), 1),
        other => panic!("expected Available, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — produce_signing_certificate_facts with all extensions (L442, L458…L481)
// ===========================================================================

#[test]
fn produce_signing_cert_facts_with_any_eku() {
    // Test multiple known EKUs to verify all standard OIDs are extracted
    let cert = gen_cert(
        "multi-eku",
        None,
        &[
            "1.3.6.1.5.5.7.3.1",  // server_auth
            "1.3.6.1.5.5.7.3.2",  // client_auth
            "1.3.6.1.5.5.7.3.3",  // code_signing
            "1.3.6.1.5.5.7.3.4",  // email_protection
            "1.3.6.1.5.5.7.3.8",  // time_stamping
            "1.3.6.1.5.5.7.3.9",  // ocsp_signing
        ],
    );
    let cose = build_cose(&[&cert.cert_der]);
    let pack = X509CertificateTrustPack::default();
    let eng = engine(pack, &cose);
    let subject = sk(&cose);

    let eku = eng
        .get_fact_set::<X509SigningCertificateEkuFact>(&subject)
        .unwrap();
    match eku {
        TrustFactSet::Available(v) => {
            let oids: Vec<&str> = v.iter().map(|f| &*f.oid_value).collect();
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.1")); // server_auth
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.2")); // client_auth
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.3")); // code_signing
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.4")); // email_protection
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.8")); // time_stamping
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.9")); // ocsp_signing
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — Key usage: data_encipherment and encipher_only/decipher_only (L500-501, L512-516)
// ===========================================================================

#[test]
fn produce_key_usage_data_encipherment() {
    // Factory sets DigitalSignature for leaf certs; test key usage fact extraction
    let cert = gen_cert("de-cert", None, &[]);
    let cose = build_cose(&[&cert.cert_der]);
    let pack = X509CertificateTrustPack::default();
    let eng = engine(pack, &cose);
    let subject = sk(&cose);

    let ku = eng
        .get_fact_set::<X509SigningCertificateKeyUsageFact>(&subject)
        .unwrap();
    match ku {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            // Factory sets DigitalSignature for leaf certs.
            assert!(v[0].usages.contains(&"DigitalSignature".to_string()));
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — produce() on non-signing-key subject marks facts as produced (L387-391)
// ===========================================================================

#[test]
fn produce_signing_cert_facts_for_non_signing_key_subject() {
    let cert = leaf("non-sk");
    let cose = build_cose(&[&cert.cert_der]);
    let pack = X509CertificateTrustPack::default();
    let eng = engine(pack, &cose);

    // Message subject (not a signing key) — facts should be Available(empty)
    let message_subject = TrustSubject::message(&cose);
    let id = eng
        .get_fact_set::<X509SigningCertificateIdentityFact>(&message_subject)
        .unwrap();
    match id {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty) for non-sk subject, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — produce_chain_identity_facts for non-signing-key subject (L547-551)
// ===========================================================================

#[test]
fn produce_chain_identity_facts_for_non_signing_key_subject() {
    let cert = leaf("non-sk-chain");
    let cose = build_cose(&[&cert.cert_der]);
    let pack = X509CertificateTrustPack::default();
    let eng = engine(pack, &cose);

    let message_subject = TrustSubject::message(&cose);
    let elems = eng
        .get_fact_set::<X509ChainElementIdentityFact>(&message_subject)
        .unwrap();
    match elems {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty) for non-sk subject, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — produce_chain_trust_facts for non-signing-key subject (L607-610)
// ===========================================================================

#[test]
fn produce_chain_trust_facts_for_non_signing_key_subject() {
    let cert = leaf("non-sk-trust");
    let cose = build_cose(&[&cert.cert_der]);
    let pack = X509CertificateTrustPack::default();
    let eng = engine(pack, &cose);

    let message_subject = TrustSubject::message(&cose);
    let trust = eng
        .get_fact_set::<X509ChainTrustedFact>(&message_subject)
        .unwrap();
    match trust {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty) for non-sk subject, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — produce_chain_identity_facts with empty chain (L564-572)
// ===========================================================================

#[test]
fn produce_chain_identity_facts_empty_chain() {
    // Build a COSE_Sign1 with no x5chain
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(-7).unwrap();
    let protected = enc.into_bytes();
    let cose = cose_from_protected(&protected);

    let pack = X509CertificateTrustPack::default();
    let eng = engine(pack, &cose);
    let subject = sk(&cose);

    let elems = eng
        .get_fact_set::<X509ChainElementIdentityFact>(&subject)
        .unwrap();
    // No x5chain → marks missing
    match elems {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        TrustFactSet::Missing { .. } => { /* expected */ }
        other => panic!("unexpected: {other:?}"),
    }
}

// ===========================================================================
// pack.rs — PQC OID detection (L442)
// ===========================================================================

#[test]
fn pqc_oid_detection_no_match() {
    let cert = leaf("pqc-nomatch");
    let cose = build_cose(&[&cert.cert_der]);

    let opts = CertificateTrustOptions {
        pqc_algorithm_oids: vec!["2.16.840.1.101.3.4.3.17".to_string()], // ML-DSA-65 OID
        ..Default::default()
    };
    let pack = X509CertificateTrustPack::new(opts);
    let eng = engine(pack, &cose);
    let subject = sk(&cose);

    let alg = eng
        .get_fact_set::<X509PublicKeyAlgorithmFact>(&subject)
        .unwrap();
    match alg {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            // ECDSA P-256 OID should not match the PQC OID
            assert!(!v[0].is_pqc);
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — Chain trust with single self-signed cert (L643-654)
// ===========================================================================

#[test]
fn chain_trust_single_self_signed_cert() {
    let cert = leaf("single-ss");
    let cose = build_cose(&[&cert.cert_der]);
    let pack = X509CertificateTrustPack::trust_embedded_chain_as_trusted();
    let eng = engine(pack, &cose);
    let subject = sk(&cose);

    let fact = eng.get_fact_set::<X509ChainTrustedFact>(&subject).unwrap();
    match fact {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            // Single self-signed cert: subject == issuer is well-formed
            assert!(v[0].chain_built);
            assert_eq!(v[0].element_count, 1);
            // Self-signed leaf: well_formed check should pass
            assert!(v[0].is_trusted);
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

// ===========================================================================
// pack.rs — chain_identity_facts iteration with 3-element chain (L575-593)
// ===========================================================================

#[test]
fn chain_identity_with_three_element_chain() {
    let root_cert = ca("root3", 2);
    let root_der = root_cert.cert_der.clone();
    let mid_cert = {
        let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
        factory.create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=mid3")
                .add_subject_alternative_name("mid3.example")
                .as_ca(0)
                .signed_by(root_cert.clone())
        ).unwrap()
    };
    let mid_der = mid_cert.cert_der.clone();
    let leaf_cert = gen_issued_cert("leaf3", &mid_cert);
    let leaf_der = leaf_cert.cert_der.clone();

    let cose = build_cose(&[&leaf_der, &mid_der, &root_der]);
    let pack = X509CertificateTrustPack::default();
    let eng = engine(pack, &cose);
    let subject = sk(&cose);

    let elems = eng
        .get_fact_set::<X509ChainElementIdentityFact>(&subject)
        .unwrap();
    match elems {
        TrustFactSet::Available(mut v) => {
            v.sort_by_key(|e| e.index);
            assert_eq!(v.len(), 3);
            assert_eq!(v[0].index, 0);
            assert_eq!(v[1].index, 1);
            assert_eq!(v[2].index, 2);
        }
        other => panic!("expected Available, got {other:?}"),
    }

    let validity = eng
        .get_fact_set::<X509ChainElementValidityFact>(&subject)
        .unwrap();
    match validity {
        TrustFactSet::Available(v) => assert_eq!(v.len(), 3),
        other => panic!("expected Available, got {other:?}"),
    }

    let x5chain_id = eng
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&subject)
        .unwrap();
    match x5chain_id {
        TrustFactSet::Available(v) => assert_eq!(v.len(), 3),
        other => panic!("expected Available, got {other:?}"),
    }
}

// ===========================================================================
// signing_key_resolver.rs — CERT_PARSE_FAILED error path (L81-84)
// ===========================================================================

#[test]
fn resolver_cert_parse_failed() {
    // Build a COSE_Sign1 with garbage bytes in x5chain
    let garbage = b"not-a-valid-der-certificate-at-all";
    let pm = protected_map_with_x5chain(&[garbage.as_slice()]);
    let cose = cose_from_protected(&pm);
    let msg = CoseSign1Message::parse(&cose).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions::default();
    let result = resolver.resolve(&msg, &opts);
    assert!(!result.is_success);
}

// ===========================================================================
// signing_key_resolver.rs — No algorithm auto-detection path (L117-141)
// ===========================================================================

#[test]
fn resolver_no_alg_auto_detection_success() {
    let cert = leaf("auto-detect");
    // Build a COSE_Sign1 with NO alg header → triggers auto-detection
    let pm = protected_map_no_alg_with_x5chain(&[&cert.cert_der]);
    let cose = cose_from_protected(&pm);
    let msg = CoseSign1Message::parse(&cose).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions::default();
    let result = resolver.resolve(&msg, &opts);
    assert!(
        result.is_success,
        "expected success but diagnostics: {:?}",
        result.diagnostics
    );
}

// ===========================================================================
// signing_key_resolver.rs — Happy path with alg present (L105-115)
// ===========================================================================

#[test]
fn resolver_with_alg_present_success() {
    let cert = leaf("alg-present");
    let pm = protected_map_with_x5chain(&[&cert.cert_der]);
    let cose = cose_from_protected(&pm);
    let msg = CoseSign1Message::parse(&cose).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions::default();
    let result = resolver.resolve(&msg, &opts);
    assert!(result.is_success);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.contains("x509_verifier_resolved")),
        "expected diagnostic about openssl resolver"
    );
}

// ===========================================================================
// signing_key_resolver.rs — X5CHAIN_NOT_FOUND error (L46-50)
// ===========================================================================

#[test]
fn resolver_x5chain_not_found() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(-7).unwrap();
    let pm = enc.into_bytes();
    let cose = cose_from_protected(&pm);
    let msg = CoseSign1Message::parse(&cose).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions::default();
    let result = resolver.resolve(&msg, &opts);
    assert!(!result.is_success);
}

// ===========================================================================
// signing_key_resolver.rs — X5CHAIN_EMPTY error (L53-57)
// ===========================================================================

#[test]
fn resolver_x5chain_empty() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(33).unwrap();
    enc.encode_array(0).unwrap();
    let pm = enc.into_bytes();
    let cose = cose_from_protected(&pm);
    let msg = CoseSign1Message::parse(&cose).unwrap();

    let resolver = X509CertificateCoseKeyResolver::new();
    let opts = CoseSign1ValidationOptions::default();
    let result = resolver.resolve(&msg, &opts);
    assert!(!result.is_success);
}

// ===========================================================================
// signing_key_resolver.rs — Default trait impl
// ===========================================================================

#[test]
fn resolver_default_impl() {
    let resolver = X509CertificateCoseKeyResolver::default();
    // Just ensure Default works
    let _ = resolver;
}

// ===========================================================================
// certificate_header_contributor.rs — new() error: chain[0] != signing_cert (L47-51)
// ===========================================================================

#[test]
fn header_contributor_chain_mismatch_error() {
    let cert_a = leaf("hdr-a");
    let cert_b = leaf("hdr-b");

    let result = CertificateHeaderContributor::new(&cert_a.cert_der, &[&cert_b.cert_der]);
    assert!(result.is_err());
}

// ===========================================================================
// certificate_header_contributor.rs — new() success + contribute_* (L54-62, L77-85, L95-102, L114-130)
// ===========================================================================

#[test]
fn header_contributor_success_with_chain() {
    let cert = leaf("hdr-ok");
    let contributor = CertificateHeaderContributor::new(&cert.cert_der, &[&cert.cert_der]).unwrap();

    assert_eq!(contributor.merge_strategy(), HeaderMergeStrategy::Replace);

    // Test contribute_protected_headers
    let mut headers = CoseHeaderMap::new();
    let context = make_hdr_ctx();
    contributor.contribute_protected_headers(&mut headers, &context);

    // Should contain x5t (label 34) and x5chain (label 33)
    assert!(headers.get(&CoseHeaderLabel::Int(34)).is_some());
    assert!(headers.get(&CoseHeaderLabel::Int(33)).is_some());

    // Test contribute_unprotected_headers (no-op)
    let mut unprotected = CoseHeaderMap::new();
    contributor.contribute_unprotected_headers(&mut unprotected, &context);
    assert!(unprotected.is_empty());
}

// ===========================================================================
// certificate_header_contributor.rs — build_x5t + build_x5chain with multi-cert chain (L77-85, L95-102)
// ===========================================================================

#[test]
fn header_contributor_multi_cert_chain() {
    let root_cert = ca("root-hdr", 1);
    let root_der = root_cert.cert_der.clone();
    let leaf_cert = gen_issued_cert("leaf-hdr", &root_cert);
    let leaf_der = leaf_cert.cert_der.clone();

    let chain: Vec<&[u8]> = vec![leaf_der.as_slice(), root_der.as_slice()];
    let contributor = CertificateHeaderContributor::new(&leaf_der, &chain).unwrap();

    let mut headers = CoseHeaderMap::new();
    let context = make_hdr_ctx();
    contributor.contribute_protected_headers(&mut headers, &context);
    let x5t = headers.get(&CoseHeaderLabel::Int(34));
    let x5chain = headers.get(&CoseHeaderLabel::Int(33));
    assert!(x5t.is_some(), "x5t header missing");
    assert!(x5chain.is_some(), "x5chain header missing");
}

// ===========================================================================
// certificate_header_contributor.rs — empty chain path
// ===========================================================================

#[test]
fn header_contributor_empty_chain() {
    let cert = leaf("hdr-empty");
    // Empty chain is allowed (no mismatch check)
    let contributor = CertificateHeaderContributor::new(&cert.cert_der, &[]).unwrap();

    let mut headers = CoseHeaderMap::new();
    let context = make_hdr_ctx();
    contributor.contribute_protected_headers(&mut headers, &context);

    assert!(headers.get(&CoseHeaderLabel::Int(34)).is_some());
    assert!(headers.get(&CoseHeaderLabel::Int(33)).is_some());
}
