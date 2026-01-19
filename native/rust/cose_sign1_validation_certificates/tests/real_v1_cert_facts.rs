// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_certificates::facts::{
    CertificateSigningKeyTrustFact, X509ChainElementIdentityFact, X509ChainTrustedFact,
    X509PublicKeyAlgorithmFact, X509SigningCertificateBasicConstraintsFact,
    X509SigningCertificateEkuFact, X509SigningCertificateIdentityAllowedFact,
    X509SigningCertificateIdentityFact, X509SigningCertificateKeyUsageFact,
    X509X5ChainCertificateIdentityFact,
};
use cose_sign1_validation_certificates::pack::{CertificateTrustOptions, X509CertificateTrustPack};
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_trust::subject::TrustSubject;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

fn v1_testdata_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("v1")
        .join(file_name)
}

#[test]
fn real_v1_cose_produces_x509_signing_certificate_fact_groups() {
    let cose_path = v1_testdata_path("UnitTestSignatureWithCRL.cose");
    let cose_bytes = fs::read(cose_path).unwrap();
    let cose_arc: Arc<[u8]> = Arc::from(cose_bytes.clone().into_boxed_slice());

    let msg = TrustSubject::message(&cose_bytes);
    let signing_key = TrustSubject::primary_signing_key(&msg);

    let engine = TrustFactEngine::new(vec![Arc::new(X509CertificateTrustPack::default())])
        .with_cose_sign1_bytes(cose_arc);

    let id = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&signing_key)
        .unwrap();
    let allowed = engine
        .get_fact_set::<X509SigningCertificateIdentityAllowedFact>(&signing_key)
        .unwrap();
    let eku = engine
        .get_fact_set::<X509SigningCertificateEkuFact>(&signing_key)
        .unwrap();
    let ku = engine
        .get_fact_set::<X509SigningCertificateKeyUsageFact>(&signing_key)
        .unwrap();
    let bc = engine
        .get_fact_set::<X509SigningCertificateBasicConstraintsFact>(&signing_key)
        .unwrap();
    let alg = engine
        .get_fact_set::<X509PublicKeyAlgorithmFact>(&signing_key)
        .unwrap();

    match id {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert!(!v[0].certificate_thumbprint.is_empty());
            assert!(!v[0].subject.is_empty());
        }
        _ => panic!("expected signing certificate identity"),
    }

    match allowed {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
        }
        _ => panic!("expected identity-allowed"),
    }

    // EKUs/key usage/basic constraints may be empty depending on the certificate,
    // but the fact sets should be Available (produced) for signing key subjects.
    assert!(matches!(eku, TrustFactSet::Available(_)));
    assert!(matches!(ku, TrustFactSet::Available(_)));
    assert!(matches!(bc, TrustFactSet::Available(_)));
    assert!(matches!(alg, TrustFactSet::Available(_)));
}

#[test]
fn identity_pinning_can_allow_or_deny_thumbprints() {
    let cose_path = v1_testdata_path("UnitTestSignatureWithCRL.cose");
    let cose_bytes = fs::read(cose_path).unwrap();
    let cose_arc: Arc<[u8]> = Arc::from(cose_bytes.clone().into_boxed_slice());

    let msg = TrustSubject::message(&cose_bytes);
    let signing_key = TrustSubject::primary_signing_key(&msg);

    // First, discover the leaf thumbprint.
    let base_engine = TrustFactEngine::new(vec![Arc::new(X509CertificateTrustPack::default())])
        .with_cose_sign1_bytes(cose_arc.clone());

    let leaf_thumb = match base_engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&signing_key)
        .unwrap()
    {
        TrustFactSet::Available(v) => v[0].certificate_thumbprint.clone(),
        _ => panic!("expected identity"),
    };

    // Format the allow-list entry with whitespace + lower-case to exercise normalization.
    let spaced_lower = leaf_thumb
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|pair| pair.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ");

    let allow_pack = X509CertificateTrustPack::new(CertificateTrustOptions {
        identity_pinning_enabled: true,
        allowed_thumbprints: vec![spaced_lower],
        ..CertificateTrustOptions::default()
    });

    let allow_engine =
        TrustFactEngine::new(vec![Arc::new(allow_pack)]).with_cose_sign1_bytes(cose_arc.clone());
    let allow_fact = allow_engine
        .get_fact_set::<X509SigningCertificateIdentityAllowedFact>(&signing_key)
        .unwrap();

    match allow_fact {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert!(v[0].is_allowed);
        }
        _ => panic!("expected identity-allowed"),
    }

    let deny_pack = X509CertificateTrustPack::new(CertificateTrustOptions {
        identity_pinning_enabled: true,
        allowed_thumbprints: vec!["DEADBEEF".to_string()],
        ..CertificateTrustOptions::default()
    });

    let deny_engine =
        TrustFactEngine::new(vec![Arc::new(deny_pack)]).with_cose_sign1_bytes(cose_arc);
    let deny_fact = deny_engine
        .get_fact_set::<X509SigningCertificateIdentityAllowedFact>(&signing_key)
        .unwrap();

    match deny_fact {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert!(!v[0].is_allowed);
        }
        _ => panic!("expected identity-allowed"),
    }
}

#[test]
fn pqc_algorithm_oids_option_marks_algorithm_as_pqc() {
    let cose_path = v1_testdata_path("UnitTestSignatureWithCRL.cose");
    let cose_bytes = fs::read(cose_path).unwrap();
    let cose_arc: Arc<[u8]> = Arc::from(cose_bytes.clone().into_boxed_slice());

    let msg = TrustSubject::message(&cose_bytes);
    let signing_key = TrustSubject::primary_signing_key(&msg);

    // Discover the algorithm OID.
    let base_engine = TrustFactEngine::new(vec![Arc::new(X509CertificateTrustPack::default())])
        .with_cose_sign1_bytes(cose_arc.clone());

    let alg_oid = match base_engine
        .get_fact_set::<X509PublicKeyAlgorithmFact>(&signing_key)
        .unwrap()
    {
        TrustFactSet::Available(v) => v[0].algorithm_oid.clone(),
        _ => panic!("expected public key algorithm"),
    };

    let pqc_pack = X509CertificateTrustPack::new(CertificateTrustOptions {
        pqc_algorithm_oids: vec![format!("  {}  ", alg_oid)],
        ..CertificateTrustOptions::default()
    });

    let engine = TrustFactEngine::new(vec![Arc::new(pqc_pack)]).with_cose_sign1_bytes(cose_arc);
    let alg = engine
        .get_fact_set::<X509PublicKeyAlgorithmFact>(&signing_key)
        .unwrap();

    match alg {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert!(v[0].is_pqc);
        }
        _ => panic!("expected public key algorithm"),
    }
}

#[test]
fn non_signing_key_subjects_are_available_empty_for_cert_facts() {
    let cose_path = v1_testdata_path("UnitTestSignatureWithCRL.cose");
    let cose_bytes = fs::read(cose_path).unwrap();
    let cose_arc: Arc<[u8]> = Arc::from(cose_bytes.clone().into_boxed_slice());

    let engine = TrustFactEngine::new(vec![Arc::new(X509CertificateTrustPack::default())])
        .with_cose_sign1_bytes(cose_arc);

    let non_applicable = TrustSubject::message(&cose_bytes);

    let id = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&non_applicable)
        .unwrap();

    match id {
        TrustFactSet::Available(v) => assert_eq!(0, v.len()),
        _ => panic!("expected Available(empty)"),
    }
}

#[test]
fn chain_identity_and_trust_summary_facts_are_available_from_real_v1_cose() {
    let cose_path = v1_testdata_path("UnitTestSignatureWithCRL.cose");
    let cose_bytes = fs::read(cose_path).unwrap();
    let cose_arc: Arc<[u8]> = Arc::from(cose_bytes.clone().into_boxed_slice());

    let msg = TrustSubject::message(&cose_bytes);
    let signing_key = TrustSubject::primary_signing_key(&msg);

    let engine = TrustFactEngine::new(vec![Arc::new(X509CertificateTrustPack::default())])
        .with_cose_sign1_bytes(cose_arc);

    let x5 = engine
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&signing_key)
        .unwrap();
    let elems = engine
        .get_fact_set::<X509ChainElementIdentityFact>(&signing_key)
        .unwrap();
    let chain = engine
        .get_fact_set::<X509ChainTrustedFact>(&signing_key)
        .unwrap();
    let sk_trust = engine
        .get_fact_set::<CertificateSigningKeyTrustFact>(&signing_key)
        .unwrap();

    assert!(matches!(x5, TrustFactSet::Available(_)));
    assert!(matches!(elems, TrustFactSet::Available(_)));
    assert!(matches!(chain, TrustFactSet::Available(_)));
    assert!(matches!(sk_trust, TrustFactSet::Available(_)));
}

#[test]
fn real_v1_chain_is_trusted_and_subject_issuer_chain_matches_when_enabled() {
    let cose_path = v1_testdata_path("UnitTestSignatureWithCRL.cose");
    let cose_bytes = fs::read(cose_path).unwrap();
    let cose_arc: Arc<[u8]> = Arc::from(cose_bytes.clone().into_boxed_slice());

    let msg = TrustSubject::message(&cose_bytes);
    let signing_key = TrustSubject::primary_signing_key(&msg);

    let pack = X509CertificateTrustPack::new(CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..CertificateTrustOptions::default()
    });

    let engine = TrustFactEngine::new(vec![Arc::new(pack)]).with_cose_sign1_bytes(cose_arc);

    let leaf_id = match engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&signing_key)
        .unwrap()
    {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            v[0].clone()
        }
        _ => panic!("expected signing certificate identity"),
    };

    let mut elems = match engine
        .get_fact_set::<X509ChainElementIdentityFact>(&signing_key)
        .unwrap()
    {
        TrustFactSet::Available(v) => v,
        _ => panic!("expected chain element identity facts"),
    };

    // Ensure deterministic order for assertions.
    elems.sort_by_key(|e| e.index);

    assert!(!elems.is_empty());
    assert_eq!(0, elems[0].index);

    // Leaf element should align with signing cert identity.
    assert_eq!(leaf_id.subject, elems[0].subject);
    assert_eq!(leaf_id.issuer, elems[0].issuer);

    // Issuer chaining: issuer(i) == subject(i+1)
    for i in 0..elems.len().saturating_sub(1) {
        assert_eq!(
            elems[i].issuer,
            elems[i + 1].subject,
            "expected issuer/subject chain match at index {} -> {}",
            elems[i].index,
            elems[i + 1].index
        );
    }

    // Root should be self-signed for deterministic embedded trust.
    let root = elems.last().unwrap();
    assert_eq!(root.subject, root.issuer);

    let chain = match engine
        .get_fact_set::<X509ChainTrustedFact>(&signing_key)
        .unwrap()
    {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            v[0].clone()
        }
        _ => panic!("expected chain trust"),
    };

    assert!(chain.chain_built);
    assert!(chain.is_trusted);
    assert_eq!(0, chain.status_flags);
    assert!(chain.status_summary.is_none());

    let sk_trust = match engine
        .get_fact_set::<CertificateSigningKeyTrustFact>(&signing_key)
        .unwrap()
    {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            v[0].clone()
        }
        _ => panic!("expected signing key trust"),
    };

    assert!(sk_trust.chain_built);
    assert!(sk_trust.chain_trusted);
    assert_eq!(leaf_id.subject, sk_trust.subject);
    assert_eq!(leaf_id.issuer, sk_trust.issuer);
}
