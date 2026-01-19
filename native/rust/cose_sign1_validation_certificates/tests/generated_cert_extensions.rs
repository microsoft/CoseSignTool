// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::{CoseSign1, UnknownCounterSignatureBytesFact};
use cose_sign1_validation_certificates::facts::{
    X509PublicKeyAlgorithmFact, X509SigningCertificateBasicConstraintsFact,
    X509SigningCertificateEkuFact, X509SigningCertificateIdentityAllowedFact,
    X509SigningCertificateIdentityFact, X509SigningCertificateKeyUsageFact,
    X509X5ChainCertificateIdentityFact,
};
use cose_sign1_validation_certificates::pack::{CertificateTrustOptions, X509CertificateTrustPack};
use cose_sign1_validation_trust::error::TrustError;
use cose_sign1_validation_trust::facts::{
    FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer, TrustFactSet,
};
use cose_sign1_validation_trust::subject::TrustSubject;
use cose_sign1_validation_trust::CoseHeaderLocation;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use sha1::{Digest as _, Sha1};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tinycbor::{Encode, Encoder};
use x509_parser::prelude::{FromDer, X509Certificate};

fn build_cose_sign1_with_x5chain(
    cert_der: &[u8],
    x5chain_in_protected: bool,
    x5chain_in_unprotected: bool,
    x5chain_is_single_bstr: bool,
) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map)
    let mut hdr_buf = vec![0u8; 2048];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());

    // 1 => alg, 33 => x5chain
    let map_len = if x5chain_in_protected { 2 } else { 1 };
    hdr_enc.map(map_len).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    (-7i64).encode(&mut hdr_enc).unwrap();

    if x5chain_in_protected {
        (33i64).encode(&mut hdr_enc).unwrap();
        if x5chain_is_single_bstr {
            cert_der.encode(&mut hdr_enc).unwrap();
        } else {
            hdr_enc.array(1).unwrap();
            cert_der.encode(&mut hdr_enc).unwrap();
        }
    }

    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];
    protected_bytes.encode(&mut enc).unwrap();

    // unprotected header: map
    let map_len = if x5chain_in_unprotected { 1 } else { 0 };
    enc.map(map_len).unwrap();
    if x5chain_in_unprotected {
        (33i64).encode(&mut enc).unwrap();
        if x5chain_is_single_bstr {
            cert_der.encode(&mut enc).unwrap();
        } else {
            enc.array(1).unwrap();
            cert_der.encode(&mut enc).unwrap();
        }
    }

    // payload: null
    Option::<&[u8]>::None.encode(&mut enc).unwrap();

    // signature
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn build_cose_signature_with_x5chain(
    cert_der: &[u8],
    x5chain_in_protected: bool,
    x5chain_in_unprotected: bool,
    wrap_in_bstr: bool,
) -> Vec<u8> {
    // protected header bytes: map
    let mut hdr_buf = vec![0u8; 2048];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());

    let map_len = if x5chain_in_protected { 1 } else { 0 };
    hdr_enc.map(map_len).unwrap();
    if x5chain_in_protected {
        (33i64).encode(&mut hdr_enc).unwrap();
        hdr_enc.array(1).unwrap();
        cert_der.encode(&mut hdr_enc).unwrap();
    }

    let used_hdr = hdr_len - hdr_enc.0.len();
    hdr_buf.truncate(used_hdr);

    // COSE_Signature = [ protected: bstr(map_bytes), unprotected: map, signature: bstr ]
    let mut arr_buf = vec![0u8; 4096];
    let arr_len = arr_buf.len();
    let mut enc = Encoder(arr_buf.as_mut_slice());

    enc.array(3).unwrap();
    hdr_buf.as_slice().encode(&mut enc).unwrap();
    let map_len = if x5chain_in_unprotected { 1 } else { 0 };
    enc.map(map_len).unwrap();
    if x5chain_in_unprotected {
        (33i64).encode(&mut enc).unwrap();
        enc.array(1).unwrap();
        cert_der.encode(&mut enc).unwrap();
    }
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used_arr = arr_len - enc.0.len();
    arr_buf.truncate(used_arr);

    if !wrap_in_bstr {
        return arr_buf;
    }

    let mut wrapped = vec![0u8; 4096];
    let wrapped_len = wrapped.len();
    let mut wenc = Encoder(wrapped.as_mut_slice());
    arr_buf.as_slice().encode(&mut wenc).unwrap();
    let used = wrapped_len - wenc.0.len();
    wrapped.truncate(used);
    wrapped
}

fn generate_cert_der_with_extensions() -> Vec<u8> {
    let mut params = CertificateParams::new(vec!["leaf.example".to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "leaf.example");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));

    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::CodeSigning,
        ExtendedKeyUsagePurpose::TimeStamping,
    ];

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    cert.der().as_ref().to_vec()
}

fn generate_leaf_cert_der_with_many_usages() -> Vec<u8> {
    let mut params = CertificateParams::new(vec!["leaf2.example".to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "leaf2.example");

    // No basic constraints extension => exercises the "absent" branch.
    params.is_ca = IsCa::NoCa;

    // Key usage: attempt to set every flag the pack maps.
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::DataEncipherment,
        KeyUsagePurpose::KeyAgreement,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::EncipherOnly,
        KeyUsagePurpose::DecipherOnly,
    ];

    // EKU: cover the common boolean flags.
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::CodeSigning,
        ExtendedKeyUsagePurpose::EmailProtection,
        ExtendedKeyUsagePurpose::TimeStamping,
        ExtendedKeyUsagePurpose::OcspSigning,
    ];

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    cert.der().as_ref().to_vec()
}

fn sha1_thumbprint_hex_upper(der: &[u8]) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(der);
    hex::encode_upper(sha1.finalize())
}

#[test]
fn x509_certificate_pack_provides_reports_expected_fact_keys() {
    let pack = X509CertificateTrustPack::default();
    let provided = pack.provides();
    assert!(provided.len() >= 8);
}

struct UnknownCounterSigProducer {
    cs_bytes: Arc<[u8]>,
    called: Arc<AtomicUsize>,
}

impl TrustFactProducer for UnknownCounterSigProducer {
    fn name(&self) -> &'static str {
        "UnknownCounterSigProducer"
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact().type_id != FactKey::of::<UnknownCounterSignatureBytesFact>().type_id
        {
            return Ok(());
        }

        self.called.fetch_add(1, Ordering::SeqCst);

        let message_subject = TrustSubject::message(ctx.cose_sign1_bytes().unwrap_or_default());
        if ctx.subject().id != message_subject.id {
            return Ok(());
        }

        let cs_subject = TrustSubject::counter_signature(&message_subject, self.cs_bytes.as_ref());
        let fact = UnknownCounterSignatureBytesFact {
            counter_signature_id: cs_subject.id,
            raw_counter_signature_bytes: self.cs_bytes.clone(),
        };
        ctx.observe(fact)
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<UnknownCounterSignatureBytesFact>()])
            .as_slice()
    }
}

#[test]
fn signing_certificate_produces_eku_ku_basic_constraints_and_pqc_flag() {
    let cert_der = generate_cert_der_with_extensions();

    // Determine the algorithm OID so we can mark it as PQC in options.
    let (_, parsed) = X509Certificate::from_der(cert_der.as_slice()).unwrap();
    let alg_oid = parsed
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_id_string();

    let cose = build_cose_sign1_with_x5chain(&cert_der, true, false, false);

    let producer = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        identity_pinning_enabled: false,
        allowed_thumbprints: vec![],
        pqc_algorithm_oids: vec![format!("  {alg_oid}  ")],
        trust_embedded_chain_as_trusted: false,
    }));

    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let alg = engine
        .get_facts::<X509PublicKeyAlgorithmFact>(&subject)
        .unwrap();
    assert_eq!(1, alg.len());
    assert_eq!(alg_oid, alg[0].algorithm_oid);
    assert!(alg[0].is_pqc);

    let eku = engine
        .get_facts::<X509SigningCertificateEkuFact>(&subject)
        .unwrap();
    assert!(eku.iter().any(|e| e.oid_value == "1.3.6.1.5.5.7.3.3")); // codeSigning
    assert!(eku.iter().any(|e| e.oid_value == "1.3.6.1.5.5.7.3.8")); // timeStamping

    let ku = engine
        .get_facts::<X509SigningCertificateKeyUsageFact>(&subject)
        .unwrap();
    assert_eq!(1, ku.len());
    assert!(ku[0].usages.iter().any(|u| u == "DigitalSignature"));

    let bc = engine
        .get_facts::<X509SigningCertificateBasicConstraintsFact>(&subject)
        .unwrap();
    assert_eq!(1, bc.len());
    assert!(bc[0].is_ca);
    assert_eq!(Some(1), bc[0].path_len_constraint);
}

#[test]
fn signing_certificate_produces_all_common_ekus_and_key_usage_flags_and_bc_absent() {
    let cert_der = generate_leaf_cert_der_with_many_usages();
    let cose = build_cose_sign1_with_x5chain(&cert_der, true, false, false);

    let producer = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        identity_pinning_enabled: false,
        allowed_thumbprints: vec![],
        pqc_algorithm_oids: vec![],
        trust_embedded_chain_as_trusted: false,
    }));

    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let eku = engine
        .get_facts::<X509SigningCertificateEkuFact>(&subject)
        .unwrap();
    let eku_oids: Vec<&str> = eku.iter().map(|e| e.oid_value.as_str()).collect();
    assert!(eku_oids.contains(&"1.3.6.1.5.5.7.3.1")); // serverAuth
    assert!(eku_oids.contains(&"1.3.6.1.5.5.7.3.2")); // clientAuth
    assert!(eku_oids.contains(&"1.3.6.1.5.5.7.3.3")); // codeSigning
    assert!(eku_oids.contains(&"1.3.6.1.5.5.7.3.4")); // emailProtection
    assert!(eku_oids.contains(&"1.3.6.1.5.5.7.3.8")); // timeStamping
    assert!(eku_oids.contains(&"1.3.6.1.5.5.7.3.9")); // ocspSigning

    let ku = engine
        .get_facts::<X509SigningCertificateKeyUsageFact>(&subject)
        .unwrap();
    assert_eq!(1, ku.len());
    let usages = ku[0].usages.as_slice();
    assert!(usages.contains(&"DigitalSignature".to_string()));
    assert!(usages.contains(&"NonRepudiation".to_string()));
    assert!(usages.contains(&"KeyEncipherment".to_string()));
    assert!(usages.contains(&"DataEncipherment".to_string()));
    assert!(usages.contains(&"KeyAgreement".to_string()));
    assert!(usages.contains(&"KeyCertSign".to_string()));
    assert!(usages.contains(&"CrlSign".to_string()));
    assert!(usages.contains(&"EncipherOnly".to_string()));
    assert!(usages.contains(&"DecipherOnly".to_string()));

    let bc = engine
        .get_facts::<X509SigningCertificateBasicConstraintsFact>(&subject)
        .unwrap();
    assert_eq!(1, bc.len());
    assert!(!bc[0].is_ca);
    assert_eq!(None, bc[0].path_len_constraint);
}

#[test]
fn identity_pinning_normalizes_thumbprint() {
    let cert_der = generate_cert_der_with_extensions();
    let thumb = sha1_thumbprint_hex_upper(&cert_der);

    let cose = build_cose_sign1_with_x5chain(&cert_der, true, false, false);

    let allowed_with_spaces = format!("  {}  ", thumb.to_lowercase());

    let producer = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        identity_pinning_enabled: true,
        allowed_thumbprints: vec![allowed_with_spaces],
        pqc_algorithm_oids: vec![],
        trust_embedded_chain_as_trusted: false,
    }));

    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");
    let allowed = engine
        .get_facts::<X509SigningCertificateIdentityAllowedFact>(&subject)
        .unwrap();
    assert_eq!(1, allowed.len());
    assert!(allowed[0].is_allowed);
}

#[test]
fn counter_signature_signing_key_x5chain_is_missing_when_no_cose_bytes() {
    let cert_der = generate_cert_der_with_extensions();
    let cs_bytes = build_cose_signature_with_x5chain(&cert_der, true, false, false);

    let called = Arc::new(AtomicUsize::new(0));
    let unknown = Arc::new(UnknownCounterSigProducer {
        cs_bytes: Arc::from(cs_bytes.into_boxed_slice()),
        called: called.clone(),
    });

    let certs = Arc::new(X509CertificateTrustPack::default());
    let engine = TrustFactEngine::new(vec![certs, unknown]);

    let subject = TrustSubject::root("CounterSignatureSigningKey", b"seed");
    let chain = engine
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&subject)
        .unwrap();
    assert!(chain.is_missing());
    assert_eq!(0, called.load(Ordering::SeqCst));
}

#[test]
fn counter_signature_signing_key_x5chain_is_missing_when_unknown_counter_signatures_missing() {
    let cert_der = generate_cert_der_with_extensions();
    let cs_bytes = build_cose_signature_with_x5chain(&cert_der, true, false, false);

    // Provide outer bytes, but do not register a producer for UnknownCounterSignatureBytesFact.
    let outer_bytes: Arc<[u8]> = Arc::from(b"outer".as_slice());
    let message_subject = TrustSubject::message(outer_bytes.as_ref());
    let cs_subject = TrustSubject::counter_signature(&message_subject, &cs_bytes);
    let signing_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

    let certs = Arc::new(X509CertificateTrustPack::default());
    let engine = TrustFactEngine::new(vec![certs]).with_cose_sign1_bytes(outer_bytes);

    let chain = engine
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&signing_key_subject)
        .unwrap();
    assert!(chain.is_missing());
}

#[test]
fn counter_signature_signing_key_reads_x5chain_from_unwrapped_counter_signature_headers() {
    let cert_der = generate_cert_der_with_extensions();
    let cs_bytes = build_cose_signature_with_x5chain(&cert_der, true, false, false);

    let outer_bytes: Arc<[u8]> = Arc::from(b"outer".as_slice());
    let message_subject = TrustSubject::message(outer_bytes.as_ref());
    let cs_subject = TrustSubject::counter_signature(&message_subject, &cs_bytes);
    let signing_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

    let called = Arc::new(AtomicUsize::new(0));
    let unknown = Arc::new(UnknownCounterSigProducer {
        cs_bytes: Arc::from(cs_bytes.into_boxed_slice()),
        called,
    });
    let certs = Arc::new(X509CertificateTrustPack::default());

    let engine = TrustFactEngine::new(vec![certs, unknown]).with_cose_sign1_bytes(outer_bytes);

    let chain = engine
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&signing_key_subject)
        .unwrap();
    match chain {
        TrustFactSet::Available(items) => assert!(!items.is_empty()),
        _ => panic!("expected Available chain identity facts"),
    }
}

#[test]
fn counter_signature_signing_key_reads_x5chain_from_wrapped_counter_signature_unprotected_when_any()
{
    let cert_der = generate_cert_der_with_extensions();
    let cs_bytes = build_cose_signature_with_x5chain(&cert_der, false, true, true);

    let outer_bytes: Arc<[u8]> = Arc::from(b"outer".as_slice());
    let message_subject = TrustSubject::message(outer_bytes.as_ref());
    let cs_subject = TrustSubject::counter_signature(&message_subject, &cs_bytes);
    let signing_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

    let called = Arc::new(AtomicUsize::new(0));
    let unknown = Arc::new(UnknownCounterSigProducer {
        cs_bytes: Arc::from(cs_bytes.into_boxed_slice()),
        called,
    });
    let certs = Arc::new(X509CertificateTrustPack::default());

    let engine = TrustFactEngine::new(vec![certs, unknown])
        .with_cose_sign1_bytes(outer_bytes)
        .with_cose_header_location(CoseHeaderLocation::Any);

    let chain = engine
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&signing_key_subject)
        .unwrap();
    match chain {
        TrustFactSet::Available(items) => assert!(!items.is_empty()),
        _ => panic!("expected Available chain identity facts"),
    }
}

#[test]
fn counter_signature_signing_key_chain_is_missing_when_subject_id_does_not_match_any_counter_signature(
) {
    let cert_der = generate_cert_der_with_extensions();
    let cs_bytes = build_cose_signature_with_x5chain(&cert_der, true, false, false);

    let called = Arc::new(AtomicUsize::new(0));
    let unknown = Arc::new(UnknownCounterSigProducer {
        cs_bytes: Arc::from(cs_bytes.into_boxed_slice()),
        called,
    });
    let certs = Arc::new(X509CertificateTrustPack::default());

    let outer_bytes = Arc::from(b"outer".as_slice());
    let engine = TrustFactEngine::new(vec![certs, unknown]).with_cose_sign1_bytes(outer_bytes);

    // This kind matches the CounterSignatureSigningKey branch, but the ID won't match
    // the derived subject for the provided counter-signature bytes.
    let subject = TrustSubject::root("CounterSignatureSigningKey", b"different");
    let chain = engine
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&subject)
        .unwrap();
    assert!(chain.is_missing());
}

#[test]
fn x5chain_single_bstr_is_supported() {
    let cert_der = generate_cert_der_with_extensions();
    let cose = build_cose_sign1_with_x5chain(&cert_der, true, false, true);

    let producer = Arc::new(X509CertificateTrustPack::default());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");
    let chain = engine
        .get_facts::<X509X5ChainCertificateIdentityFact>(&subject)
        .unwrap();
    assert_eq!(1, chain.len());
    assert_eq!(40, chain[0].certificate_thumbprint.len());
}

#[test]
fn unprotected_x5chain_is_read_when_header_location_any_and_parsed_message_provided() {
    let cert_der = generate_cert_der_with_extensions();
    let cose = build_cose_sign1_with_x5chain(&cert_der, false, true, false);

    let msg = CoseSign1::from_cbor(&cose).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let producer = Arc::new(X509CertificateTrustPack::default());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_header_location(CoseHeaderLocation::Any)
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");
    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&subject)
        .unwrap();

    match identity {
        TrustFactSet::Available(v) => assert_eq!(1, v.len()),
        other => panic!("expected Available, got {other:?}"),
    }
}

#[test]
fn counter_signature_headers_can_be_bstr_wrapped_and_read_unprotected_x5chain() {
    let cert_der = generate_cert_der_with_extensions();
    let cose = build_cose_sign1_with_x5chain(&cert_der, false, false, false);

    let counter_sig = build_cose_signature_with_x5chain(&cert_der, false, true, true);
    let cs_arc: Arc<[u8]> = Arc::from(counter_sig.clone().into_boxed_slice());

    let called = Arc::new(AtomicUsize::new(0));
    let unknowns = Arc::new(UnknownCounterSigProducer {
        cs_bytes: cs_arc.clone(),
        called: called.clone(),
    });

    let cert_pack = Arc::new(X509CertificateTrustPack::default());

    let engine = TrustFactEngine::new(vec![unknowns, cert_pack])
        .with_cose_header_location(CoseHeaderLocation::Any)
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()));

    let message_subject = TrustSubject::message(cose.as_slice());
    let cs_subject = TrustSubject::counter_signature(&message_subject, counter_sig.as_slice());
    let cs_signing_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&cs_signing_key_subject)
        .unwrap();

    match identity {
        TrustFactSet::Available(v) => assert_eq!(1, v.len()),
        other => panic!("expected Available, got {other:?}"),
    }

    assert_eq!(1, called.load(Ordering::SeqCst));
}

#[test]
fn counter_signature_headers_can_be_parsed_when_not_wrapped() {
    let cert_der = generate_cert_der_with_extensions();
    let cose = build_cose_sign1_with_x5chain(&cert_der, false, false, false);

    let counter_sig = build_cose_signature_with_x5chain(&cert_der, true, false, false);
    let cs_arc: Arc<[u8]> = Arc::from(counter_sig.clone().into_boxed_slice());

    let called = Arc::new(AtomicUsize::new(0));
    let unknowns = Arc::new(UnknownCounterSigProducer {
        cs_bytes: cs_arc.clone(),
        called: called.clone(),
    });

    let cert_pack = Arc::new(X509CertificateTrustPack::default());

    let engine = TrustFactEngine::new(vec![unknowns, cert_pack])
        .with_cose_header_location(CoseHeaderLocation::Any)
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()));

    let message_subject = TrustSubject::message(cose.as_slice());
    let cs_subject = TrustSubject::counter_signature(&message_subject, counter_sig.as_slice());
    let cs_signing_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&cs_signing_key_subject)
        .unwrap();

    match identity {
        TrustFactSet::Available(v) => assert_eq!(1, v.len()),
        other => panic!("expected Available, got {other:?}"),
    }

    assert_eq!(1, called.load(Ordering::SeqCst));
}

#[test]
fn counter_signature_signing_key_subject_mismatch_results_in_missing_identity() {
    let cert_der = generate_cert_der_with_extensions();
    let cose = build_cose_sign1_with_x5chain(&cert_der, false, false, false);

    let counter_sig_a = build_cose_signature_with_x5chain(&cert_der, false, true, false);
    let counter_sig_b = build_cose_signature_with_x5chain(&cert_der, true, false, false);

    let called = Arc::new(AtomicUsize::new(0));
    let unknowns = Arc::new(UnknownCounterSigProducer {
        cs_bytes: Arc::from(counter_sig_a.clone().into_boxed_slice()),
        called: called.clone(),
    });

    let cert_pack = Arc::new(X509CertificateTrustPack::default());

    let engine = TrustFactEngine::new(vec![unknowns, cert_pack])
        .with_cose_header_location(CoseHeaderLocation::Any)
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()));

    let message_subject = TrustSubject::message(cose.as_slice());
    let cs_subject = TrustSubject::counter_signature(&message_subject, counter_sig_b.as_slice());
    let cs_signing_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&cs_signing_key_subject)
        .unwrap();

    match identity {
        TrustFactSet::Missing { reason: _ } => {}
        other => panic!("expected Missing, got {other:?}"),
    }

    assert_eq!(1, called.load(Ordering::SeqCst));
}

#[test]
fn counter_signature_missing_fields_results_in_factproduction_error() {
    let cert_der = generate_cert_der_with_extensions();
    let cose = build_cose_sign1_with_x5chain(&cert_der, false, false, false);

    // invalid COSE_Signature: [protected, unprotected] (missing signature bytes)
    let mut cs = vec![0u8; 256];
    let cs_len = cs.len();
    let mut enc = Encoder(cs.as_mut_slice());
    enc.array(2).unwrap();
    b"".as_slice().encode(&mut enc).unwrap();
    enc.map(0).unwrap();
    let used = cs_len - enc.0.len();
    cs.truncate(used);

    let cs_arc: Arc<[u8]> = Arc::from(cs.clone().into_boxed_slice());

    let unknowns = Arc::new(UnknownCounterSigProducer {
        cs_bytes: cs_arc,
        called: Arc::new(AtomicUsize::new(0)),
    });

    let cert_pack = Arc::new(X509CertificateTrustPack::default());

    let engine = TrustFactEngine::new(vec![unknowns, cert_pack])
        .with_cose_header_location(CoseHeaderLocation::Any)
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()));

    let message_subject = TrustSubject::message(cose.as_slice());
    let cs_subject = TrustSubject::counter_signature(&message_subject, cs.as_slice());
    let cs_signing_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

    let err = engine
        .get_facts::<X509SigningCertificateIdentityFact>(&cs_signing_key_subject)
        .unwrap_err();
    assert!(matches!(err, TrustError::FactProduction(_)));
}
