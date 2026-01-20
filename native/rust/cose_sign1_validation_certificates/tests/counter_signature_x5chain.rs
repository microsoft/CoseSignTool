// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_certificates::facts::X509SigningCertificateIdentityFact;
use cose_sign1_validation_certificates::pack::X509CertificateTrustPack;
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_trust::subject::TrustSubject;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

fn wrap_as_cbor_bstr(inner: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 4096 + inner.len()];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    inner.encode(&mut enc).unwrap();
    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn build_cose_sign1_minimal() -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7})  (alg = ES256)
    let mut hdr_buf = vec![0u8; 64];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(1).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    (-7i64).encode(&mut hdr_enc).unwrap();
    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];
    protected_bytes.encode(&mut enc).unwrap();

    // unprotected header: {}
    enc.map(0).unwrap();

    // payload: null
    Option::<&[u8]>::None.encode(&mut enc).unwrap();

    // signature: b"sig"
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn build_cose_signature_with_x5chain(cert_der: &[u8]) -> Vec<u8> {
    // protected header bytes: {33: [ cert_der ]}
    let mut hdr_buf = vec![0u8; 1024];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(1).unwrap();
    (33i64).encode(&mut hdr_enc).unwrap();
    hdr_enc.array(1).unwrap();
    cert_der.encode(&mut hdr_enc).unwrap();
    let used_hdr = hdr_len - hdr_enc.0.len();
    hdr_buf.truncate(used_hdr);

    // COSE_Signature = [ protected: bstr(map_bytes), unprotected: {}, signature: b"sig" ]
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(3).unwrap();
    hdr_buf.as_slice().encode(&mut enc).unwrap();
    enc.map(0).unwrap();
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn build_cose_signature_with_unprotected_x5chain(cert_der: &[u8]) -> Vec<u8> {
    // protected header bytes: {} (no x5chain)
    let mut hdr_buf = vec![0u8; 64];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(0).unwrap();
    let used_hdr = hdr_len - hdr_enc.0.len();
    hdr_buf.truncate(used_hdr);

    // COSE_Signature = [ protected: bstr(map_bytes), unprotected: {33: [ cert_der ]}, signature: b"sig" ]
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(3).unwrap();
    hdr_buf.as_slice().encode(&mut enc).unwrap();

    enc.map(1).unwrap();
    (33i64).encode(&mut enc).unwrap();
    enc.array(1).unwrap();
    cert_der.encode(&mut enc).unwrap();

    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

struct FixedCounterSignature {
    raw: Arc<[u8]>,
    protected: bool,
    signing_key: Arc<dyn SigningKey>,
}

impl CounterSignature for FixedCounterSignature {
    fn raw_counter_signature_bytes(&self) -> Arc<[u8]> {
        self.raw.clone()
    }

    fn is_protected_header(&self) -> bool {
        self.protected
    }

    fn signing_key(&self) -> Arc<dyn SigningKey> {
        self.signing_key.clone()
    }
}

struct NoopSigningKey;

impl SigningKey for NoopSigningKey {
    fn key_type(&self) -> &'static str {
        "noop"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Ok(false)
    }
}

struct OneCounterSignatureResolver {
    cs: Arc<dyn CounterSignature>,
}

impl CounterSignatureResolver for OneCounterSignatureResolver {
    fn name(&self) -> &'static str {
        "one"
    }

    fn resolve(
        &self,
        _message: &cose_sign1_validation_trust::CoseSign1ParsedMessage,
    ) -> CounterSignatureResolutionResult {
        CounterSignatureResolutionResult::success(vec![self.cs.clone()])
    }
}

#[test]
fn counter_signature_signing_key_can_produce_x5chain_identity() {
    let CertifiedKey { cert, .. } =
        generate_simple_self_signed(vec!["counter-leaf.example".to_string()]).unwrap();
    let cert_der = cert.der().as_ref().to_vec();

    let cose = build_cose_sign1_minimal();
    let counter_sig = build_cose_signature_with_x5chain(&cert_der);

    let cs = Arc::new(FixedCounterSignature {
        raw: Arc::from(counter_sig.as_slice()),
        protected: true,
        signing_key: Arc::new(NoopSigningKey),
    });

    let message_producer = Arc::new(
        CoseSign1MessageFactProducer::new()
            .with_counter_signature_resolvers(vec![Arc::new(OneCounterSignatureResolver { cs })]),
    );

    let cert_pack = Arc::new(X509CertificateTrustPack::default());

    let engine = TrustFactEngine::new(vec![message_producer, cert_pack])
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()));

    let message_subject = TrustSubject::message(cose.as_slice());
    let cs_subject = TrustSubject::counter_signature(&message_subject, counter_sig.as_slice());
    let cs_signing_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&cs_signing_key_subject)
        .unwrap();

    match identity {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert_eq!(40, v[0].certificate_thumbprint.len());
            assert!(!v[0].subject.is_empty());
            assert!(!v[0].issuer.is_empty());
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

#[test]
fn counter_signature_signing_key_parses_bstr_wrapped_cose_signature() {
    let CertifiedKey { cert, .. } =
        generate_simple_self_signed(vec!["counter-wrapped.example".to_string()]).unwrap();
    let cert_der = cert.der().as_ref().to_vec();

    let cose = build_cose_sign1_minimal();
    let counter_sig = build_cose_signature_with_x5chain(&cert_der);
    let wrapped = wrap_as_cbor_bstr(counter_sig.as_slice());

    let cs = Arc::new(FixedCounterSignature {
        raw: Arc::from(wrapped.as_slice()),
        protected: true,
        signing_key: Arc::new(NoopSigningKey),
    });

    let message_producer = Arc::new(
        CoseSign1MessageFactProducer::new()
            .with_counter_signature_resolvers(vec![Arc::new(OneCounterSignatureResolver { cs })]),
    );

    let cert_pack = Arc::new(X509CertificateTrustPack::default());
    let engine = TrustFactEngine::new(vec![message_producer, cert_pack])
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()));

    let message_subject = TrustSubject::message(cose.as_slice());
    let cs_subject = TrustSubject::counter_signature(&message_subject, wrapped.as_slice());
    let cs_signing_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&cs_signing_key_subject)
        .unwrap();
    assert!(matches!(identity, TrustFactSet::Available(_)));
}

#[test]
fn counter_signature_signing_key_can_read_x5chain_from_unprotected_when_header_location_any() {
    let CertifiedKey { cert, .. } =
        generate_simple_self_signed(vec!["counter-unprotected.example".to_string()]).unwrap();
    let cert_der = cert.der().as_ref().to_vec();

    let cose = build_cose_sign1_minimal();
    let counter_sig = build_cose_signature_with_unprotected_x5chain(&cert_der);

    let cs = Arc::new(FixedCounterSignature {
        raw: Arc::from(counter_sig.as_slice()),
        protected: false,
        signing_key: Arc::new(NoopSigningKey),
    });

    let message_producer = Arc::new(
        CoseSign1MessageFactProducer::new()
            .with_counter_signature_resolvers(vec![Arc::new(OneCounterSignatureResolver { cs })]),
    );

    let cert_pack = Arc::new(X509CertificateTrustPack::default());
    let engine = TrustFactEngine::new(vec![message_producer, cert_pack])
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()))
        .with_cose_header_location(cose_sign1_validation_trust::CoseHeaderLocation::Any);

    let message_subject = TrustSubject::message(cose.as_slice());
    let cs_subject = TrustSubject::counter_signature(&message_subject, counter_sig.as_slice());
    let cs_signing_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&cs_signing_key_subject)
        .unwrap();
    assert!(matches!(identity, TrustFactSet::Available(_)));
}
