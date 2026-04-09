// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_certificates::validation::facts::X509SigningCertificateIdentityFact;
use cose_sign1_certificates::validation::pack::X509CertificateTrustPack;
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use crypto_primitives::{CryptoError, CryptoVerifier};
use cose_sign1_certificates_local::{
    CertificateFactory, CertificateOptions, EphemeralCertificateFactory, SoftwareKeyProvider,
};
use std::sync::Arc;

fn wrap_as_cbor_bstr(inner: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_bstr(inner).unwrap();
    enc.into_bytes()
}

fn build_cose_sign1_minimal() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7})  (alg = ES256)
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(1).unwrap();
    hdr_enc.encode_i64(-7).unwrap();
    let protected_bytes = hdr_enc.into_bytes();
    enc.encode_bstr(&protected_bytes).unwrap();

    // unprotected header: {}
    enc.encode_map(0).unwrap();

    // payload: null
    enc.encode_null().unwrap();

    // signature: b"sig"
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

fn build_cose_signature_with_x5chain(cert_der: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;

    // protected header bytes: {33: [ cert_der ]}
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_array(1).unwrap();
    hdr_enc.encode_bstr(cert_der).unwrap();
    let hdr_buf = hdr_enc.into_bytes();

    // COSE_Signature = [ protected: bstr(map_bytes), unprotected: {}, signature: b"sig" ]
    let mut enc = p.encoder();

    enc.encode_array(3).unwrap();
    enc.encode_bstr(&hdr_buf).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

fn build_cose_signature_with_unprotected_x5chain(cert_der: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;

    // protected header bytes: {} (no x5chain)
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(0).unwrap();
    let hdr_buf = hdr_enc.into_bytes();

    // COSE_Signature = [ protected: bstr(map_bytes), unprotected: {33: [ cert_der ]}, signature: b"sig" ]
    let mut enc = p.encoder();

    enc.encode_array(3).unwrap();
    enc.encode_bstr(&hdr_buf).unwrap();

    enc.encode_map(1).unwrap();
    enc.encode_i64(33).unwrap();
    enc.encode_array(1).unwrap();
    enc.encode_bstr(cert_der).unwrap();

    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

struct FixedCounterSignature {
    raw: Arc<[u8]>,
    protected: bool,
    cose_key: Arc<dyn CryptoVerifier>,
}

impl CounterSignature for FixedCounterSignature {
    fn raw_counter_signature_bytes(&self) -> Arc<[u8]> {
        self.raw.clone()
    }

    fn is_protected_header(&self) -> bool {
        self.protected
    }

    fn cose_key(&self) -> Arc<dyn CryptoVerifier> {
        self.cose_key.clone()
    }
}

struct NoopCoseKey;

impl CryptoVerifier for NoopCoseKey {
    fn algorithm(&self) -> i64 {
        -7 // ES256
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
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
        _message: &cose_sign1_primitives::CoseSign1Message,
    ) -> CounterSignatureResolutionResult {
        CounterSignatureResolutionResult::success(vec![self.cs.clone()])
    }
}

#[test]
fn counter_signature_signing_key_can_produce_x5chain_identity() {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert_obj = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=counter-leaf.example")
                .add_subject_alternative_name("counter-leaf.example"),
        )
        .unwrap();
    let cert_der = cert_obj.cert_der.clone();

    let cose = build_cose_sign1_minimal();
    let counter_sig = build_cose_signature_with_x5chain(&cert_der);

    let cs = Arc::new(FixedCounterSignature {
        raw: Arc::from(counter_sig.as_slice()),
        protected: true,
        cose_key: Arc::new(NoopCoseKey),
    });

    let message_producer = Arc::new(
        CoseSign1MessageFactProducer::new()
            .with_counter_signature_resolvers(vec![Arc::new(OneCounterSignatureResolver { cs })]),
    );

    let cert_pack = Arc::new(X509CertificateTrustPack::new(Default::default()));

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let engine = TrustFactEngine::new(vec![message_producer, cert_pack])
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let message_subject = TrustSubject::message(cose.as_slice());
    let cs_subject = TrustSubject::counter_signature(&message_subject, counter_sig.as_slice());
    let cs_signing_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&cs_signing_key_subject)
        .unwrap();

    match identity {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert_eq!(64, v[0].certificate_thumbprint.len());
            assert!(!v[0].subject.is_empty());
            assert!(!v[0].issuer.is_empty());
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

#[test]
fn counter_signature_signing_key_parses_bstr_wrapped_cose_signature() {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert_obj = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=counter-wrapped.example")
                .add_subject_alternative_name("counter-wrapped.example"),
        )
        .unwrap();
    let cert_der = cert_obj.cert_der.clone();

    let cose = build_cose_sign1_minimal();
    let counter_sig = build_cose_signature_with_x5chain(&cert_der);
    let wrapped = wrap_as_cbor_bstr(counter_sig.as_slice());

    let cs = Arc::new(FixedCounterSignature {
        raw: Arc::from(wrapped.as_slice()),
        protected: true,
        cose_key: Arc::new(NoopCoseKey),
    });

    let message_producer = Arc::new(
        CoseSign1MessageFactProducer::new()
            .with_counter_signature_resolvers(vec![Arc::new(OneCounterSignatureResolver { cs })]),
    );

    let cert_pack = Arc::new(X509CertificateTrustPack::new(Default::default()));

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let engine = TrustFactEngine::new(vec![message_producer, cert_pack])
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

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
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert_obj = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=counter-unprotected.example")
                .add_subject_alternative_name("counter-unprotected.example"),
        )
        .unwrap();
    let cert_der = cert_obj.cert_der.clone();

    let cose = build_cose_sign1_minimal();
    let counter_sig = build_cose_signature_with_unprotected_x5chain(&cert_der);

    let cs = Arc::new(FixedCounterSignature {
        raw: Arc::from(counter_sig.as_slice()),
        protected: false,
        cose_key: Arc::new(NoopCoseKey),
    });

    let message_producer = Arc::new(
        CoseSign1MessageFactProducer::new()
            .with_counter_signature_resolvers(vec![Arc::new(OneCounterSignatureResolver { cs })]),
    );

    let cert_pack = Arc::new(X509CertificateTrustPack::new(Default::default()));

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let engine = TrustFactEngine::new(vec![message_producer, cert_pack])
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed))
        .with_cose_header_location(cose_sign1_validation_primitives::CoseHeaderLocation::Any);

    let message_subject = TrustSubject::message(cose.as_slice());
    let cs_subject = TrustSubject::counter_signature(&message_subject, counter_sig.as_slice());
    let cs_signing_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&cs_signing_key_subject)
        .unwrap();
    assert!(matches!(identity, TrustFactSet::Available(_)));
}
