// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for uncovered x5chain parsing paths in `pack.rs`.
//!
//! These cover:
//! - Single bstr x5chain (not array)
//! - Skipping non-x5chain header entries
//! - Indefinite-length map header error
//! - Indefinite-length x5chain array error
//! - bstr-wrapped COSE_Signature encoding
//! - Empty x5chain (no label 33 in headers)

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal COSE_Sign1 message (no x5chain).
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

/// Build a COSE_Signature with x5chain as a *single bstr* (not array).
/// Protected header: {33: bstr(cert_der)}
fn build_cose_signature_x5chain_single_bstr(cert_der: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;

    // protected header bytes: {33: cert_der}  (single bstr, not array)
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_bstr(cert_der).unwrap();
    let hdr_buf = hdr_enc.into_bytes();

    // COSE_Signature = [protected: bstr(map_bytes), unprotected: {}, signature: b"sig"]
    let mut enc = p.encoder();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&hdr_buf).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

/// Build a COSE_Signature whose protected header has non-x5chain entries
/// *before* the x5chain entry.
/// Protected header: {1: -7, 33: [cert_der]}
fn build_cose_signature_with_extra_headers(cert_der: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;

    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(2).unwrap();
    // entry 1: alg = ES256  (label 1, not x5chain)
    hdr_enc.encode_i64(1).unwrap();
    hdr_enc.encode_i64(-7).unwrap();
    // entry 2: x5chain = [cert_der]
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_array(1).unwrap();
    hdr_enc.encode_bstr(cert_der).unwrap();
    let hdr_buf = hdr_enc.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&hdr_buf).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

/// Build a COSE_Signature whose protected header uses an indefinite-length map.
fn build_cose_signature_indefinite_map(cert_der: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;

    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map_indefinite_begin().unwrap();
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_bstr(cert_der).unwrap();
    hdr_enc.encode_break().unwrap();
    let hdr_buf = hdr_enc.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&hdr_buf).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

/// Build a COSE_Signature whose protected header has x5chain as an
/// indefinite-length array.
fn build_cose_signature_indefinite_x5chain_array(cert_der: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;

    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_array_indefinite_begin().unwrap();
    hdr_enc.encode_bstr(cert_der).unwrap();
    hdr_enc.encode_break().unwrap();
    let hdr_buf = hdr_enc.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&hdr_buf).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

/// Build a COSE_Signature with no x5chain in headers.
fn build_cose_signature_no_x5chain() -> Vec<u8> {
    let p = EverParseCborProvider;

    // protected header: {1: -7}  (alg only)
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(1).unwrap();
    hdr_enc.encode_i64(-7).unwrap();
    let hdr_buf = hdr_enc.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&hdr_buf).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

/// Wrap raw bytes as a CBOR bstr (bstr-wrapped encoding).
fn wrap_as_cbor_bstr(inner: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_bstr(inner).unwrap();
    enc.into_bytes()
}

/// Build a COSE_Signature array and then wrap the whole thing as a bstr.
fn build_bstr_wrapped_cose_signature_x5chain(cert_der: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;

    // protected header bytes: {33: [cert_der]}
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_array(1).unwrap();
    hdr_enc.encode_bstr(cert_der).unwrap();
    let hdr_buf = hdr_enc.into_bytes();

    // Inner COSE_Signature array
    let mut inner_enc = p.encoder();
    inner_enc.encode_array(3).unwrap();
    inner_enc.encode_bstr(&hdr_buf).unwrap();
    inner_enc.encode_map(0).unwrap();
    inner_enc.encode_bstr(b"sig").unwrap();
    let inner = inner_enc.into_bytes();

    // Wrap it
    wrap_as_cbor_bstr(&inner)
}

// ---------------------------------------------------------------------------
// Counter-signature plumbing (reused from counter_signature_x5chain.rs)
// ---------------------------------------------------------------------------

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
        -7
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

    fn resolve(&self, _message: &CoseSign1Message) -> CounterSignatureResolutionResult {
        CounterSignatureResolutionResult::success(vec![self.cs.clone()])
    }
}

/// Helper: run the engine for a counter-signature signing key and return the
/// identity fact set.
fn run_counter_sig_identity(
    counter_sig_bytes: &[u8],
) -> TrustFactSet<X509SigningCertificateIdentityFact> {
    let cose = build_cose_sign1_minimal();

    let cs = Arc::new(FixedCounterSignature {
        raw: Arc::from(counter_sig_bytes),
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
    let cs_subject = TrustSubject::counter_signature(&message_subject, counter_sig_bytes);
    let cs_signing_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

    engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&cs_signing_key_subject)
        .unwrap()
}

fn generate_cert_der() -> Vec<u8> {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=test.example.com")
                .add_subject_alternative_name("test.example.com"),
        )
        .unwrap();
    cert.cert_der.clone()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Lines 121-124: x5chain is a single bstr, not wrapped in an array.
#[test]
fn single_bstr_x5chain_produces_identity() {
    let cert_der = generate_cert_der();
    let counter_sig = build_cose_signature_x5chain_single_bstr(&cert_der);

    let identity = run_counter_sig_identity(&counter_sig);

    match identity {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len(), "expected exactly one certificate");
            assert_eq!(64, v[0].certificate_thumbprint.len());
            assert!(!v[0].subject.is_empty());
            assert!(!v[0].issuer.is_empty());
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

/// Lines 148, 150-152: header map has non-x5chain entries that must be skipped.
#[test]
fn skip_non_x5chain_header_entries() {
    let cert_der = generate_cert_der();
    let counter_sig = build_cose_signature_with_extra_headers(&cert_der);

    let identity = run_counter_sig_identity(&counter_sig);

    match identity {
        TrustFactSet::Available(v) => {
            assert_eq!(
                1,
                v.len(),
                "expected exactly one certificate after skipping non-x5chain"
            );
            assert_eq!(64, v[0].certificate_thumbprint.len());
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

/// Lines 98-100: indefinite-length map header triggers an error.
#[test]
fn indefinite_length_map_header_is_error() {
    let cert_der = generate_cert_der();
    let counter_sig = build_cose_signature_indefinite_map(&cert_der);

    let cose = build_cose_sign1_minimal();

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

    let result = engine.get_fact_set::<X509SigningCertificateIdentityFact>(&cs_signing_key_subject);

    assert!(
        result.is_err(),
        "indefinite-length map should produce an error"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("indefinite-length maps not supported"),
        "error message should mention indefinite-length maps, got: {err_msg}"
    );
}

/// Lines 134-136: indefinite-length x5chain array triggers an error.
#[test]
fn indefinite_length_x5chain_array_is_error() {
    let cert_der = generate_cert_der();
    let counter_sig = build_cose_signature_indefinite_x5chain_array(&cert_der);

    let cose = build_cose_sign1_minimal();

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

    let result = engine.get_fact_set::<X509SigningCertificateIdentityFact>(&cs_signing_key_subject);

    assert!(
        result.is_err(),
        "indefinite-length x5chain array should produce an error"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("indefinite-length x5chain arrays not supported"),
        "error message should mention indefinite-length x5chain, got: {err_msg}"
    );
}

/// Lines 185-203: bstr-wrapped COSE_Signature encoding is handled.
#[test]
fn bstr_wrapped_cose_signature_produces_identity() {
    let cert_der = generate_cert_der();
    let counter_sig = build_bstr_wrapped_cose_signature_x5chain(&cert_der);

    let identity = run_counter_sig_identity(&counter_sig);

    match identity {
        TrustFactSet::Available(v) => {
            assert_eq!(
                1,
                v.len(),
                "expected one certificate from bstr-wrapped encoding"
            );
            assert_eq!(64, v[0].certificate_thumbprint.len());
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

/// No label 33 in headers results in missing identity facts.
#[test]
fn no_x5chain_in_counter_signature_headers_produces_missing() {
    let counter_sig = build_cose_signature_no_x5chain();

    let cose = build_cose_sign1_minimal();

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

    assert!(
        identity.is_missing(),
        "no x5chain should result in Missing identity, got {identity:?}"
    );
}

/// Multiple non-x5chain entries all skipped before reaching label 33.
#[test]
fn multiple_non_x5chain_entries_all_skipped() {
    let cert_der = generate_cert_der();
    let p = EverParseCborProvider;

    // protected header: {1: -7, 4: b"kid", 33: [cert_der]}
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(3).unwrap();
    hdr_enc.encode_i64(1).unwrap();
    hdr_enc.encode_i64(-7).unwrap();
    hdr_enc.encode_i64(4).unwrap();
    hdr_enc.encode_bstr(b"kid").unwrap();
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_array(1).unwrap();
    hdr_enc.encode_bstr(&cert_der).unwrap();
    let hdr_buf = hdr_enc.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&hdr_buf).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"sig").unwrap();
    let counter_sig = enc.into_bytes();

    let identity = run_counter_sig_identity(&counter_sig);

    match identity {
        TrustFactSet::Available(v) => {
            assert_eq!(
                1,
                v.len(),
                "expected one certificate after skipping two entries"
            );
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

/// x5chain with multiple certificates in an array.
#[test]
fn x5chain_array_with_multiple_certs() {
    let cert_der_1 = generate_cert_der();
    let cert_der_2 = generate_cert_der();
    let p = EverParseCborProvider;

    // protected header: {33: [cert_der_1, cert_der_2]}
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_array(2).unwrap();
    hdr_enc.encode_bstr(&cert_der_1).unwrap();
    hdr_enc.encode_bstr(&cert_der_2).unwrap();
    let hdr_buf = hdr_enc.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&hdr_buf).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"sig").unwrap();
    let counter_sig = enc.into_bytes();

    let identity = run_counter_sig_identity(&counter_sig);

    match identity {
        TrustFactSet::Available(v) => {
            // X509SigningCertificateIdentityFact is for the leaf only;
            // having two certs in the x5chain array still yields one identity fact.
            assert_eq!(1, v.len(), "expected one identity fact for the leaf cert");
            assert_eq!(64, v[0].certificate_thumbprint.len());
        }
        other => panic!("expected Available, got {other:?}"),
    }
}
