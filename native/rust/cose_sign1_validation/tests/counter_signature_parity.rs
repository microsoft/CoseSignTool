// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::{
    CoseSign1MessageFactProducer, CounterSignature, CounterSignatureResolutionResult,
    CounterSignatureResolver, CounterSignatureSigningKeySubjectFact, CounterSignatureSubjectFact,
    PrimarySigningKeySubjectFact, UnknownCounterSignatureBytesFact,
};
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_trust::subject::TrustSubject;
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

struct TestCounterSignature {
    raw: Arc<[u8]>,
    protected: bool,
    signing_key: Arc<dyn cose_sign1_validation::SigningKey>,
}

impl CounterSignature for TestCounterSignature {
    fn raw_counter_signature_bytes(&self) -> Arc<[u8]> {
        self.raw.clone()
    }

    fn is_protected_header(&self) -> bool {
        self.protected
    }

    fn signing_key(&self) -> Arc<dyn cose_sign1_validation::SigningKey> {
        self.signing_key.clone()
    }
}

struct NoopSigningKey;

impl cose_sign1_validation::SigningKey for NoopSigningKey {
    fn key_type(&self) -> &'static str {
        "noop"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Ok(false)
    }
}

struct FixedCounterSignatureResolver {
    out: Vec<Arc<dyn CounterSignature>>,
}

impl CounterSignatureResolver for FixedCounterSignatureResolver {
    fn name(&self) -> &'static str {
        "fixed"
    }

    fn resolve(
        &self,
        _message: &cose_sign1_validation_trust::CoseSign1ParsedMessage,
    ) -> CounterSignatureResolutionResult {
        CounterSignatureResolutionResult::success(self.out.clone())
    }
}

struct FailingCounterSignatureResolver {
    name: &'static str,
    error_message: Option<&'static str>,
}

impl CounterSignatureResolver for FailingCounterSignatureResolver {
    fn name(&self) -> &'static str {
        self.name
    }

    fn resolve(
        &self,
        _message: &cose_sign1_validation_trust::CoseSign1ParsedMessage,
    ) -> CounterSignatureResolutionResult {
        CounterSignatureResolutionResult {
            is_success: false,
            error_message: self.error_message.map(|s| s.to_string()),
            ..Default::default()
        }
    }
}

fn build_cose_sign1_bytes() -> Vec<u8> {
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

    // unprotected header: empty map
    enc.map(0).unwrap();

    // payload: bstr
    b"payload".as_slice().encode(&mut enc).unwrap();

    // signature: b"sig"
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

#[test]
fn counter_signature_facts_are_empty_when_no_resolvers_registered() {
    let cose_bytes = build_cose_sign1_bytes();
    let message = cose_sign1_validation::CoseSign1::from_cbor(&cose_bytes).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        message.protected_header,
        message.unprotected_header.as_ref(),
        message.payload,
        message.signature,
    )
    .unwrap();

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");

    // Primary signing key subject is still available even if counter signature resolvers are not.
    match engine
        .get_fact_set::<PrimarySigningKeySubjectFact>(&subject)
        .unwrap()
    {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert_eq!("PrimarySigningKey", v[0].subject.kind);
        }
        other => panic!("expected Available, got {other:?}"),
    }

    match engine
        .get_fact_set::<CounterSignatureSubjectFact>(&subject)
        .unwrap()
    {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty), got {other:?}"),
    }

    match engine
        .get_fact_set::<CounterSignatureSigningKeySubjectFact>(&subject)
        .unwrap()
    {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty), got {other:?}"),
    }

    match engine
        .get_fact_set::<UnknownCounterSignatureBytesFact>(&subject)
        .unwrap()
    {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty), got {other:?}"),
    }
}

#[test]
fn counter_signature_facts_are_produced_from_resolvers() {
    let cose_bytes = build_cose_sign1_bytes();
    let message = cose_sign1_validation::CoseSign1::from_cbor(&cose_bytes).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        message.protected_header,
        message.unprotected_header.as_ref(),
        message.payload,
        message.signature,
    )
    .unwrap();

    let signing_key: Arc<dyn cose_sign1_validation::SigningKey> = Arc::new(NoopSigningKey);
    let cs = Arc::new(TestCounterSignature {
        raw: Arc::from(b"counter-sig".as_slice()),
        protected: true,
        signing_key,
    });

    let producer = Arc::new(
        CoseSign1MessageFactProducer::new().with_counter_signature_resolvers(vec![Arc::new(
            FixedCounterSignatureResolver { out: vec![cs] },
        )]),
    );

    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");

    match engine
        .get_fact_set::<PrimarySigningKeySubjectFact>(&subject)
        .unwrap()
    {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert_eq!("PrimarySigningKey", v[0].subject.kind);
        }
        other => panic!("expected Available, got {other:?}"),
    }

    let subjects = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&subject)
        .unwrap();

    match subjects {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert_eq!("CounterSignature", v[0].subject.kind);
            assert!(v[0].is_protected_header);
        }
        other => panic!("expected Available, got {other:?}"),
    }

    let signing_key_subjects = engine
        .get_fact_set::<CounterSignatureSigningKeySubjectFact>(&subject)
        .unwrap();

    match signing_key_subjects {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert_eq!("CounterSignatureSigningKey", v[0].subject.kind);
            assert!(v[0].is_protected_header);
        }
        other => panic!("expected Available, got {other:?}"),
    }

    let unknowns = engine
        .get_fact_set::<UnknownCounterSignatureBytesFact>(&subject)
        .unwrap();

    match unknowns {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert_eq!(
                b"counter-sig".as_slice(),
                v[0].raw_counter_signature_bytes.as_ref()
            );
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

#[test]
fn counter_signature_unknown_bytes_fact_is_deduplicated_by_counter_signature_id() {
    let cose_bytes = build_cose_sign1_bytes();
    let message = cose_sign1_validation::CoseSign1::from_cbor(&cose_bytes).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        message.protected_header,
        message.unprotected_header.as_ref(),
        message.payload,
        message.signature,
    )
    .unwrap();

    let signing_key: Arc<dyn cose_sign1_validation::SigningKey> = Arc::new(NoopSigningKey);
    let raw: Arc<[u8]> = Arc::from(b"same".as_slice());
    let cs1: Arc<dyn CounterSignature> = Arc::new(TestCounterSignature {
        raw: raw.clone(),
        protected: true,
        signing_key: signing_key.clone(),
    });
    let cs2: Arc<dyn CounterSignature> = Arc::new(TestCounterSignature {
        raw: raw.clone(),
        protected: false,
        signing_key,
    });

    let producer = Arc::new(
        CoseSign1MessageFactProducer::new().with_counter_signature_resolvers(vec![Arc::new(
            FixedCounterSignatureResolver {
                out: vec![cs1, cs2],
            },
        )]),
    );

    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let unknowns = engine
        .get_fact_set::<UnknownCounterSignatureBytesFact>(&subject)
        .unwrap();

    match unknowns {
        TrustFactSet::Available(v) => {
            // The subject facts are not deduped; UnknownCounterSignatureBytesFact is.
            assert_eq!(1, v.len());
            assert_eq!(
                b"same".as_slice(),
                v[0].raw_counter_signature_bytes.as_ref()
            );
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

#[test]
fn counter_signature_facts_are_missing_when_all_resolvers_fail_with_formatted_reasons() {
    let cose_bytes = build_cose_sign1_bytes();
    let message = cose_sign1_validation::CoseSign1::from_cbor(&cose_bytes).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        message.protected_header,
        message.unprotected_header.as_ref(),
        message.payload,
        message.signature,
    )
    .unwrap();

    let producer = Arc::new(
        CoseSign1MessageFactProducer::new().with_counter_signature_resolvers(vec![
            Arc::new(FailingCounterSignatureResolver {
                name: "one",
                error_message: Some("bad"),
            }),
            Arc::new(FailingCounterSignatureResolver {
                name: "two",
                error_message: Some("   "),
            }),
        ]),
    );

    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");

    let set = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    match set {
        TrustFactSet::Missing { reason } => {
            assert!(reason.contains("ProducerFailed:one:bad"));
            assert!(reason.contains("ProducerFailed:two"));
            // join separator
            assert!(reason.contains(" | "));
        }
        other => panic!("expected Missing, got {other:?}"),
    }
}
