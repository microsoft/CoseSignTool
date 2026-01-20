// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use base64::Engine;
use cose_sign1_validation::fluent::{
    CoseSign1TrustPack, CounterSignatureSigningKeySubjectFact, CounterSignatureSubjectFact,
    UnknownCounterSignatureBytesFact,
};
use cose_sign1_validation_transparent_mst::facts::MstReceiptTrustedFact;
use cose_sign1_validation_transparent_mst::pack::MstTrustPack;
use cose_sign1_validation_trust::cose_sign1::CoseSign1ParsedMessage;
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactProducer, TrustFactSet};
use cose_sign1_validation_trust::subject::TrustSubject;
use ring::{rand, signature};
use ring::signature::KeyPair as _;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn encode_receipt_protected_header_bytes(issuer: &str, kid: &str, alg: i64, vds: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(4).unwrap();

    (1i64).encode(&mut enc).unwrap();
    alg.encode(&mut enc).unwrap();

    (4i64).encode(&mut enc).unwrap();
    kid.as_bytes().encode(&mut enc).unwrap();

    (395i64).encode(&mut enc).unwrap();
    vds.encode(&mut enc).unwrap();

    (15i64).encode(&mut enc).unwrap();
    enc.map(1).unwrap();
    (1i64).encode(&mut enc).unwrap();
    issuer.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_proof_blob_bytes(
    internal_txn_hash: &[u8],
    internal_evidence: &str,
    data_hash: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(2).unwrap();

    (1i64).encode(&mut enc).unwrap();
    enc.array(3).unwrap();
    internal_txn_hash.encode(&mut enc).unwrap();
    internal_evidence.encode(&mut enc).unwrap();
    data_hash.encode(&mut enc).unwrap();

    (2i64).encode(&mut enc).unwrap();
    enc.array(0).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn build_sig_structure_for_test(protected_header_bytes: &[u8], detached_payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; protected_header_bytes.len() + detached_payload.len() + 256];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();
    "Signature1".encode(&mut enc).unwrap();
    protected_header_bytes.encode(&mut enc).unwrap();
    b"".as_slice().encode(&mut enc).unwrap();
    detached_payload.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_receipt_bytes_with_signature(
    protected_header_bytes: &[u8],
    proof_blobs: &[Vec<u8>],
    signature_bytes: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0u8; 4096 + signature_bytes.len()];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();
    protected_header_bytes.encode(&mut enc).unwrap();

    enc.map(1).unwrap();
    (396i64).encode(&mut enc).unwrap();
    enc.map(1).unwrap();
    (-1i64).encode(&mut enc).unwrap();
    enc.array(proof_blobs.len()).unwrap();
    for b in proof_blobs {
        b.as_slice().encode(&mut enc).unwrap();
    }

    Option::<&[u8]>::None.encode(&mut enc).unwrap();
    signature_bytes.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_statement_protected_header_bytes(alg: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 128];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(1).unwrap();
    (1i64).encode(&mut enc).unwrap();
    alg.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_statement_bytes_with_receipts(protected_header_bytes: &[u8], receipts: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = vec![0u8; 4096 + receipts.iter().map(|r| r.len()).sum::<usize>()];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();
    protected_header_bytes.encode(&mut enc).unwrap();

    enc.map(1).unwrap();
    (394i64).encode(&mut enc).unwrap();
    enc.array(receipts.len()).unwrap();
    for r in receipts {
        r.as_slice().encode(&mut enc).unwrap();
    }

    Option::<&[u8]>::None.encode(&mut enc).unwrap();
    b"stmt_sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn reencode_statement_with_cleared_unprotected_headers_for_test(statement_bytes: &[u8]) -> Vec<u8> {
    let msg = cose_sign1_validation::fluent::CoseSign1::from_cbor(statement_bytes).expect("decode");

    let mut buf = vec![0u8; statement_bytes.len() + 128];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();
    msg.protected_header.encode(&mut enc).unwrap();
    enc.map(0).unwrap();
    msg.payload.encode(&mut enc).unwrap();
    msg.signature.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn build_valid_statement_and_receipt() -> (Vec<u8>, Vec<u8>, String) {
    let rng = rand::SystemRandom::new();
    let key_pair_pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .expect("ring key generation");

    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        key_pair_pkcs8.as_ref(),
        &rng,
    )
    .expect("ring key accepted");

    let pubkey = key_pair.public_key().as_ref();
    assert_eq!(pubkey.len(), 65);
    assert_eq!(pubkey[0], 0x04);

    let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pubkey[1..33]);
    let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pubkey[33..65]);

    let kid = "test-kid";
    let jwks_json = format!(
        "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"{kid}\",\"x\":\"{x_b64}\",\"y\":\"{y_b64}\"}}]}}"
    );

    let statement_protected = encode_statement_protected_header_bytes(-7);
    let statement_bytes = encode_statement_bytes_with_receipts(
        statement_protected.as_slice(),
        &[b"placeholder".to_vec()],
    );

    let normalized = reencode_statement_with_cleared_unprotected_headers_for_test(statement_bytes.as_slice());
    let statement_hash = sha256(normalized.as_slice());

    let internal_txn_hash = [0u8; 32];
    let internal_evidence = "evidence";
    let proof_blob = encode_proof_blob_bytes(
        internal_txn_hash.as_slice(),
        internal_evidence,
        statement_hash.as_slice(),
    );

    let internal_evidence_hash = sha256(internal_evidence.as_bytes());
    let mut h = Sha256::new();
    h.update(internal_txn_hash);
    h.update(internal_evidence_hash);
    h.update(statement_hash);
    let acc: [u8; 32] = h.finalize().into();

    let issuer = "example.com";
    let receipt_protected = encode_receipt_protected_header_bytes(issuer, kid, -7, 2);
    let sig_structure = build_sig_structure_for_test(receipt_protected.as_slice(), acc.as_slice());
    let signature_bytes = key_pair
        .sign(&rng, sig_structure.as_slice())
        .expect("ecdsa sign")
        .as_ref()
        .to_vec();

    let receipt_bytes = encode_receipt_bytes_with_signature(
        receipt_protected.as_slice(),
        &[proof_blob],
        signature_bytes.as_slice(),
    );

    // Embed the actual receipt into the statement to exercise the pack's receipt parsing.
    let statement_bytes_with_receipt =
        encode_statement_bytes_with_receipts(statement_protected.as_slice(), &[receipt_bytes.clone()]);

    (statement_bytes_with_receipt, receipt_bytes, jwks_json)
}

#[test]
fn mst_pack_constructors_set_expected_fields() {
    let offline = MstTrustPack::offline_with_jwks("{\"keys\":[]}".to_string());
    assert!(!offline.allow_network);
    assert!(offline.offline_jwks_json.is_some());
    assert!(offline.jwks_api_version.is_none());

    let online = MstTrustPack::online();
    assert!(online.allow_network);

    assert_eq!("MstTrustPack", CoseSign1TrustPack::name(&online));
    assert_eq!(
        "cose_sign1_validation_transparent_mst::MstTrustPack",
        TrustFactProducer::name(&online)
    );
}

#[test]
fn mst_pack_counter_signature_subject_with_message_but_no_bytes_is_noop_available() {
    let (statement_bytes, receipt_bytes, jwks_json) = build_valid_statement_and_receipt();

    let pack = MstTrustPack::offline_with_jwks(jwks_json);
    let producer = Arc::new(pack);

    // Parsed message is available, but raw bytes are deliberately not provided.
    let msg = cose_sign1_validation::fluent::CoseSign1::from_cbor(statement_bytes.as_slice())
        .expect("decode statement");
    let parsed = CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .expect("parse statement");

    let engine = TrustFactEngine::new(vec![producer]).with_cose_sign1_message(Arc::new(parsed));

    // Any counter signature subject will hit the early-return branch when message bytes are absent.
    let seed_message_subject = TrustSubject::message(b"seed");
    let cs_subject = TrustSubject::counter_signature(&seed_message_subject, receipt_bytes.as_slice());

    // Trigger production by asking for an MST fact.
    let facts = engine
        .get_facts::<MstReceiptTrustedFact>(&cs_subject)
        .expect("facts should be available (possibly empty)");

    // Nothing is emitted without raw message bytes, but the request should succeed.
    assert!(facts.is_empty());
}

#[test]
fn mst_pack_projects_receipts_and_dedupes_unknown_bytes_by_counter_signature_id() {
    let (_statement_bytes, receipt_bytes, jwks_json) = build_valid_statement_and_receipt();

    // Duplicate the same receipt twice to exercise dedupe.
    let statement_protected = encode_statement_protected_header_bytes(-7);
    let statement_bytes =
        encode_statement_bytes_with_receipts(statement_protected.as_slice(), &[receipt_bytes.clone(), receipt_bytes.clone()]);

    let cose = cose_sign1_validation::fluent::CoseSign1::from_cbor(statement_bytes.as_slice()).expect("decode");
    let parsed = CoseSign1ParsedMessage::from_parts(
        cose.protected_header,
        cose.unprotected_header.as_ref(),
        cose.payload,
        cose.signature,
    )
    .expect("parsed");

    let pack = MstTrustPack::offline_with_jwks(jwks_json);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(statement_bytes.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let message_subject = TrustSubject::message(statement_bytes.as_slice());

    let unknown = engine
        .get_fact_set::<UnknownCounterSignatureBytesFact>(&message_subject)
        .expect("fact set");

    let Some(values) = unknown.as_available() else {
        panic!("expected Available");
    };

    assert_eq!(values.len(), 1, "duplicate receipts should dedupe");

    let cs_subjects = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&message_subject)
        .expect("cs subject facts");

    let Some(cs) = cs_subjects.as_available() else {
        panic!("expected Available");
    };

    assert_eq!(cs.len(), 2, "counter signature subjects are projected per receipt");
}

#[test]
fn mst_pack_can_verify_a_valid_receipt_and_emit_trusted_fact() {
    let (statement_bytes, receipt_bytes, jwks_json) = build_valid_statement_and_receipt();

    let pack = MstTrustPack::offline_with_jwks(jwks_json);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(statement_bytes.clone().into_boxed_slice()));

    let message_subject = TrustSubject::message(statement_bytes.as_slice());
    let cs_subject = TrustSubject::counter_signature(&message_subject, receipt_bytes.as_slice());

    let out = engine
        .get_fact_set::<MstReceiptTrustedFact>(&cs_subject)
        .expect("mst trusted fact set");

    let Some(values) = out.as_available() else {
        panic!("expected Available");
    };

    assert_eq!(values.len(), 1);
    assert!(values[0].trusted, "expected the receipt to verify successfully");
}

#[test]
fn mst_pack_marks_non_microsoft_receipts_as_untrusted_but_available() {
    let (_statement_bytes, _receipt_bytes, jwks_json) = build_valid_statement_and_receipt();

    // Re-encode the receipt with an unsupported VDS value; pack should treat as untrusted receipt.
    let protected = encode_receipt_protected_header_bytes("example.com", "kid", -7, 123);
    let receipt = encode_receipt_bytes_with_signature(&protected, &[], b"");

    let statement_protected = encode_statement_protected_header_bytes(-7);
    let statement_bytes =
        encode_statement_bytes_with_receipts(statement_protected.as_slice(), &[receipt.clone()]);

    let pack = MstTrustPack::offline_with_jwks(jwks_json);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(statement_bytes.clone().into_boxed_slice()));

    let message_subject = TrustSubject::message(statement_bytes.as_slice());
    let cs_subject = TrustSubject::counter_signature(&message_subject, receipt.as_slice());

    let out = engine
        .get_fact_set::<MstReceiptTrustedFact>(&cs_subject)
        .expect("mst trusted fact set");

    let Some(values) = out.as_available() else {
        panic!("expected Available");
    };

    assert_eq!(values.len(), 1);
    assert!(!values[0].trusted);
    assert!(values[0]
        .details
        .as_deref()
        .unwrap_or_default()
        .contains("unsupported_vds"));

}

#[test]
fn mst_pack_is_noop_for_unknown_subject_kinds() {
    let pack = MstTrustPack::online();
    let engine = TrustFactEngine::new(vec![Arc::new(pack)]);

    let subject = TrustSubject::root("NotAMstSubject", b"seed");

    let out = engine
        .get_fact_set::<MstReceiptTrustedFact>(&subject)
        .expect("fact set");

    let Some(values) = out.as_available() else {
        panic!("expected Available");
    };
    assert!(values.is_empty());
}

#[test]
fn mst_pack_projects_receipts_when_only_parsed_message_is_available() {
    let (_statement_bytes, receipt_bytes, jwks_json) = build_valid_statement_and_receipt();

    // Build a statement that contains a single receipt, but do not provide raw COSE bytes to the engine.
    let statement_protected = encode_statement_protected_header_bytes(-7);
    let statement_bytes =
        encode_statement_bytes_with_receipts(statement_protected.as_slice(), &[receipt_bytes.clone()]);

    let cose = cose_sign1_validation::fluent::CoseSign1::from_cbor(statement_bytes.as_slice())
        .expect("decode");
    let parsed = CoseSign1ParsedMessage::from_parts(
        cose.protected_header,
        cose.unprotected_header.as_ref(),
        cose.payload,
        cose.signature,
    )
    .expect("parsed");

    let pack = MstTrustPack::offline_with_jwks(jwks_json);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)]).with_cose_sign1_message(Arc::new(parsed));

    // Use the same seed bytes the pack falls back to when raw message bytes are not available.
    let message_subject = TrustSubject::message(b"seed");
    let cs_subjects = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&message_subject)
        .expect("fact set");

    let Some(cs) = cs_subjects.as_available() else {
        panic!("expected Available");
    };
    assert_eq!(cs.len(), 1);

    // Ensure UnknownCounterSignatureBytesFact is also projected.
    let unknown = engine
        .get_fact_set::<UnknownCounterSignatureBytesFact>(&message_subject)
        .expect("fact set");
    let Some(values) = unknown.as_available() else {
        panic!("expected Available");
    };
    assert_eq!(values.len(), 1);
}

#[test]
fn mst_pack_receipts_header_single_bstr_is_a_fact_production_error() {
    let (_statement_bytes, receipt_bytes, jwks_json) = build_valid_statement_and_receipt();

    // COSE_Sign1 with unprotected header: { 394: bstr(receipt) } which is invalid for MST receipts.
    let protected = encode_statement_protected_header_bytes(-7);

    let mut buf = vec![0u8; 4096 + receipt_bytes.len()];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.array(4).unwrap();
    protected.as_slice().encode(&mut enc).unwrap();

    enc.map(1).unwrap();
    (394i64).encode(&mut enc).unwrap();
    receipt_bytes.as_slice().encode(&mut enc).unwrap();

    Option::<&[u8]>::None.encode(&mut enc).unwrap();
    b"stmt_sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    let cose_bytes = buf;

    let msg = cose_sign1_validation::fluent::CoseSign1::from_cbor(cose_bytes.as_slice()).expect("decode");
    let parsed = CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .expect("parsed");

    let pack = MstTrustPack::offline_with_jwks(jwks_json);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let message_subject = TrustSubject::message(b"seed");
    let err = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&message_subject)
        .expect_err("expected invalid header error");

    let msg = err.to_string();
    assert!(msg.contains("invalid header"));
}

#[test]
fn mst_pack_marks_message_scoped_counter_signature_facts_missing_when_message_not_provided() {
    let pack = MstTrustPack::online();
    let engine = TrustFactEngine::new(vec![Arc::new(pack)]);

    let subject = TrustSubject::message(b"seed");

    let cs_subjects = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&subject)
        .expect("fact set");
    assert!(matches!(cs_subjects, TrustFactSet::Missing { .. }));

    let cs_key_subjects = engine
        .get_fact_set::<CounterSignatureSigningKeySubjectFact>(&subject)
        .expect("fact set");
    assert!(matches!(cs_key_subjects, TrustFactSet::Missing { .. }));

    let unknown = engine
        .get_fact_set::<UnknownCounterSignatureBytesFact>(&subject)
        .expect("fact set");
    assert!(matches!(unknown, TrustFactSet::Missing { .. }));
}

#[test]
fn mst_pack_marks_counter_signature_receipt_facts_missing_when_message_not_provided() {
    let pack = MstTrustPack::online();
    let engine = TrustFactEngine::new(vec![Arc::new(pack)]);

    let message_subject = TrustSubject::message(b"seed");
    let cs_subject = TrustSubject::counter_signature(&message_subject, b"receipt");

    let trusted = engine
        .get_fact_set::<MstReceiptTrustedFact>(&cs_subject)
        .expect("fact set");
    assert!(matches!(trusted, TrustFactSet::Missing { .. }));
}

#[test]
fn mst_pack_receipts_header_non_bytes_value_in_parsed_message_is_a_fact_production_error() {
    let (_statement_bytes, receipt_bytes, jwks_json) = build_valid_statement_and_receipt();

    // COSE_Sign1 with unprotected header: { 394: 1 } which is invalid for MST receipts.
    let protected = encode_statement_protected_header_bytes(-7);

    let mut buf = vec![0u8; 4096 + receipt_bytes.len()];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.array(4).unwrap();
    protected.as_slice().encode(&mut enc).unwrap();

    enc.map(1).unwrap();
    (394i64).encode(&mut enc).unwrap();
    (1i64).encode(&mut enc).unwrap();

    Option::<&[u8]>::None.encode(&mut enc).unwrap();
    b"stmt_sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    let cose_bytes = buf;

    let msg =
        cose_sign1_validation::fluent::CoseSign1::from_cbor(cose_bytes.as_slice()).expect("decode");
    let parsed = CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .expect("parsed");

    let pack = MstTrustPack::offline_with_jwks(jwks_json);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let message_subject = TrustSubject::message(b"seed");
    let err = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&message_subject)
        .expect_err("expected invalid header error");
    assert!(err.to_string().contains("invalid header"));
}

#[test]
fn mst_pack_receipts_header_non_array_value_in_unprotected_bytes_is_a_fact_production_error() {
    let (_statement_bytes, receipt_bytes, jwks_json) = build_valid_statement_and_receipt();

    // COSE_Sign1 with unprotected header: { 394: 1 } triggers the fallback CBOR decode path.
    let protected = encode_statement_protected_header_bytes(-7);

    let mut buf = vec![0u8; 4096 + receipt_bytes.len()];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.array(4).unwrap();
    protected.as_slice().encode(&mut enc).unwrap();

    enc.map(1).unwrap();
    (394i64).encode(&mut enc).unwrap();
    (1i64).encode(&mut enc).unwrap();

    Option::<&[u8]>::None.encode(&mut enc).unwrap();
    b"stmt_sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    let cose_bytes = buf;

    let pack = MstTrustPack::offline_with_jwks(jwks_json);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()));

    let message_subject = TrustSubject::message(b"seed");
    let err = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&message_subject)
        .expect_err("expected invalid header error");
    assert!(err.to_string().contains("invalid header"));
}
