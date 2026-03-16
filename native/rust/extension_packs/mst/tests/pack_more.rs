// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_transparent_mst::validation::facts::{MstReceiptPresentFact, MstReceiptTrustedFact};
use cose_sign1_transparent_mst::validation::pack::MstTrustPack;
use cose_sign1_validation::fluent::{
    CoseSign1TrustPack, CounterSignatureSigningKeySubjectFact, CounterSignatureSubjectFact,
    UnknownCounterSignatureBytesFact,
};
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactProducer, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;

// Inline base64url utilities for tests
const BASE64_URL_SAFE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64_encode(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 2 < input.len() {
        let n = (input[i] as u32) << 16 | (input[i + 1] as u32) << 8 | input[i + 2] as u32;
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 6) & 0x3F) as usize] as char);
        out.push(alphabet[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        if pad {
            out.push_str("==");
        }
    } else if rem == 2 {
        let n = (input[i] as u32) << 16 | (input[i + 1] as u32) << 8;
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 6) & 0x3F) as usize] as char);
        if pad {
            out.push('=');
        }
    }
    out
}

fn base64url_encode(input: &[u8]) -> String {
    base64_encode(input, BASE64_URL_SAFE, false)
}
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn encode_receipt_protected_header_bytes(issuer: &str, kid: &str, alg: i64, vds: i64) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_map(4).unwrap();

    enc.encode_i64(1).unwrap();
    enc.encode_i64(alg).unwrap();

    enc.encode_i64(4).unwrap();
    enc.encode_bstr(kid.as_bytes()).unwrap();

    enc.encode_i64(395).unwrap();
    enc.encode_i64(vds).unwrap();

    enc.encode_i64(15).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_tstr(issuer).unwrap();

    enc.into_bytes()
}

fn encode_proof_blob_bytes(
    internal_txn_hash: &[u8],
    internal_evidence: &str,
    data_hash: &[u8],
) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_map(2).unwrap();

    enc.encode_i64(1).unwrap();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(internal_txn_hash).unwrap();
    enc.encode_tstr(internal_evidence).unwrap();
    enc.encode_bstr(data_hash).unwrap();

    enc.encode_i64(2).unwrap();
    enc.encode_array(0).unwrap();

    enc.into_bytes()
}

fn build_sig_structure_for_test(protected_header_bytes: &[u8], detached_payload: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();
    enc.encode_tstr("Signature1").unwrap();
    enc.encode_bstr(protected_header_bytes).unwrap();
    enc.encode_bstr(b"").unwrap();
    enc.encode_bstr(detached_payload).unwrap();

    enc.into_bytes()
}

fn encode_receipt_bytes_with_signature(
    protected_header_bytes: &[u8],
    proof_blobs: &[Vec<u8>],
    signature_bytes: &[u8],
) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected_header_bytes).unwrap();

    enc.encode_map(1).unwrap();
    enc.encode_i64(396).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_i64(-1).unwrap();
    enc.encode_array(proof_blobs.len()).unwrap();
    for b in proof_blobs {
        enc.encode_bstr(b.as_slice()).unwrap();
    }

    enc.encode_null().unwrap();
    enc.encode_bstr(signature_bytes).unwrap();

    enc.into_bytes()
}

fn encode_statement_protected_header_bytes(alg: i64) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(alg).unwrap();

    enc.into_bytes()
}

fn encode_statement_bytes_with_receipts(
    protected_header_bytes: &[u8],
    receipts: &[Vec<u8>],
) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected_header_bytes).unwrap();

    enc.encode_map(1).unwrap();
    enc.encode_i64(394).unwrap();
    enc.encode_array(receipts.len()).unwrap();
    for r in receipts {
        enc.encode_bstr(r.as_slice()).unwrap();
    }

    enc.encode_null().unwrap();
    enc.encode_bstr(b"stmt_sig").unwrap();

    enc.into_bytes()
}

fn reencode_statement_with_cleared_unprotected_headers_for_test(statement_bytes: &[u8]) -> Vec<u8> {
    let msg =
        cose_sign1_validation::fluent::CoseSign1Message::parse(statement_bytes).expect("decode");

    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();
    enc.encode_bstr(msg.protected_header_bytes()).unwrap();
    enc.encode_map(0).unwrap();
    match &msg.payload {
        Some(p) => enc.encode_bstr(p).unwrap(),
        None => enc.encode_null().unwrap(),
    }
    enc.encode_bstr(&msg.signature).unwrap();

    enc.into_bytes()
}

fn build_valid_statement_and_receipt() -> (Vec<u8>, Vec<u8>, String) {
    // Generate an ECDSA P-256 key pair using OpenSSL.
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

    // Extract uncompressed public key point (0x04 || x || y)
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let pubkey_bytes = ec_key.public_key()
        .to_bytes(&group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx)
        .unwrap();
    assert_eq!(pubkey_bytes.len(), 65);
    assert_eq!(pubkey_bytes[0], 0x04);

    let x_b64 = base64url_encode(&pubkey_bytes[1..33]);
    let y_b64 = base64url_encode(&pubkey_bytes[33..65]);

    let kid = "test-kid";
    let jwks_json = format!(
        "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"{kid}\",\"x\":\"{x_b64}\",\"y\":\"{y_b64}\"}}]}}"
    );

    let statement_protected = encode_statement_protected_header_bytes(-7);
    let statement_bytes = encode_statement_bytes_with_receipts(
        statement_protected.as_slice(),
        &[b"placeholder".to_vec()],
    );

    let normalized =
        reencode_statement_with_cleared_unprotected_headers_for_test(statement_bytes.as_slice());
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

    // Sign using OpenSSL ECDSA with SHA-256.
    // COSE ECDSA uses fixed-length r||s format (not DER).
    let sig_der = {
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey).unwrap();
        signer.sign_oneshot_to_vec(&sig_structure).unwrap()
    };
    // Convert DER-encoded ECDSA signature to fixed-length r||s format (64 bytes for P-256)
    let signature_bytes = cose_sign1_crypto_openssl::ecdsa_format::der_to_fixed(&sig_der, 64)
        .expect("der_to_fixed");
    assert_eq!(signature_bytes.len(), 64, "P-256 fixed sig should be 64 bytes");

    let receipt_bytes = encode_receipt_bytes_with_signature(
        receipt_protected.as_slice(),
        &[proof_blob],
        signature_bytes.as_slice(),
    );

    // Embed the actual receipt into the statement to exercise the pack's receipt parsing.
    let statement_bytes_with_receipt = encode_statement_bytes_with_receipts(
        statement_protected.as_slice(),
        &[receipt_bytes.clone()],
    );

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
        "cose_sign1_transparent_mst::MstTrustPack",
        TrustFactProducer::name(&online)
    );
}

#[test]
fn mst_pack_counter_signature_subject_with_message_but_no_bytes_is_noop_available() {
    let (statement_bytes, receipt_bytes, jwks_json) = build_valid_statement_and_receipt();

    let pack = MstTrustPack::offline_with_jwks(jwks_json);
    let producer = Arc::new(pack);

    // Parsed message is available, but raw bytes are deliberately not provided.
    let parsed = CoseSign1Message::parse(statement_bytes.as_slice()).expect("parse statement");

    let engine = TrustFactEngine::new(vec![producer]).with_cose_sign1_message(Arc::new(parsed));

    // Any counter signature subject will hit the early-return branch when message bytes are absent.
    let seed_message_subject = TrustSubject::message(b"seed");
    let cs_subject =
        TrustSubject::counter_signature(&seed_message_subject, receipt_bytes.as_slice());

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
    let statement_bytes = encode_statement_bytes_with_receipts(
        statement_protected.as_slice(),
        &[receipt_bytes.clone(), receipt_bytes.clone()],
    );

    let parsed = CoseSign1Message::parse(statement_bytes.as_slice()).expect("parsed");

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

    assert_eq!(
        cs.len(),
        2,
        "counter signature subjects are projected per receipt"
    );
}

#[test]
fn mst_pack_can_verify_a_valid_receipt_and_emit_trusted_fact() {
    let (statement_bytes, receipt_bytes, jwks_json) = build_valid_statement_and_receipt();

    let parsed = CoseSign1Message::parse(statement_bytes.as_slice()).expect("parse statement");

    let pack = MstTrustPack::offline_with_jwks(jwks_json);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(statement_bytes.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let message_subject = TrustSubject::message(statement_bytes.as_slice());
    let cs_subject = TrustSubject::counter_signature(&message_subject, receipt_bytes.as_slice());

    let out = engine
        .get_fact_set::<MstReceiptTrustedFact>(&cs_subject)
        .expect("mst trusted fact set");

    let Some(values) = out.as_available() else {
        panic!("expected Available");
    };

    assert_eq!(values.len(), 1);
    assert!(
        values[0].trusted,
        "expected the receipt to verify successfully"
    );
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

    let parsed = CoseSign1Message::parse(statement_bytes.as_slice()).expect("parse statement");

    let pack = MstTrustPack::offline_with_jwks(jwks_json);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(statement_bytes.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

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
    let statement_bytes = encode_statement_bytes_with_receipts(
        statement_protected.as_slice(),
        &[receipt_bytes.clone()],
    );

    let parsed = CoseSign1Message::parse(statement_bytes.as_slice()).expect("parsed");

    let pack = MstTrustPack::offline_with_jwks(jwks_json);
    let engine =
        TrustFactEngine::new(vec![Arc::new(pack)]).with_cose_sign1_message(Arc::new(parsed));

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

    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected.as_slice()).unwrap();

    enc.encode_map(1).unwrap();
    enc.encode_i64(394).unwrap();
    enc.encode_bstr(receipt_bytes.as_slice()).unwrap();

    enc.encode_null().unwrap();
    enc.encode_bstr(b"stmt_sig").unwrap();

    let cose_bytes = enc.into_bytes();

    let parsed = CoseSign1Message::parse(cose_bytes.as_slice()).expect("parsed");

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
    let (_statement_bytes, _receipt_bytes, jwks_json) = build_valid_statement_and_receipt();

    // COSE_Sign1 with unprotected header: { 394: 1 } which is invalid for MST receipts.
    let protected = encode_statement_protected_header_bytes(-7);

    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected.as_slice()).unwrap();

    enc.encode_map(1).unwrap();
    enc.encode_i64(394).unwrap();
    enc.encode_i64(1).unwrap();

    enc.encode_null().unwrap();
    enc.encode_bstr(b"stmt_sig").unwrap();

    let cose_bytes = enc.into_bytes();

    let parsed = CoseSign1Message::parse(cose_bytes.as_slice()).expect("parsed");

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
    let (_statement_bytes, _receipt_bytes, jwks_json) = build_valid_statement_and_receipt();

    // COSE_Sign1 with unprotected header: { 394: 1 } triggers the fallback CBOR decode path.
    let protected = encode_statement_protected_header_bytes(-7);

    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected.as_slice()).unwrap();

    enc.encode_map(1).unwrap();
    enc.encode_i64(394).unwrap();
    enc.encode_i64(1).unwrap();

    enc.encode_null().unwrap();
    enc.encode_bstr(b"stmt_sig").unwrap();

    let cose_bytes = enc.into_bytes();

    let parsed = CoseSign1Message::parse(cose_bytes.as_slice()).expect("parse statement");

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
fn mst_pack_counter_signature_subject_not_in_receipts_is_noop_available() {
    let (statement_bytes, _receipt_bytes, jwks_json) = build_valid_statement_and_receipt();

    let pack = MstTrustPack::offline_with_jwks(jwks_json);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(statement_bytes.clone().into_boxed_slice()));

    let message_subject = TrustSubject::message(statement_bytes.as_slice());
    let cs_subject = TrustSubject::counter_signature(&message_subject, b"not-a-receipt");

    let out = engine
        .get_fact_set::<MstReceiptPresentFact>(&cs_subject)
        .expect("fact set");

    let Some(values) = out.as_available() else {
        panic!("expected Available");
    };
    assert!(values.is_empty());
}

#[test]
fn mst_pack_default_trust_plan_is_present() {
    let pack = MstTrustPack::offline_with_jwks("{\"keys\":[]}".to_string());
    let plan = CoseSign1TrustPack::default_trust_plan(&pack);
    assert!(plan.is_some());
}

#[test]
fn mst_pack_try_read_receipts_no_label_returns_empty() {
    // Minimal COSE_Sign1: [ bstr(a0), {}, null, bstr("sig") ]
    let cose_bytes = vec![0x84, 0x41, 0xA0, 0xA0, 0xF6, 0x43, b's', b'i', b'g'];

    let pack = MstTrustPack::online();
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()));

    let message_subject = TrustSubject::message(b"seed");
    let cs_subjects = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&message_subject)
        .expect("fact set");

    let Some(values) = cs_subjects.as_available() else {
        panic!("expected Available");
    };
    assert!(values.is_empty());
}
