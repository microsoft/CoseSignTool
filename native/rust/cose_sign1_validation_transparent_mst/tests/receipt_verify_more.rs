// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_transparent_mst::receipt_verify::{
    verify_mst_receipt, ReceiptVerifyError, ReceiptVerifyInput,
};
use base64::Engine;
use cose_sign1_validation::fluent::CoseSign1;
use ring::{rand, signature};
use ring::signature::KeyPair as _;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use tinycbor::{Encode, Encoder};

const TEST_JWKS_JSON: &str =
    include_str!("../testdata/esrp-cts-cp.confidential-ledger.azure.com.jwks.json");

const TEST_KID: &str =
    "a7ad3b7729516ca443fa472a0f2faa4a984ee3da7eafd17f98dcffbac4a6a10f";

// Base64url (no pad) encodings for all-zero coordinate arrays.
// 32 bytes => 43 base64url chars; 48 bytes => 64 base64url chars.
const B64URL_32_ZERO: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const B64URL_48_ZERO: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn spawn_one_shot_http_server(status_code: u16, body: &'static str) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);

        let status_line = match status_code {
            200 => "HTTP/1.1 200 OK".to_string(),
            204 => "HTTP/1.1 204 No Content".to_string(),
            500 => "HTTP/1.1 500 Internal Server Error".to_string(),
            other => format!("HTTP/1.1 {other} Status"),
        };

        let resp = format!(
            "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.as_bytes().len()
        );
        let _ = stream.write_all(resp.as_bytes());
    });

    (format!("http://{}", addr), handle)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn encode_protected_header_bytes(issuer: &str, kid: &str, alg: i64, vds: i64) -> Vec<u8> {
    // Protected header is a CBOR map stored as bstr in COSE_Sign1.
    // ReceiptVerify expects an int-keyed map with:
    // - 1 (alg)
    // - 4 (kid)
    // - 395 (vds)
    // - 15 (cwt claims) => { 1 (iss): "..." }
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

fn encode_protected_header_bytes_with_extra_negative_key(
    issuer: &str,
    kid: &str,
    alg: i64,
    vds: i64,
) -> Vec<u8> {
    // Same as encode_protected_header_bytes(), but includes an extra negative int key to
    // exercise CBOR negative-int key decoding in the receipt verifier.
    let mut buf = vec![0u8; 512];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(5).unwrap();

    (-1i64).encode(&mut enc).unwrap();
    (0i64).encode(&mut enc).unwrap();

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

fn encode_protected_header_bytes_without_alg(issuer: &str, kid: &str, vds: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    // { 4: kid, 395: vds, 15: { 1: issuer } }
    enc.map(3).unwrap();

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

fn encode_protected_header_bytes_without_kid(issuer: &str, alg: i64, vds: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    // { 1: alg, 395: vds, 15: { 1: issuer } }
    enc.map(3).unwrap();

    (1i64).encode(&mut enc).unwrap();
    alg.encode(&mut enc).unwrap();

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

fn encode_protected_header_bytes_without_vds(issuer: &str, kid: &str, alg: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    // { 1: alg, 4: kid, 15: { 1: issuer } }
    enc.map(3).unwrap();

    (1i64).encode(&mut enc).unwrap();
    alg.encode(&mut enc).unwrap();

    (4i64).encode(&mut enc).unwrap();
    kid.as_bytes().encode(&mut enc).unwrap();

    (15i64).encode(&mut enc).unwrap();
    enc.map(1).unwrap();
    (1i64).encode(&mut enc).unwrap();
    issuer.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_protected_header_bytes_without_issuer(kid: &str, alg: i64, vds: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    // { 1: alg, 4: kid, 395: vds }
    enc.map(3).unwrap();

    (1i64).encode(&mut enc).unwrap();
    alg.encode(&mut enc).unwrap();

    (4i64).encode(&mut enc).unwrap();
    kid.as_bytes().encode(&mut enc).unwrap();

    (395i64).encode(&mut enc).unwrap();
    vds.encode(&mut enc).unwrap();

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

    // Map { 1: leaf, 2: path }
    enc.map(2).unwrap();

    // 1 => leaf = [ internal_txn_hash, internal_evidence, data_hash ]
    (1i64).encode(&mut enc).unwrap();
    enc.array(3).unwrap();
    internal_txn_hash.encode(&mut enc).unwrap();
    internal_evidence.encode(&mut enc).unwrap();
    data_hash.encode(&mut enc).unwrap();

    // 2 => path = []
    (2i64).encode(&mut enc).unwrap();
    enc.array(0).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_proof_blob_bytes_with_path(
    internal_txn_hash: &[u8],
    internal_evidence: &str,
    data_hash: &[u8],
    path: &[(bool, &[u8])],
) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    // Map { 1: leaf, 2: path }
    enc.map(2).unwrap();

    // 1 => leaf = [ internal_txn_hash, internal_evidence, data_hash ]
    (1i64).encode(&mut enc).unwrap();
    enc.array(3).unwrap();
    internal_txn_hash.encode(&mut enc).unwrap();
    internal_evidence.encode(&mut enc).unwrap();
    data_hash.encode(&mut enc).unwrap();

    // 2 => path = [ [bool, bstr] ... ]
    (2i64).encode(&mut enc).unwrap();
    enc.array(path.len()).unwrap();
    for (is_left, sibling) in path {
        enc.array(2).unwrap();
        is_left.encode(&mut enc).unwrap();
        sibling.encode(&mut enc).unwrap();
    }

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_proof_blob_bytes_with_empty_leaf_and_path() -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(2).unwrap();

    (1i64).encode(&mut enc).unwrap();
    enc.array(0).unwrap();

    (2i64).encode(&mut enc).unwrap();
    enc.array(0).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_proof_blob_bytes_with_leaf_missing_internal_evidence(internal_txn_hash: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(2).unwrap();

    (1i64).encode(&mut enc).unwrap();
    enc.array(1).unwrap();
    internal_txn_hash.encode(&mut enc).unwrap();

    (2i64).encode(&mut enc).unwrap();
    enc.array(0).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_proof_blob_bytes_with_path_missing_hash(
    internal_txn_hash: &[u8],
    internal_evidence: &str,
    data_hash: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(2).unwrap();

    (1i64).encode(&mut enc).unwrap();
    enc.array(3).unwrap();
    internal_txn_hash.encode(&mut enc).unwrap();
    internal_evidence.encode(&mut enc).unwrap();
    data_hash.encode(&mut enc).unwrap();

    (2i64).encode(&mut enc).unwrap();
    enc.array(1).unwrap();
    enc.array(1).unwrap();
    true.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn prepend(prefix: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(prefix.len() + bytes.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(bytes);
    out
}

fn encode_receipt_bytes(protected_header_bytes: &[u8], vdp_proof_blobs: Option<&[Vec<u8>]>) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    // COSE_Sign1 = [ protected: bstr, unprotected: map, payload, signature ]
    enc.array(4).unwrap();

    protected_header_bytes.encode(&mut enc).unwrap();

    match vdp_proof_blobs {
        None => {
            enc.map(0).unwrap();
        }
        Some(blobs) => {
            // Unprotected header with VDP label 396 -> map { -1: [ bstr(proof_blob)... ] }
            enc.map(1).unwrap();
            (396i64).encode(&mut enc).unwrap();

            enc.map(1).unwrap();
            (-1i64).encode(&mut enc).unwrap();
            enc.array(blobs.len()).unwrap();
            for b in blobs {
                b.as_slice().encode(&mut enc).unwrap();
            }
        }
    }

    // payload: nil
    Option::<&[u8]>::None.encode(&mut enc).unwrap();

    // signature: placeholder bytes
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_receipt_bytes_with_signature(
    protected_header_bytes: &[u8],
    vdp_proof_blobs: &[Vec<u8>],
    signature_bytes: &[u8],
) -> Vec<u8> {
    let mut buf = vec![0u8; 4096 + signature_bytes.len()];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    // COSE_Sign1 = [ protected: bstr, unprotected: map, payload, signature ]
    enc.array(4).unwrap();

    protected_header_bytes.encode(&mut enc).unwrap();

    // Unprotected header with VDP label 396 -> map { -1: [ bstr(proof_blob)... ] }
    enc.map(1).unwrap();
    (396i64).encode(&mut enc).unwrap();

    enc.map(1).unwrap();
    (-1i64).encode(&mut enc).unwrap();
    enc.array(vdp_proof_blobs.len()).unwrap();
    for b in vdp_proof_blobs {
        b.as_slice().encode(&mut enc).unwrap();
    }

    // payload: nil
    Option::<&[u8]>::None.encode(&mut enc).unwrap();

    // signature: raw r||s for ES256
    signature_bytes.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_statement_protected_header_bytes(alg: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 128];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    // Minimal int-keyed protected header: { 1: alg }
    enc.map(1).unwrap();
    (1i64).encode(&mut enc).unwrap();
    alg.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_statement_bytes_with_receipts(
    protected_header_bytes: &[u8],
    receipts: &[Vec<u8>],
) -> Vec<u8> {
    let mut buf = vec![0u8; 4096 + receipts.iter().map(|r| r.len()).sum::<usize>()];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    // COSE_Sign1 = [ protected: bstr, unprotected: map, payload, signature ]
    enc.array(4).unwrap();
    protected_header_bytes.encode(&mut enc).unwrap();

    // Unprotected header includes MST receipt header label 394 -> [ bstr(receipt)... ]
    enc.map(1).unwrap();
    (394i64).encode(&mut enc).unwrap();
    enc.array(receipts.len()).unwrap();
    for r in receipts {
        r.as_slice().encode(&mut enc).unwrap();
    }

    // payload: nil
    Option::<&[u8]>::None.encode(&mut enc).unwrap();

    // signature: arbitrary bytes (not used by receipt verification)
    b"stmt_sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn reencode_statement_with_cleared_unprotected_headers_for_test(
    statement_bytes: &[u8],
) -> Vec<u8> {
    let msg = CoseSign1::from_cbor(statement_bytes).expect("statement decode");

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

fn build_sig_structure_for_test(
    protected_header_bytes: &[u8],
    detached_payload: &[u8],
) -> Vec<u8> {
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

#[test]
fn verify_mst_receipt_can_succeed_for_a_self_signed_es256_test_vector() {
    // Generate an ephemeral ES256 keypair. (Non-deterministic, but stable in practice.)
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
    assert_eq!(pubkey.len(), 65, "expected uncompressed P-256 point");
    assert_eq!(pubkey[0], 0x04, "expected uncompressed point prefix");

    let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(&pubkey[1..33]);
    let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(&pubkey[33..65]);

    let kid = "test-kid";
    let jwks_json = format!(
        "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"{kid}\",\"x\":\"{x_b64}\",\"y\":\"{y_b64}\"}}]}}"
    );

    // Create a statement that contains an MST receipt in its unprotected header.
    // The verifier will re-encode with unprotected headers cleared before hashing.
    let statement_protected = encode_statement_protected_header_bytes(-7);
    let statement_bytes = encode_statement_bytes_with_receipts(
        statement_protected.as_slice(),
        &[b"placeholder_receipt".to_vec()],
    );

    let normalized = reencode_statement_with_cleared_unprotected_headers_for_test(statement_bytes.as_slice());
    let statement_hash = sha256(normalized.as_slice());

    // Build a proof whose data_hash matches the statement digest.
    let internal_txn_hash = [0u8; 32];
    let internal_evidence = "evidence";
    let proof_blob = encode_proof_blob_bytes(
        internal_txn_hash.as_slice(),
        internal_evidence,
        statement_hash.as_slice(),
    );

    // Accumulator = sha256(internal_txn_hash || sha256(internal_evidence) || data_hash)
    let internal_evidence_hash = sha256(internal_evidence.as_bytes());
    let mut h = Sha256::new();
    h.update(internal_txn_hash);
    h.update(internal_evidence_hash);
    h.update(statement_hash);
    let acc: [u8; 32] = h.finalize().into();

    // Sign Sig_structure using the receipt protected header bytes.
    let issuer = "example.com";
    let receipt_protected = encode_protected_header_bytes(issuer, kid, -7, 2);
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

    let out = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement_bytes.as_slice(),
        receipt_bytes: receipt_bytes.as_slice(),
        offline_jwks_json: Some(jwks_json.as_str()),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect("receipt verification");

    assert!(out.trusted);
    assert_eq!(out.issuer, issuer);
    assert_eq!(out.kid, kid);
    assert_eq!(out.statement_sha256, statement_hash);
}

#[test]
fn verify_mst_receipt_skips_data_hash_mismatched_proof_and_returns_signature_invalid() {
    // Exercise the `continue` path when a parsed proof's data_hash doesn't match.
    let issuer = "example.com";
    let kid = "kid";

    let statement_protected = encode_statement_protected_header_bytes(-7);
    let statement_bytes = encode_statement_bytes_with_receipts(
        statement_protected.as_slice(),
        &[b"placeholder_receipt".to_vec()],
    );

    // Intentionally NOT the statement hash.
    let proof_blob = encode_proof_blob_bytes(
        [0u8; 32].as_slice(),
        "evidence",
        [0u8; 32].as_slice(),
    );

    let receipt_protected = encode_protected_header_bytes(issuer, kid, -7, 2);
    let receipt_bytes = encode_receipt_bytes(receipt_protected.as_slice(), Some(&[proof_blob]));

    let jwks_json = minimal_jwks_json_for_kid(kid, "P-256");

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement_bytes.as_slice(),
        receipt_bytes: receipt_bytes.as_slice(),
        offline_jwks_json: Some(jwks_json.as_str()),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .unwrap_err();

    assert!(matches!(err, ReceiptVerifyError::SignatureInvalid));
}

#[test]
fn verify_mst_receipt_folds_non_empty_path_and_returns_signature_invalid() {
    // Exercise the path-folding loop (both left and right branches).
    let issuer = "example.com";
    let kid = "kid";

    let statement_protected = encode_statement_protected_header_bytes(-7);
    let statement_bytes = encode_statement_bytes_with_receipts(
        statement_protected.as_slice(),
        &[b"placeholder_receipt".to_vec()],
    );

    let normalized = reencode_statement_with_cleared_unprotected_headers_for_test(statement_bytes.as_slice());
    let statement_hash = sha256(normalized.as_slice());

    let sibling_left = [0x11u8; 32];
    let sibling_right = [0x22u8; 32];
    let path: Vec<(bool, &[u8])> = vec![
        (true, sibling_left.as_slice()),
        (false, sibling_right.as_slice()),
    ];

    let proof_blob = encode_proof_blob_bytes_with_path(
        [0u8; 32].as_slice(),
        "evidence",
        statement_hash.as_slice(),
        path.as_slice(),
    );

    let receipt_protected = encode_protected_header_bytes(issuer, kid, -7, 2);
    let receipt_bytes = encode_receipt_bytes(receipt_protected.as_slice(), Some(&[proof_blob]));

    let jwks_json = minimal_jwks_json_for_kid(kid, "P-256");

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement_bytes.as_slice(),
        receipt_bytes: receipt_bytes.as_slice(),
        offline_jwks_json: Some(jwks_json.as_str()),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .unwrap_err();

    assert!(matches!(err, ReceiptVerifyError::SignatureInvalid));
}

#[test]
fn verify_mst_receipt_accepts_tag_18_with_all_integer_width_encodings() {
    // Exercise tag parsing branches (AI 0..23, 24, 25, 26, 27) in is_cose_sign1_tagged_18.
    let issuer = "example.com";
    let kid = "kid";

    let statement_protected = encode_statement_protected_header_bytes(-7);
    let untagged_statement = encode_statement_bytes_with_receipts(
        statement_protected.as_slice(),
        &[b"placeholder_receipt".to_vec()],
    );

    let tag_prefixes: Vec<Vec<u8>> = vec![
        vec![0xD2],
        vec![0xD8, 0x12],
        vec![0xD9, 0x00, 0x12],
        vec![0xDA, 0x00, 0x00, 0x00, 0x12],
        vec![0xDB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12],
    ];

    // Provide a proof blob that is parseable but whose data_hash won't match,
    // so we don't need to reproduce the exact normalized hashing behavior here.
    let proof_blob = encode_proof_blob_bytes(
        [0u8; 32].as_slice(),
        "evidence",
        [0u8; 32].as_slice(),
    );

    let receipt_protected = encode_protected_header_bytes(issuer, kid, -7, 2);
    let receipt_bytes = encode_receipt_bytes(receipt_protected.as_slice(), Some(&[proof_blob]));
    let jwks_json = minimal_jwks_json_for_kid(kid, "P-256");

    for prefix in tag_prefixes {
        let statement_bytes = prepend(prefix.as_slice(), untagged_statement.as_slice());
        let err = verify_mst_receipt(ReceiptVerifyInput {
            statement_bytes_with_receipts: statement_bytes.as_slice(),
            receipt_bytes: receipt_bytes.as_slice(),
            offline_jwks_json: Some(jwks_json.as_str()),
            allow_network_fetch: false,
            jwks_api_version: None,
        })
        .unwrap_err();

        assert!(matches!(err, ReceiptVerifyError::SignatureInvalid));
    }
}

#[test]
fn verify_mst_receipt_statement_reencode_errors_on_invalid_tag_encoding() {
    let issuer = "example.com";
    let kid = "kid";

    // Tag major type with AI=24 but missing the tag value byte.
    let statement_bytes = vec![0xD8];

    let proof_blob = encode_proof_blob_bytes(
        [0u8; 32].as_slice(),
        "evidence",
        [0u8; 32].as_slice(),
    );

    let receipt_protected = encode_protected_header_bytes(issuer, kid, -7, 2);
    let receipt_bytes = encode_receipt_bytes(receipt_protected.as_slice(), Some(&[proof_blob]));
    let jwks_json = minimal_jwks_json_for_kid(kid, "P-256");

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement_bytes.as_slice(),
        receipt_bytes: receipt_bytes.as_slice(),
        offline_jwks_json: Some(jwks_json.as_str()),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .unwrap_err();

    match err {
        ReceiptVerifyError::StatementReencode(msg) => {
            assert!(msg.contains("invalid CBOR tag encoding"));
        }
        other => panic!("expected StatementReencode, got {other:?}"),
    }
}

fn encode_receipt_bytes_with_vdp_proof_label(
    protected_header_bytes: &[u8],
    proof_label: i64,
    blobs: &[Vec<u8>],
) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    // COSE_Sign1 = [ protected: bstr, unprotected: map, payload, signature ]
    enc.array(4).unwrap();
    protected_header_bytes.encode(&mut enc).unwrap();

    // Unprotected header with VDP label 396 -> map { proof_label: [ bstr(proof_blob)... ] }
    enc.map(1).unwrap();
    (396i64).encode(&mut enc).unwrap();
    enc.map(1).unwrap();
    proof_label.encode(&mut enc).unwrap();
    enc.array(blobs.len()).unwrap();
    for b in blobs {
        b.as_slice().encode(&mut enc).unwrap();
    }

    Option::<&[u8]>::None.encode(&mut enc).unwrap();
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn minimal_jwks_json_for_kid(kid: &str, crv: &str) -> String {
    format!(
        r#"{{"keys":[{{"kty":"EC","crv":"{crv}","kid":"{kid}","x":"{x}","y":"{y}"}}]}}"#,
        kid = kid,
        crv = crv,
        x = if crv == "P-256" {
            B64URL_32_ZERO
        } else {
            B64URL_48_ZERO
        },
        y = if crv == "P-256" {
            B64URL_32_ZERO
        } else {
            B64URL_48_ZERO
        }
    )
}

fn encode_statement_bytes(tagged: bool) -> Vec<u8> {
    let mut inner_buf = vec![0u8; 256];
    let inner_len = inner_buf.len();
    let mut enc = Encoder(inner_buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header bytes: encode empty map {} and wrap in bstr
    let mut hdr_buf = vec![0u8; 64];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(0).unwrap();
    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];
    protected_bytes.encode(&mut enc).unwrap();

    // unprotected header: empty map
    enc.map(0).unwrap();

    // payload: nil
    Option::<&[u8]>::None.encode(&mut enc).unwrap();

    // signature: placeholder bytes
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = inner_len - enc.0.len();
    inner_buf.truncate(used);

    if tagged {
        let mut out = Vec::with_capacity(1 + inner_buf.len());
        // tag(18)
        out.push(0xD2);
        out.extend_from_slice(inner_buf.as_slice());
        out
    } else {
        inner_buf
    }
}

#[test]
fn verify_mst_receipt_errors_when_jwks_is_invalid_json() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some("{not json"),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected jwks parse failure");

    assert!(matches!(err, ReceiptVerifyError::JwksParse(_)));
}

#[test]
fn verify_mst_receipt_errors_when_statement_has_invalid_tag_encoding() {
    // Major type 6 (tag), AI=24 (one-byte tag value), but truncated (missing tag value byte).
    let statement = vec![0xD8];
    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    // Provide a minimal non-empty proof blob so receipt parsing progresses past VDP extraction.
    let receipt = encode_receipt_bytes(&protected, Some(&[vec![0xA0]]));

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected statement reencode failure");

    assert!(matches!(err, ReceiptVerifyError::StatementReencode(_)));
}

#[test]
fn verify_mst_receipt_errors_when_alg_missing() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes_without_alg("issuer", TEST_KID, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected missing alg");

    assert!(matches!(err, ReceiptVerifyError::MissingAlg));
}

#[test]
fn verify_mst_receipt_errors_when_kid_missing() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes_without_kid("issuer", -35, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected missing kid");

    assert!(matches!(err, ReceiptVerifyError::MissingKid));
}

#[test]
fn verify_mst_receipt_errors_when_vds_missing() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes_without_vds("issuer", TEST_KID, -35);
    let receipt = encode_receipt_bytes(&protected, None);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected unsupported vds when missing");

    assert!(matches!(err, ReceiptVerifyError::UnsupportedVds(_)));
}

#[test]
fn verify_mst_receipt_errors_when_vds_unsupported_value() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 123);
    let receipt = encode_receipt_bytes(&protected, None);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected unsupported vds");

    assert!(matches!(err, ReceiptVerifyError::UnsupportedVds(123)));
}

#[test]
fn verify_mst_receipt_errors_when_issuer_missing() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes_without_issuer(TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected missing issuer");

    assert!(matches!(err, ReceiptVerifyError::MissingIssuer));
}

#[test]
fn verify_mst_receipt_errors_when_vdp_proof_label_missing() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes_with_vdp_proof_label(&protected, 0, &[]);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected missing proof");

    assert!(matches!(err, ReceiptVerifyError::MissingProof));
}

#[test]
fn verify_mst_receipt_errors_when_network_fetch_enabled_but_issuer_url_invalid() {
    let statement = encode_statement_bytes(false);
    // Invalid URL that fails Url::parse quickly (no network).
    let protected = encode_protected_header_bytes("https://[::1", "missing_kid", -35, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: None,
        allow_network_fetch: true,
        jwks_api_version: None,
    })
    .expect_err("expected jwks fetch failure");

    assert!(matches!(err, ReceiptVerifyError::JwksFetch(_)));
}

#[test]
fn verify_mst_receipt_errors_when_network_fetch_returns_ok_but_not_200() {
    let (issuer, handle) = spawn_one_shot_http_server(204, "");

    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes(issuer.as_str(), "missing_kid", -35, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: None,
        allow_network_fetch: true,
        jwks_api_version: None,
    })
    .expect_err("expected jwks fetch failure");

    handle.join().expect("server thread join");
    assert!(matches!(err, ReceiptVerifyError::JwksFetch(msg) if msg.contains("http_status_204")));
}

#[test]
fn verify_mst_receipt_errors_when_network_fetch_returns_error_status_includes_body() {
    let (issuer, handle) = spawn_one_shot_http_server(500, "nope");

    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes(issuer.as_str(), "missing_kid", -35, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: None,
        allow_network_fetch: true,
        jwks_api_version: None,
    })
    .expect_err("expected jwks fetch failure");

    handle.join().expect("server thread join");
    assert!(matches!(err, ReceiptVerifyError::JwksFetch(msg) if msg.contains("http_status_500")));
}

#[test]
fn verify_mst_receipt_errors_when_jwk_kty_is_not_ec() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes("issuer", "kid1", -35, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let jwks = r#"{"keys":[{"kty":"RSA","crv":"P-384","kid":"kid1"}]}"#;

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(jwks),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected unsupported jwk");

    assert!(matches!(err, ReceiptVerifyError::JwkUnsupported(msg) if msg.contains("kty=")));
}

#[test]
fn verify_mst_receipt_errors_when_jwk_missing_crv() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes("issuer", "kid2", -35, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let jwks = r#"{"keys":[{"kty":"EC","kid":"kid2"}]}"#;

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(jwks),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected missing crv");

    assert!(matches!(err, ReceiptVerifyError::JwkUnsupported(msg) if msg == "missing_crv"));
}

#[test]
fn verify_mst_receipt_errors_when_alg_curve_mismatch() {
    let statement = encode_statement_bytes(false);
    // ES384 alg but P-256 crv.
    let protected = encode_protected_header_bytes("issuer", "kid3", -35, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let jwks = minimal_jwks_json_for_kid("kid3", "P-256");

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(jwks.as_str()),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected alg/crv mismatch");

    assert!(matches!(err, ReceiptVerifyError::JwkUnsupported(msg) if msg.contains("alg_curve_mismatch")));
}

#[test]
fn verify_mst_receipt_errors_when_jwk_missing_x_or_y() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes("issuer", "kid4", -7, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let jwks_missing_x = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"kid4","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}"#;
    let err_x = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(jwks_missing_x),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected missing x");
    assert!(matches!(err_x, ReceiptVerifyError::JwkUnsupported(msg) if msg == "missing_x"));

    let jwks_missing_y = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"kid4","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}"#;
    let err_y = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(jwks_missing_y),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected missing y");
    assert!(matches!(err_y, ReceiptVerifyError::JwkUnsupported(msg) if msg == "missing_y"));
}

#[test]
fn verify_mst_receipt_errors_when_jwk_x_decode_fails() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes("issuer", "kid5", -7, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let jwks = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"kid5\",\"x\":\"###\",\"y\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}]}";

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(jwks),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected x decode failure");

    assert!(matches!(err, ReceiptVerifyError::JwkUnsupported(msg) if msg.contains("x_decode_failed")));
}

#[test]
fn verify_mst_receipt_errors_when_jwk_xy_have_wrong_length() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes("issuer", "kid6", -7, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    // Valid base64url but decodes to 1 byte.
    let jwks = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"kid6","x":"AA","y":"AA"}]}"#;

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(jwks),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected xy length mismatch");

    assert!(matches!(err, ReceiptVerifyError::JwkUnsupported(msg) if msg.contains("unexpected_xy_len")));
}

#[test]
fn verify_mst_receipt_errors_on_malformed_leaf_and_path() {
    let statement = encode_statement_bytes(false);
    let expected = sha256(statement.as_slice());

    // Leaf array missing data_hash (only 2 items).
    let mut buf = vec![0u8; 256];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.map(2).unwrap();

    (1i64).encode(&mut enc).unwrap();
    enc.array(2).unwrap();
    [0u8; 32].as_slice().encode(&mut enc).unwrap();
    "evidence".encode(&mut enc).unwrap();

    (2i64).encode(&mut enc).unwrap();
    // Path contains a malformed pair (missing hash)
    enc.array(1).unwrap();
    enc.array(1).unwrap();
    true.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    let proof_blob = buf;

    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(&protected, Some(&[proof_blob]));

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected receipt decode error");

    match err {
        ReceiptVerifyError::ReceiptDecode(msg) => {
            assert!(msg.contains("leaf_missing_data_hash") || msg.contains("path_missing_hash"));
        }
        other => panic!("expected ReceiptDecode error, got {other:?}"),
    }

    // Ensure our helper isn't optimized away.
    assert_eq!(expected.len(), 32);
}

#[test]
fn verify_mst_receipt_errors_when_leaf_missing_data_hash_but_path_valid() {
    let statement = encode_statement_bytes(false);

    // Leaf array missing data_hash (only 2 items), but path is valid and empty.
    let mut buf = vec![0u8; 256];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.map(2).unwrap();

    (1i64).encode(&mut enc).unwrap();
    enc.array(2).unwrap();
    [0u8; 32].as_slice().encode(&mut enc).unwrap();
    "evidence".encode(&mut enc).unwrap();

    (2i64).encode(&mut enc).unwrap();
    enc.array(0).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    let proof_blob = buf;

    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(&protected, Some(&[proof_blob]));

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected receipt decode error");

    assert!(matches!(err, ReceiptVerifyError::ReceiptDecode(msg) if msg.contains("leaf_missing_data_hash")));
}

#[test]
fn verify_mst_receipt_errors_when_path_item_missing_dir() {
    let statement = encode_statement_bytes(false);

    // Leaf is valid, but the path contains a malformed pair (missing direction bool).
    let mut buf = vec![0u8; 256];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.map(2).unwrap();

    (1i64).encode(&mut enc).unwrap();
    enc.array(3).unwrap();
    [0u8; 32].as_slice().encode(&mut enc).unwrap();
    "evidence".encode(&mut enc).unwrap();
    [0u8; 32].as_slice().encode(&mut enc).unwrap();

    (2i64).encode(&mut enc).unwrap();
    enc.array(1).unwrap();
    // Encode an empty pair array so `visit::<bool>()` returns None.
    enc.array(0).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    let proof_blob = buf;

    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(&protected, Some(&[proof_blob]));

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected receipt decode error");

    assert!(matches!(err, ReceiptVerifyError::ReceiptDecode(msg) if msg.contains("path_missing_dir")));
}

#[test]
fn verify_mst_receipt_errors_when_leaf_missing_internal_txn_hash() {
    let statement = encode_statement_bytes(false);

    // Build a proof blob with an empty leaf array but a valid (empty) path.
    let proof_blob = encode_proof_blob_bytes_with_empty_leaf_and_path();

    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(protected.as_slice(), Some(&[proof_blob]));

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected leaf decode error");

    assert!(err.to_string().contains("leaf_missing_internal_txn_hash"));
}

#[test]
fn verify_mst_receipt_errors_when_leaf_missing_internal_evidence() {
    let statement = encode_statement_bytes(false);

    let internal_txn_hash = [0u8; 32];

    // Leaf array: [ internal_txn_hash ] (missing evidence + data_hash)
    let proof_blob = encode_proof_blob_bytes_with_leaf_missing_internal_evidence(internal_txn_hash.as_slice());

    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(protected.as_slice(), Some(&[proof_blob]));

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected leaf decode error");

    assert!(err.to_string().contains("leaf_missing_internal_evidence"));
}

#[test]
fn verify_mst_receipt_errors_when_path_item_missing_hash() {
    let statement = encode_statement_bytes(false);

    let internal_txn_hash = [0u8; 32];
    let data_hash = [0u8; 32];

    // Leaf is structurally valid; path contains a pair with only the direction.
    let proof_blob = encode_proof_blob_bytes_with_path_missing_hash(
        internal_txn_hash.as_slice(),
        "evidence",
        data_hash.as_slice(),
    );

    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(protected.as_slice(), Some(&[proof_blob]));

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected path decode error");

    assert!(err.to_string().contains("path_missing_hash"));
}

#[test]
fn verify_mst_receipt_errors_when_kid_not_found_in_offline_jwks_and_network_fetch_disabled() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes("issuer", "missing_kid", -35, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected offline jwks to be insufficient");

    assert!(matches!(
        err,
        ReceiptVerifyError::JwksParse(msg) if msg == "MissingOfflineJwks"
    ));
}

#[test]
fn verify_mst_receipt_errors_when_offline_jwks_is_malformed() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some("not-json"),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected offline jwks parse failure");

    assert!(matches!(err, ReceiptVerifyError::JwksParse(_)));
}

#[test]
fn verify_mst_receipt_accepts_extra_negative_int_keys_in_protected_header() {
    let statement = encode_statement_bytes(false);
    let protected =
        encode_protected_header_bytes_with_extra_negative_key("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected missing VDP");

    assert!(matches!(err, ReceiptVerifyError::MissingVdp));
}

#[test]
fn verify_mst_receipt_errors_when_vdp_missing() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(&protected, None);

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected missing VDP");

    assert!(matches!(err, ReceiptVerifyError::MissingVdp));
}

#[test]
fn verify_mst_receipt_errors_when_proof_array_empty() {
    let statement = encode_statement_bytes(false);
    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(&protected, Some(&[]));

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected missing proof");

    assert!(matches!(err, ReceiptVerifyError::MissingProof));
}

#[test]
fn verify_mst_receipt_reaches_signature_verification_and_returns_signature_invalid() {
    let statement = encode_statement_bytes(true);
    let expected = sha256(statement.as_slice());

    let proof = encode_proof_blob_bytes(&[0u8; 32], "evidence", expected.as_slice());

    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(&protected, Some(&[proof]));

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected signature to fail");

    assert!(matches!(err, ReceiptVerifyError::SignatureInvalid));
}

#[test]
fn verify_mst_receipt_errors_when_internal_txn_hash_is_wrong_length() {
    let statement = encode_statement_bytes(false);
    let expected = sha256(statement.as_slice());

    let bad_leaf = vec![0u8; 31];
    let proof = encode_proof_blob_bytes(bad_leaf.as_slice(), "evidence", expected.as_slice());

    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(&protected, Some(&[proof]));

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected accumulator to reject internal_txn_hash length");

    match err {
        ReceiptVerifyError::ReceiptDecode(msg) => {
            assert!(msg.contains("unexpected_internal_txn_hash_len"));
        }
        other => panic!("expected ReceiptDecode error, got {other:?}"),
    }
}

#[test]
fn verify_mst_receipt_errors_when_path_hash_is_wrong_length() {
    let statement = encode_statement_bytes(true);
    let expected = sha256(statement.as_slice());

    // Include a path hash that is not 32 bytes to exercise the fixed-size conversion.
    let short_sibling = vec![0u8; 31];
    let proof = encode_proof_blob_bytes_with_path(
        &[0u8; 32],
        "evidence",
        expected.as_slice(),
        &[(true, short_sibling.as_slice())],
    );

    let protected = encode_protected_header_bytes("issuer", TEST_KID, -35, 2);
    let receipt = encode_receipt_bytes(&protected, Some(&[proof]));

    let err = verify_mst_receipt(ReceiptVerifyInput {
        statement_bytes_with_receipts: statement.as_slice(),
        receipt_bytes: receipt.as_slice(),
        offline_jwks_json: Some(TEST_JWKS_JSON),
        allow_network_fetch: false,
        jwks_api_version: None,
    })
    .expect_err("expected path hash length to be rejected");

    match err {
        ReceiptVerifyError::ReceiptDecode(msg) => {
            assert!(msg.contains("unexpected_path_hash_len"));
        }
        other => panic!("expected ReceiptDecode error, got {other:?}"),
    }
}
