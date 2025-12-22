// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Unit tests for the Rust MST verifier.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cosesign1::common::{encode_signature1_sig_structure, parse_cose_sign1};
use cosesign1_mst::{
    verify_transparent_statement, verify_transparent_statement_online, verify_transparent_statement_receipt,
    AuthorizedReceiptBehavior, JwkEcPublicKey, JwksDocument, JwksFetcher, OfflineEcKeyStore, ResolvedKey,
    UnauthorizedReceiptBehavior, VerificationOptions,
};
use cosesign1::validation::CoseAlgorithm;
use minicbor::Encoder;
use sha2::{Digest, Sha256};
use p256::ecdsa::signature::Signer;
use p256::pkcs8::EncodePublicKey;

fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().to_vec()
}

fn build_jwk_from_p256(kid: &str, vk: &p256::ecdsa::VerifyingKey) -> JwkEcPublicKey {
    let point = vk.to_encoded_point(false);
    let x = point.x().expect("x");
    let y = point.y().expect("y");

    JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: URL_SAFE_NO_PAD.encode(x),
        y: URL_SAFE_NO_PAD.encode(y),
        kid: kid.to_string(),
    }
}

fn encode_receipt(protected_map_cbor: &[u8], inclusion_map_cbor: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    enc.array(4).unwrap();
    enc.bytes(protected_map_cbor).unwrap();
    enc.map(1).unwrap();
    enc.i64(396).unwrap();
    // vdp is a CBOR map value: { -1: [ bstr(inclusion_map) ] }
    enc.map(1).unwrap();
    enc.i64(-1).unwrap();
    enc.array(1).unwrap();
    enc.bytes(inclusion_map_cbor).unwrap();
    enc.null().unwrap();
    enc.bytes(signature).unwrap();
    out
}

fn build_receipt_es256_with_kid_bytes(
    kid_bytes: &[u8],
    issuer: &str,
    claims: &[u8],
    sk: &p256::ecdsa::SigningKey,
) -> Vec<u8> {
    // Leaf values.
    let tx_hash = sha256(b"tx");
    let evidence = "evidence";
    let data_hash = sha256(claims);

    let mut inclusion_map = Vec::new();
    {
        let mut enc = Encoder::new(&mut inclusion_map);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str(evidence).unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }

    // protected header map.
    let mut protected = Vec::new();
    {
        let mut enc = Encoder::new(&mut protected);
        enc.map(4).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap(); // ES256
        enc.i64(4).unwrap();
        enc.bytes(kid_bytes).unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap(); // vds = CCF
        enc.i64(15).unwrap();
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.str(issuer).unwrap();
    }

    let evidence_hash = sha256(evidence.as_bytes());
    let mut leaf_hash_input = Vec::new();
    leaf_hash_input.extend_from_slice(&tx_hash);
    leaf_hash_input.extend_from_slice(&evidence_hash);
    leaf_hash_input.extend_from_slice(&data_hash);
    let accumulator = sha256(&leaf_hash_input);

    let placeholder_sig = vec![0u8; 64];
    let receipt0 = encode_receipt(&protected, &inclusion_map, &placeholder_sig);
    let parsed0 = parse_cose_sign1(&receipt0).expect("parse receipt");
    let sig_structure = encode_signature1_sig_structure(&parsed0, Some(&accumulator)).expect("sig_struct");
    let sig: p256::ecdsa::Signature = sk.sign(&sig_structure);
    let sig_bytes = sig.to_bytes().to_vec();

    encode_receipt(&protected, &inclusion_map, &sig_bytes)
}

fn encode_inclusion_map_with_path(claims: &[u8], path: &[(bool, &[u8])]) -> Vec<u8> {
    let tx_hash = sha256(b"tx");
    let evidence = "evidence";
    let data_hash = sha256(claims);

    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    enc.map(2).unwrap();
    enc.i64(1).unwrap();
    enc.array(3).unwrap();
    enc.bytes(&tx_hash).unwrap();
    enc.str(evidence).unwrap();
    enc.bytes(&data_hash).unwrap();
    enc.i64(2).unwrap();
    enc.array(path.len() as u64).unwrap();
    for (left, h) in path {
        enc.array(2).unwrap();
        enc.bool(*left).unwrap();
        enc.bytes(*h).unwrap();
    }
    out
}

fn build_receipt_es256(
    kid: &str,
    issuer: &str,
    claims: &[u8],
    sk: &p256::ecdsa::SigningKey,
) -> Vec<u8> {
    // Leaf values.
    let tx_hash = sha256(b"tx");
    let evidence = "evidence";
    let data_hash = sha256(claims);

    // inclusion proof map: { 1: leaf, 2: path }
    let mut inclusion_map = Vec::new();
    {
        let mut enc = Encoder::new(&mut inclusion_map);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str(evidence).unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }

    // protected header map.
    let mut protected = Vec::new();
    {
        let mut enc = Encoder::new(&mut protected);
        enc.map(4).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap(); // ES256
        enc.i64(4).unwrap();
        enc.bytes(kid.as_bytes()).unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap(); // vds = CCF
        enc.i64(15).unwrap();
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.str(issuer).unwrap();
    }

    // Compute accumulator for empty path.
    let evidence_hash = sha256(evidence.as_bytes());
    let mut leaf_hash_input = Vec::new();
    leaf_hash_input.extend_from_slice(&tx_hash);
    leaf_hash_input.extend_from_slice(&evidence_hash);
    leaf_hash_input.extend_from_slice(&data_hash);
    let accumulator = sha256(&leaf_hash_input);

    // Build receipt with placeholder signature so we can compute Sig_structure.
    let placeholder_sig = vec![0u8; 64];
    let receipt0 = encode_receipt(&protected, &inclusion_map, &placeholder_sig);
    let parsed0 = parse_cose_sign1(&receipt0).expect("parse receipt");
    let sig_structure = encode_signature1_sig_structure(&parsed0, Some(&accumulator)).expect("sig_struct");
    let sig: p256::ecdsa::Signature = sk.sign(&sig_structure);
    let sig_bytes = sig.to_bytes().to_vec();

    // Re-encode with real signature.
    encode_receipt(&protected, &inclusion_map, &sig_bytes)
}

fn encode_receipt_headers(kid: &str, issuer: Option<&str>, vds: Option<i64>, cwt_as_bytes: bool) -> Vec<u8> {
    let mut protected = Vec::new();
    {
        let mut enc = Encoder::new(&mut protected);
        let mut entries = 2; // alg + kid
        if vds.is_some() {
            entries += 1;
        }
        if issuer.is_some() {
            entries += 1;
        }

        enc.map(entries).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap(); // ES256

        enc.i64(4).unwrap();
        enc.bytes(kid.as_bytes()).unwrap();

        if let Some(v) = vds {
            enc.i64(395).unwrap();
            enc.i64(v).unwrap();
        }

        if let Some(iss) = issuer {
            enc.i64(15).unwrap();
            if cwt_as_bytes {
                let mut cwt = Vec::new();
                {
                    let mut enc2 = Encoder::new(&mut cwt);
                    enc2.map(1).unwrap();
                    enc2.i64(1).unwrap();
                    enc2.str(iss).unwrap();
                }
                enc.bytes(&cwt).unwrap();
            } else {
                enc.map(1).unwrap();
                enc.i64(1).unwrap();
                enc.str(iss).unwrap();
            }
        }
    }
    protected
}

fn encode_receipt_with_vdp_value(protected_map_cbor: &[u8], vdp_value: Option<&[u8]>, signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    enc.array(4).unwrap();
    enc.bytes(protected_map_cbor).unwrap();

    match vdp_value {
        None => {
            enc.map(0).unwrap();
        }
        Some(vdp) => {
            enc.map(1).unwrap();
            enc.i64(396).unwrap();
            enc.bytes(vdp).unwrap();
        }
    }

    enc.null().unwrap();
    enc.bytes(signature).unwrap();
    out
}

fn encode_receipt_with_vdp_header_int(protected_map_cbor: &[u8], vdp_value: i64, signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    enc.array(4).unwrap();
    enc.bytes(protected_map_cbor).unwrap();
    enc.map(1).unwrap();
    enc.i64(396).unwrap();
    enc.i64(vdp_value).unwrap();
    enc.null().unwrap();
    enc.bytes(signature).unwrap();
    out
}

fn encode_statement_with_receipts_value(payload: Option<&[u8]>, signature: &[u8], receipts_header_value: &[u8]) -> Vec<u8> {
    let protected_empty: Vec<u8> = Vec::new();
    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    enc.array(4).unwrap();
    enc.bytes(&protected_empty).unwrap();

    enc.map(1).unwrap();
    enc.i64(394).unwrap();
    // receipts_header_value is already CBOR-encoded as either an array or a bstr.
    // We decode it by writing raw bytes as a bstr if it is a bstr, otherwise we embed its decoded value.
    // For simplicity, we treat it as raw CBOR and embed by decoding through parse_cose_sign1 later.
    // Here we just embed it as bytes-wrapped CBOR.
    enc.bytes(receipts_header_value).unwrap();

    match payload {
        Some(p) => {
            enc.bytes(p).unwrap();
        }
        None => {
            enc.null().unwrap();
        }
    };
    enc.bytes(signature).unwrap();
    out
}

fn encode_statement_without_unprotected_payload(payload: Option<&[u8]>, signature: &[u8]) -> Vec<u8> {
    let protected_empty: Vec<u8> = Vec::new();
    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    enc.array(4).unwrap();
    enc.bytes(&protected_empty).unwrap();
    enc.map(0).unwrap();
    match payload {
        Some(p) => {
            enc.bytes(p).unwrap();
        }
        None => {
            enc.null().unwrap();
        }
    };
    enc.bytes(signature).unwrap();
    out
}

fn encode_statement_with_receipts(payload: &[u8], signature: &[u8], receipts: &[Vec<u8>]) -> Vec<u8> {
    let protected_empty: Vec<u8> = Vec::new();
    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    enc.array(4).unwrap();
    enc.bytes(&protected_empty).unwrap();

    enc.map(1).unwrap();
    enc.i64(394).unwrap();
    enc.array(receipts.len() as u64).unwrap();
    for r in receipts {
        enc.bytes(r).unwrap();
    }

    enc.bytes(payload).unwrap();
    enc.bytes(signature).unwrap();
    out
}

fn encode_statement_without_unprotected(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let protected_empty: Vec<u8> = Vec::new();
    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    enc.array(4).unwrap();
    enc.bytes(&protected_empty).unwrap();
    enc.map(0).unwrap();
    enc.bytes(payload).unwrap();
    enc.bytes(signature).unwrap();
    out
}

#[test]
fn receipt_happy_path_verifies() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[1u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";

    let jwk = build_jwk_from_p256(kid, vk);
    let receipt = build_receipt_es256(kid, issuer, claims, &sk);

    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, claims);
    assert!(res.is_valid, "{:?}", res.failures);
}

#[test]
fn receipt_claim_digest_mismatch_fails() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[2u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";
    let receipt = build_receipt_es256(kid, issuer, claims, &sk);

    let jwk = build_jwk_from_p256(kid, vk);
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"different");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_CLAIM_DIGEST_MISMATCH"));
}

#[test]
fn receipt_kid_mismatch_fails_before_signature() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[3u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";
    let receipt = build_receipt_es256(kid, issuer, claims, &sk);

    let jwk = build_jwk_from_p256("kid-other", vk);
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, claims);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_KID_MISMATCH"));
}

#[test]
fn transparent_statement_happy_path_verifies() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[4u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);
    let receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt.clone()]);

    let mut key_store = OfflineEcKeyStore::default();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();
    key_store.insert(
        issuer,
        kid,
        ResolvedKey {
            public_key_bytes: der.as_bytes().to_vec(),
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![issuer.to_string()];

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(res.is_valid, "{:?}", res.failures);
    assert_eq!(res.metadata.get("receipts").map(|s| s.as_str()), Some("1"));
}

#[test]
fn transparent_statement_unauthorized_receipts_are_ignored_when_configured() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[44u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let issuer_authorized = "issuer.example";
    let issuer_unauthorized = "other.example";
    let kid_authorized = "kid-1";
    let kid_unauthorized = "kid-2";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);

    let receipt_authorized = build_receipt_es256(kid_authorized, issuer_authorized, &statement_without_unprotected, &sk);
    let receipt_unauthorized =
        build_receipt_es256(kid_unauthorized, issuer_unauthorized, &statement_without_unprotected, &sk);

    let statement = encode_statement_with_receipts(
        statement_payload,
        statement_sig,
        &[receipt_authorized.clone(), receipt_unauthorized.clone()],
    );

    let mut key_store = OfflineEcKeyStore::default();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();
    key_store.insert(
        issuer_authorized,
        kid_authorized,
        ResolvedKey {
            public_key_bytes: der.as_bytes().to_vec(),
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![issuer_authorized.to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(res.is_valid, "{:?}", res.failures);
    assert_eq!(res.metadata.get("receipts").map(|s| s.as_str()), Some("2"));
}

#[test]
fn transparent_statement_cwt_bytes_decode_error_yields_unknown_issuer() {
    // CWT is present as bytes, but the bytes are not valid CBOR.
    let mut protected = Vec::new();
    {
        let mut enc = Encoder::new(&mut protected);
        enc.map(4).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap(); // ES256
        enc.i64(4).unwrap();
        enc.bytes(b"kid-1").unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap(); // vds = CCF
        enc.i64(15).unwrap();
        enc.bytes(&[0xff]).unwrap();
    }

    let receipt = encode_receipt_with_vdp_value(&protected, None, b"sig");
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt]);

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec!["issuer.example".to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::FailIfPresent;

    let key_store = OfflineEcKeyStore::default();
    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_UNAUTHORIZED_RECEIPT"));
}

#[test]
fn transparent_statement_receipts_wrapped_array_is_accepted() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[5u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);
    let receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);

    // Encode receipts header value as a bstr containing a CBOR array of bstr receipts.
    let mut receipts_array = Vec::new();
    {
        let mut enc = Encoder::new(&mut receipts_array);
        enc.array(1).unwrap();
        enc.bytes(&receipt).unwrap();
    }

    let statement = encode_statement_with_receipts_value(Some(statement_payload), statement_sig, &receipts_array);

    let mut key_store = OfflineEcKeyStore::default();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();
    key_store.insert(
        issuer,
        kid,
        ResolvedKey {
            public_key_bytes: der.as_bytes().to_vec(),
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![issuer.to_string()];

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(res.is_valid, "{:?}", res.failures);
}

#[test]
fn transparent_statement_with_null_payload_verifies() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[6u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";

    let statement_sig = b"sig";
    let statement_without_unprotected = encode_statement_without_unprotected_payload(None, statement_sig);
    let receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);

    // Statement payload is null, and it embeds receipts normally.
    let statement = {
        let protected_empty: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        let mut enc = Encoder::new(&mut out);
        enc.array(4).unwrap();
        enc.bytes(&protected_empty).unwrap();
        enc.map(1).unwrap();
        enc.i64(394).unwrap();
        enc.array(1).unwrap();
        enc.bytes(&receipt).unwrap();
        enc.null().unwrap();
        enc.bytes(statement_sig).unwrap();
        out
    };

    let mut key_store = OfflineEcKeyStore::default();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();
    key_store.insert(
        issuer,
        kid,
        ResolvedKey {
            public_key_bytes: der.as_bytes().to_vec(),
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![issuer.to_string()];

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(res.is_valid, "{:?}", res.failures);
}

#[test]
fn transparent_statement_rejects_receipts_with_wrong_element_type() {
    // Statement unprotected header 394 is an array, but element is not a bstr.
    let statement = {
        let protected_empty: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        let mut enc = Encoder::new(&mut out);
        enc.array(4).unwrap();
        enc.bytes(&protected_empty).unwrap();
        enc.map(1).unwrap();
        enc.i64(394).unwrap();
        enc.array(1).unwrap();
        enc.i64(123).unwrap();
        enc.bytes(b"payload").unwrap();
        enc.bytes(b"sig").unwrap();
        out
    };

    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &VerificationOptions::default());
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_RECEIPT"));
}

#[test]
fn transparent_statement_missing_receipts_header_reports_no_receipt() {
    let statement = encode_statement_without_unprotected(b"payload", b"sig");
    let res = verify_transparent_statement(
        "mst",
        &statement,
        &OfflineEcKeyStore::default(),
        &VerificationOptions::default(),
    );
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_RECEIPT"));
}

#[test]
fn transparent_statement_receipts_wrapped_array_rejects_non_bstr_element() {
    // receipts header is a bstr wrapping a CBOR array, but the array element is not a bstr.
    let mut receipts_array = Vec::new();
    {
        let mut enc = Encoder::new(&mut receipts_array);
        enc.array(1).unwrap();
        enc.i64(123).unwrap();
    }
    let statement = encode_statement_with_receipts_value(Some(b"payload"), b"sig", &receipts_array);
    let res = verify_transparent_statement(
        "mst",
        &statement,
        &OfflineEcKeyStore::default(),
        &VerificationOptions::default(),
    );
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_RECEIPT"));
}

#[test]
fn transparent_statement_receipts_wrapped_value_not_array_reports_no_receipt() {
    // receipts header is a bstr wrapping a CBOR value that is not an array.
    let mut not_array = Vec::new();
    {
        let mut enc = Encoder::new(&mut not_array);
        enc.map(0).unwrap();
    }
    let statement = encode_statement_with_receipts_value(Some(b"payload"), b"sig", &not_array);
    let res = verify_transparent_statement(
        "mst",
        &statement,
        &OfflineEcKeyStore::default(),
        &VerificationOptions::default(),
    );
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_RECEIPT"));
}

#[test]
fn transparent_statement_no_authorized_and_ignoreall_reports_no_verifiable_receipts() {
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[b"not-cbor".to_vec()]);
    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;
    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_VERIFIABLE_RECEIPTS"));
}

#[test]
fn transparent_statement_reports_kid_missing_in_receipt() {
    let issuer = "issuer.example";

    // Protected headers: alg, vds, issuer; no KID.
    let mut protected = Vec::new();
    {
        let mut enc = Encoder::new(&mut protected);
        enc.map(3).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap();
        enc.i64(15).unwrap();
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.str(issuer).unwrap();
    }
    let inclusion_map = encode_inclusion_map_with_path(b"claims", &[]);
    let receipt = encode_receipt(&protected, &inclusion_map, b"sig");
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt]);

    let mut opts = VerificationOptions::default();
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;

    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MST_KID_MISSING")));
}

#[test]
fn transparent_statement_reads_issuer_from_cwt_bytes_and_reports_key_not_found() {
    let kid = "kid-1";
    let issuer = "issuer.example";
    let protected = encode_receipt_headers(kid, Some(issuer), Some(2), true);
    let receipt = encode_receipt_with_vdp_value(&protected, None, b"sig");
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt]);

    let mut opts = VerificationOptions::default();
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;

    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MST_KEY_NOT_FOUND")));
}

#[test]
fn transparent_statement_invalid_cbor_reports_parse_error() {
    let res = verify_transparent_statement(
        "mst",
        b"not-cbor",
        &OfflineEcKeyStore::default(),
        &VerificationOptions::default(),
    );
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("CBOR_PARSE_ERROR"));
}

#[test]
fn transparent_statement_empty_receipts_array_reports_no_receipt() {
    let statement = {
        let protected_empty: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        let mut enc = Encoder::new(&mut out);
        enc.array(4).unwrap();
        enc.bytes(&protected_empty).unwrap();
        enc.map(1).unwrap();
        enc.i64(394).unwrap();
        enc.array(0).unwrap();
        enc.bytes(b"payload").unwrap();
        enc.bytes(b"sig").unwrap();
        out
    };

    let res = verify_transparent_statement(
        "mst",
        &statement,
        &OfflineEcKeyStore::default(),
        &VerificationOptions::default(),
    );
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_RECEIPT"));
}

#[test]
fn transparent_statement_reads_issuer_from_cwt_map_and_wrong_type_yields_unknown_issuer() {
    let kid = "kid-1";
    let issuer = "issuer.example";

    // issuer as a CWT map (not bytes)
    let protected_map = encode_receipt_headers(kid, Some(issuer), Some(2), false);
    let receipt1 = encode_receipt_with_vdp_value(&protected_map, None, b"sig");

    // issuer header present but wrong type => unknown issuer
    let protected_wrong = {
        let mut out = Vec::new();
        let mut enc = Encoder::new(&mut out);
        enc.map(4).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(4).unwrap();
        enc.bytes(kid.as_bytes()).unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap();
        enc.i64(15).unwrap();
        enc.i64(123).unwrap();
        out
    };
    let receipt2 = encode_receipt_with_vdp_value(&protected_wrong, None, b"sig");

    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt1, receipt2]);

    let mut opts = VerificationOptions::default();
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;
    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MST_UNKNOWN_ISSUER")));
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MST_KEY_NOT_FOUND")));
}

#[test]
fn transparent_statement_cwt_iss_non_text_yields_unknown_issuer() {
    let kid = "kid-1";

    // Protected headers: alg, kid, vds, and CWT map where iss (label 1) is NOT a text string.
    let protected = {
        let mut out = Vec::new();
        let mut enc = Encoder::new(&mut out);
        enc.map(4).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(4).unwrap();
        enc.bytes(kid.as_bytes()).unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap();
        enc.i64(15).unwrap();
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.i64(123).unwrap();
        out
    };
    let receipt = encode_receipt_with_vdp_value(&protected, None, b"sig");
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt]);

    let mut opts = VerificationOptions::default();
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;
    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MST_UNKNOWN_ISSUER")));
}

#[test]
fn transparent_statement_unauthorized_receipt_verification_failures_are_bucketed() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[30u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();

    let kid = "kid-1";
    let issuer = "issuer.example";
    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);

    // Make the receipt structurally valid but signature-invalid.
    let mut receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);
    *receipt.last_mut().unwrap() ^= 0x01;
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt]);

    let mut key_store = OfflineEcKeyStore::default();
    key_store.insert(
        issuer,
        kid,
        ResolvedKey {
            public_key_bytes: der.as_bytes().to_vec(),
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    // Do NOT add issuer to authorized_domains; treat it as unauthorized.
    opts.authorized_domains = vec!["different.example".to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;
    opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::VerifyAnyMatching;

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MST_RECEIPT_SIGNATURE_INVALID")));
}

#[test]
fn receipt_verification_accepts_inclusion_proofs_array_wrapped_in_bstr() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[22u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), true);

    let inclusion_map = encode_inclusion_map_with_path(b"claims", &[]);
    let mut wrapped = Vec::new();
    {
        let mut enc = Encoder::new(&mut wrapped);
        enc.array(1).unwrap();
        enc.bytes(&inclusion_map).unwrap();
    }

    let mut vdp = Vec::new();
    {
        let mut enc = Encoder::new(&mut vdp);
        enc.map(1).unwrap();
        enc.i64(-1).unwrap();
        enc.bytes(&wrapped).unwrap();
    }

    let receipt = encode_receipt_with_vdp_value(&protected, Some(&vdp), &[0u8; 64]);
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_RECEIPT_SIGNATURE_INVALID"));
}

#[test]
fn receipt_verification_reports_kid_missing() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[23u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let jwk = build_jwk_from_p256("kid-ignored", vk);

    let mut protected = Vec::new();
    {
        let mut enc = Encoder::new(&mut protected);
        enc.map(3).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap();
        enc.i64(15).unwrap();
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.str("issuer.example").unwrap();
    }
    let inclusion_map = encode_inclusion_map_with_path(b"claims", &[]);
    let receipt = encode_receipt(&protected, &inclusion_map, b"sig");

    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_KID_MISSING"));
}

#[test]
fn transparent_statement_verify_all_matching_reports_required_domain_failed() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[24u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();

    let kid = "kid-1";
    let issuer = "issuer.example";
    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);

    let mut receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);
    *receipt.last_mut().unwrap() ^= 0x01;
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt]);

    let mut key_store = OfflineEcKeyStore::default();
    key_store.insert(
        issuer,
        kid,
        ResolvedKey {
            public_key_bytes: der.as_bytes().to_vec(),
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![issuer.to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;
    opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::VerifyAllMatching;

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MST_REQUIRED_DOMAIN_FAILED")));
}

#[test]
fn transparent_statement_fail_if_present_rejects_unauthorized_receipt() {
    let kid = "kid-1";
    let receipt = encode_receipt_with_vdp_value(
        &encode_receipt_headers(kid, Some("issuer.example"), Some(2), false),
        None,
        b"sig",
    );
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt]);

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec!["good.example".to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::FailIfPresent;

    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_UNAUTHORIZED_RECEIPT"));
}

#[test]
fn transparent_statement_unknown_issuer_verifyall_reports_unknown_issuer() {
    let kid = "kid-1";
    // Receipt parses but has no issuer.
    let protected = encode_receipt_headers(kid, None, Some(2), false);
    let receipt = encode_receipt_with_vdp_value(&protected, None, b"sig");
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt]);

    let mut opts = VerificationOptions::default();
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;

    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_UNKNOWN_ISSUER"));
}

#[test]
fn receipt_vdp_bytes_decode_errors_report_parse_error() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);

    // VDP is bytes containing an indefinite-length map (unsupported).
    let vdp = vec![0xbf, 0xff];
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), true);
    let receipt = encode_receipt_with_vdp_value(&protected, Some(&vdp), b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_VDP_PARSE_ERROR"));

    // VDP is bytes containing trailing bytes.
    let mut vdp2 = Vec::new();
    {
        let mut enc = Encoder::new(&mut vdp2);
        enc.map(1).unwrap();
        enc.str("k").unwrap();
        enc.null().unwrap();
    }
    vdp2.push(0x00);
    let receipt2 = encode_receipt_with_vdp_value(&protected, Some(&vdp2), b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_VDP_PARSE_ERROR"));
}

#[test]
fn receipt_decode_unsupported_cbor_type_reports_parse_error() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[11u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), true);

    // VDP bytes containing a map with float value (unsupported in our header decoder).
    let mut vdp = Vec::new();
    {
        let mut enc = Encoder::new(&mut vdp);
        enc.map(1).unwrap();
        enc.str("k").unwrap();
        enc.f64(1.0).unwrap();
    }
    let receipt = encode_receipt_with_vdp_value(&protected, Some(&vdp), b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_VDP_PARSE_ERROR"));

    // VDP bytes containing an indefinite-length array (unsupported).
    let vdp2 = vec![0x9f, 0xff];
    let receipt2 = encode_receipt_with_vdp_value(&protected, Some(&vdp2), b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_VDP_PARSE_ERROR"));
}

#[test]
fn receipt_signature_invalid_is_reported() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[12u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";

    let jwk = build_jwk_from_p256(kid, vk);
    let mut receipt = build_receipt_es256(kid, issuer, claims, &sk);
    // Corrupt signature.
    *receipt.last_mut().unwrap() ^= 0x01;
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, claims);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_RECEIPT_SIGNATURE_INVALID"));
}

#[test]
fn receipt_non_empty_path_exercises_left_and_right_accumulator_steps() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[13u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";

    let jwk = build_jwk_from_p256(kid, vk);

    let h1 = sha256(b"p1");
    let h2 = sha256(b"p2");
    let inclusion_map = encode_inclusion_map_with_path(claims, &[(true, &h1), (false, &h2)]);

    // Protected header map.
    let mut protected = Vec::new();
    {
        let mut enc = Encoder::new(&mut protected);
        enc.map(4).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap(); // ES256
        enc.i64(4).unwrap();
        enc.bytes(kid.as_bytes()).unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap();
        enc.i64(15).unwrap();
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.str(issuer).unwrap();
    }

    // Signature is intentionally invalid, but it must be the right size.
    let receipt = encode_receipt(&protected, &inclusion_map, &[0u8; 64]);
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, claims);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_RECEIPT_SIGNATURE_INVALID"));
}

#[test]
fn transparent_statement_supports_non_ascii_kid_via_hex_normalization() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[14u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let issuer = "issuer.example";
    let kid_bytes = [0u8, 1, 255];
    let kid_hex = "0001ff";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);
    let receipt = build_receipt_es256_with_kid_bytes(&kid_bytes, issuer, &statement_without_unprotected, &sk);
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt]);

    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();

    let mut key_store = OfflineEcKeyStore::default();
    key_store.insert(
        issuer,
        kid_hex,
        ResolvedKey {
            public_key_bytes: der.as_bytes().to_vec(),
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![issuer.to_string()];

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(res.is_valid, "{:?}", res.failures);
}

#[test]
fn transparent_statement_reports_receipt_parse_errors_when_verifyall() {
    // Receipt bytes are not CBOR.
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[b"not-cbor".to_vec()]);

    let mut opts = VerificationOptions::default();
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;

    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_RECEIPT_PARSE_ERROR"));
}

#[test]
fn transparent_statement_authorized_behavior_variants() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[15u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();

    let kid = "kid-1";
    let issuer1 = "issuer1.example";
    let issuer2 = "issuer2.example";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);

    let receipt1 = build_receipt_es256(kid, issuer1, &statement_without_unprotected, &sk);
    let receipt2 = build_receipt_es256(kid, issuer2, &statement_without_unprotected, &sk);

    // VerifyAnyMatching should succeed if at least one authorized receipt verifies,
    // even if another authorized receipt can't be verified.
    {
        let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt1.clone(), receipt2.clone()]);
        let mut key_store = OfflineEcKeyStore::default();
        key_store.insert(
            issuer1,
            kid,
            ResolvedKey {
                public_key_bytes: der.as_bytes().to_vec(),
                expected_alg: CoseAlgorithm::ES256,
            },
        );

        let mut opts = VerificationOptions::default();
        opts.authorized_domains = vec![issuer1.to_string(), issuer2.to_string()];
        opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::VerifyAnyMatching;
        opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;

        let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
        assert!(res.is_valid, "{:?}", res.failures);
    }

    // VerifyAllMatching: if no receipts exist for authorized domains, fail.
    {
        let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt2.clone()]);
        let mut opts = VerificationOptions::default();
        opts.authorized_domains = vec![issuer1.to_string()];
        opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::VerifyAllMatching;
        opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;
        let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
        assert!(!res.is_valid);
        assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_VALID_AUTHORIZED_RECEIPTS"));
    }

    // RequireAll: if a required domain is missing, fail.
    {
        let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt1.clone()]);
        let mut key_store = OfflineEcKeyStore::default();
        key_store.insert(
            issuer1,
            kid,
            ResolvedKey {
                public_key_bytes: der.as_bytes().to_vec(),
                expected_alg: CoseAlgorithm::ES256,
            },
        );

        let mut opts = VerificationOptions::default();
        opts.authorized_domains = vec![issuer1.to_string(), issuer2.to_string()];
        opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::RequireAll;
        opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;

        let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
        assert!(!res.is_valid);
        assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MST_REQUIRED_DOMAIN_MISSING")));
    }
}

#[test]
fn receipt_verification_handles_jwk_conversion_errors() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[16u8; 32].into()).expect("sk");
    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";
    let receipt = build_receipt_es256(kid, issuer, claims, &sk);

    // Wrong kty.
    let bad_kty = JwkEcPublicKey {
        kty: "RSA".to_string(),
        crv: "P-256".to_string(),
        x: "AA".to_string(),
        y: "AA".to_string(),
        kid: kid.to_string(),
    };
    let res = verify_transparent_statement_receipt("mst", &bad_kty, &receipt, claims);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));

    // Invalid base64 x.
    let mut bad_x = build_jwk_from_p256(kid, sk.verifying_key());
    bad_x.x = "%%%".to_string();
    let res2 = verify_transparent_statement_receipt("mst", &bad_x, &receipt, claims);
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));
}

#[test]
fn receipt_verification_handles_more_jwk_errors_and_curves() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[17u8; 32].into()).expect("sk");
    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";
    let receipt = build_receipt_es256(kid, issuer, claims, &sk);

    // Invalid base64 y.
    let mut bad_y = build_jwk_from_p256(kid, sk.verifying_key());
    bad_y.y = "%%%".to_string();
    let res = verify_transparent_statement_receipt("mst", &bad_y, &receipt, claims);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));

    // P-384 and P-521 should pass curve selection, even if decode fails later.
    let mut bad_p384 = build_jwk_from_p256(kid, sk.verifying_key());
    bad_p384.crv = "P-384".to_string();
    bad_p384.x = "%%%".to_string();
    let res2 = verify_transparent_statement_receipt("mst", &bad_p384, &receipt, claims);
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));

    let mut bad_p521 = build_jwk_from_p256(kid, sk.verifying_key());
    bad_p521.crv = "P-521".to_string();
    bad_p521.x = "%%%".to_string();
    let res3 = verify_transparent_statement_receipt("mst", &bad_p521, &receipt, claims);
    assert!(!res3.is_valid);
    assert_eq!(res3.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));

    // Unsupported curve fails early.
    let mut bad_curve = build_jwk_from_p256(kid, sk.verifying_key());
    bad_curve.crv = "P-999".to_string();
    let res4 = verify_transparent_statement_receipt("mst", &bad_curve, &receipt, claims);
    assert!(!res4.is_valid);
    assert_eq!(res4.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));
}

#[test]
fn receipt_verification_reports_vds_and_vdp_errors() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[18u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);

    // VDS missing.
    let protected_missing_vds = encode_receipt_headers(kid, Some("issuer.example"), None, false);
    let inclusion_map = encode_inclusion_map_with_path(b"claims", &[]);
    let receipt_missing_vds = encode_receipt(&protected_missing_vds, &inclusion_map, b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt_missing_vds, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_VDS_MISSING"));

    // VDS not CCF.
    let protected_wrong_vds = encode_receipt_headers(kid, Some("issuer.example"), Some(3), false);
    let receipt_wrong_vds = encode_receipt(&protected_wrong_vds, &inclusion_map, b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt_wrong_vds, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_VDS_NOT_CCF"));

    // VDP missing.
    let protected_ok = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);
    let receipt_missing_vdp = encode_receipt_with_vdp_value(&protected_ok, None, b"sig");
    let res3 = verify_transparent_statement_receipt("mst", &jwk, &receipt_missing_vdp, b"claims");
    assert!(!res3.is_valid);
    assert_eq!(res3.failures[0].error_code.as_deref(), Some("MST_VDP_MISSING"));

    // VDP wrong type.
    let receipt_vdp_int = encode_receipt_with_vdp_header_int(&protected_ok, 123, b"sig");
    let res4 = verify_transparent_statement_receipt("mst", &jwk, &receipt_vdp_int, b"claims");
    assert!(!res4.is_valid);
    assert_eq!(res4.failures[0].error_code.as_deref(), Some("MST_VDP_PARSE_ERROR"));
}

#[test]
fn receipt_verification_reports_inclusion_proof_errors() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[19u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), true);

    // Missing -1 key.
    let mut vdp_missing = Vec::new();
    {
        let mut enc = Encoder::new(&mut vdp_missing);
        enc.map(0).unwrap();
    }
    let receipt = encode_receipt_with_vdp_value(&protected, Some(&vdp_missing), b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_INCLUSION_MISSING"));

    // -1 value is wrong type.
    let mut vdp_wrong_type = Vec::new();
    {
        let mut enc = Encoder::new(&mut vdp_wrong_type);
        enc.map(1).unwrap();
        enc.i64(-1).unwrap();
        enc.i64(1).unwrap();
    }
    let receipt2 = encode_receipt_with_vdp_value(&protected, Some(&vdp_wrong_type), b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_INCLUSION_MISSING"));

    // -1 array is empty.
    let mut vdp_empty = Vec::new();
    {
        let mut enc = Encoder::new(&mut vdp_empty);
        enc.map(1).unwrap();
        enc.i64(-1).unwrap();
        enc.array(0).unwrap();
    }
    let receipt3 = encode_receipt_with_vdp_value(&protected, Some(&vdp_empty), b"sig");
    let res3 = verify_transparent_statement_receipt("mst", &jwk, &receipt3, b"claims");
    assert!(!res3.is_valid);
    assert_eq!(res3.failures[0].error_code.as_deref(), Some("MST_INCLUSION_MISSING"));

    // -1 array has element of wrong type.
    let mut vdp_bad_el = Vec::new();
    {
        let mut enc = Encoder::new(&mut vdp_bad_el);
        enc.map(1).unwrap();
        enc.i64(-1).unwrap();
        enc.array(1).unwrap();
        enc.i64(1).unwrap();
    }
    let receipt4 = encode_receipt_with_vdp_value(&protected, Some(&vdp_bad_el), b"sig");
    let res4 = verify_transparent_statement_receipt("mst", &jwk, &receipt4, b"claims");
    assert!(!res4.is_valid);
    assert_eq!(res4.failures[0].error_code.as_deref(), Some("MST_INCLUSION_PARSE_ERROR"));
}

#[test]
fn receipt_verification_leaf_value_wrong_type_reports_leaf_parse_error() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[55u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);

    let mut inclusion_map = Vec::new();
    {
        let mut enc = Encoder::new(&mut inclusion_map);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.i64(123).unwrap(); // leaf value is not an array/bstr
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }

    let receipt = encode_receipt(&protected, &inclusion_map, b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_LEAF_PARSE_ERROR"));
}

#[test]
fn receipt_verification_path_element_bool_wrong_type_reports_path_parse_error() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[56u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);

    let tx_hash = sha256(b"tx");
    let data_hash = sha256(b"claims");
    let mut inclusion_map = Vec::new();
    {
        let mut enc = Encoder::new(&mut inclusion_map);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.array(1).unwrap();
        enc.array(2).unwrap();
        enc.i64(1).unwrap(); // should be bool
        enc.bytes(b"h").unwrap();
    }

    let receipt = encode_receipt(&protected, &inclusion_map, b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_PATH_PARSE_ERROR"));
}

#[test]
fn receipt_verification_reports_inclusion_map_and_leaf_path_errors() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[20u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);

    // Inclusion map bytes have trailing bytes.
    let mut inclusion_map = encode_inclusion_map_with_path(b"claims", &[]);
    inclusion_map.push(0x00);
    let receipt = encode_receipt(&protected, &inclusion_map, b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_INCLUSION_PARSE_ERROR"));

    // Inclusion map bytes are not a map.
    let mut not_map = Vec::new();
    {
        let mut enc = Encoder::new(&mut not_map);
        enc.array(0).unwrap();
    }
    let receipt2 = encode_receipt(&protected, &not_map, b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_INCLUSION_PARSE_ERROR"));

    // Leaf missing.
    let mut only_path = Vec::new();
    {
        let mut enc = Encoder::new(&mut only_path);
        enc.map(1).unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }
    let receipt3 = encode_receipt(&protected, &only_path, b"sig");
    let res3 = verify_transparent_statement_receipt("mst", &jwk, &receipt3, b"claims");
    assert!(!res3.is_valid);
    assert_eq!(res3.failures[0].error_code.as_deref(), Some("MST_LEAF_MISSING"));

    // Path missing.
    let tx_hash = sha256(b"tx");
    let data_hash = sha256(b"claims");
    let mut only_leaf = Vec::new();
    {
        let mut enc = Encoder::new(&mut only_leaf);
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&data_hash).unwrap();
    }
    let receipt4 = encode_receipt(&protected, &only_leaf, b"sig");
    let res4 = verify_transparent_statement_receipt("mst", &jwk, &receipt4, b"claims");
    assert!(!res4.is_valid);
    assert_eq!(res4.failures[0].error_code.as_deref(), Some("MST_PATH_MISSING"));
}

#[test]
fn receipt_verification_leaf_and_path_parse_errors_cover_decoder_branches() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[21u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);

    // Leaf[0] as an int forces the custom CBOR decoder to read an integer value.
    let mut bad_leaf0 = Vec::new();
    {
        let mut enc = Encoder::new(&mut bad_leaf0);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.i64(1).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&sha256(b"claims")).unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }
    let receipt = encode_receipt(&protected, &bad_leaf0, b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_LEAF_PARSE_ERROR"));

    // Path element is not an array.
    let tx_hash = sha256(b"tx");
    let data_hash = sha256(b"claims");
    let mut bad_path = Vec::new();
    {
        let mut enc = Encoder::new(&mut bad_path);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.array(1).unwrap();
        enc.i64(1).unwrap();
    }
    let receipt2 = encode_receipt(&protected, &bad_path, b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_PATH_PARSE_ERROR"));
}

#[test]
fn receipt_verification_leaf_parse_error_variants_cover_more_lines() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[25u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);

    let tx_hash = sha256(b"tx");
    let data_hash = sha256(b"claims");

    // Leaf as bytes wrapping a non-array.
    let mut leaf_not_array = Vec::new();
    {
        let mut enc = Encoder::new(&mut leaf_not_array);
        enc.map(0).unwrap();
    }
    let mut inclusion1 = Vec::new();
    {
        let mut enc = Encoder::new(&mut inclusion1);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.bytes(&leaf_not_array).unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }
    let receipt1 = encode_receipt(&protected, &inclusion1, b"sig");
    let res1 = verify_transparent_statement_receipt("mst", &jwk, &receipt1, b"claims");
    assert_eq!(res1.failures[0].error_code.as_deref(), Some("MST_LEAF_PARSE_ERROR"));

    // Leaf array wrong length.
    let mut inclusion2 = Vec::new();
    {
        let mut enc = Encoder::new(&mut inclusion2);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(2).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }
    let receipt2 = encode_receipt(&protected, &inclusion2, b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_LEAF_PARSE_ERROR"));

    // Leaf[1] wrong type.
    let mut inclusion3 = Vec::new();
    {
        let mut enc = Encoder::new(&mut inclusion3);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.i64(123).unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }
    let receipt3 = encode_receipt(&protected, &inclusion3, b"sig");
    let res3 = verify_transparent_statement_receipt("mst", &jwk, &receipt3, b"claims");
    assert_eq!(res3.failures[0].error_code.as_deref(), Some("MST_LEAF_PARSE_ERROR"));

    // Leaf[2] wrong type.
    let mut inclusion4 = Vec::new();
    {
        let mut enc = Encoder::new(&mut inclusion4);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.str("not-bytes").unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }
    let receipt4 = encode_receipt(&protected, &inclusion4, b"sig");
    let res4 = verify_transparent_statement_receipt("mst", &jwk, &receipt4, b"claims");
    assert_eq!(res4.failures[0].error_code.as_deref(), Some("MST_LEAF_PARSE_ERROR"));
}

#[test]
fn receipt_verification_path_parse_error_variants_cover_more_lines() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[26u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);

    let tx_hash = sha256(b"tx");
    let data_hash = sha256(b"claims");

    // Path bytes wrapping an array with an inner array of wrong length.
    let mut bad_path_len = Vec::new();
    {
        let mut enc = Encoder::new(&mut bad_path_len);
        enc.array(1).unwrap();
        enc.array(1).unwrap();
        enc.bool(true).unwrap();
    }
    let mut inclusion1 = Vec::new();
    {
        let mut enc = Encoder::new(&mut inclusion1);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.bytes(&bad_path_len).unwrap();
    }
    let receipt1 = encode_receipt(&protected, &inclusion1, b"sig");
    let res1 = verify_transparent_statement_receipt("mst", &jwk, &receipt1, b"claims");
    assert_eq!(res1.failures[0].error_code.as_deref(), Some("MST_PATH_PARSE_ERROR"));

    // Path inner[0] wrong type.
    let mut bad_path_bool = Vec::new();
    {
        let mut enc = Encoder::new(&mut bad_path_bool);
        enc.array(1).unwrap();
        enc.array(2).unwrap();
        enc.i64(1).unwrap();
        enc.bytes(&sha256(b"h")).unwrap();
    }
    let mut inclusion2 = Vec::new();
    {
        let mut enc = Encoder::new(&mut inclusion2);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.bytes(&bad_path_bool).unwrap();
    }
    let receipt2 = encode_receipt(&protected, &inclusion2, b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_PATH_PARSE_ERROR"));

    // Path inner[1] wrong type.
    let mut bad_path_hash = Vec::new();
    {
        let mut enc = Encoder::new(&mut bad_path_hash);
        enc.array(1).unwrap();
        enc.array(2).unwrap();
        enc.bool(true).unwrap();
        enc.str("not-bytes").unwrap();
    }
    let mut inclusion3 = Vec::new();
    {
        let mut enc = Encoder::new(&mut inclusion3);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.bytes(&bad_path_hash).unwrap();
    }
    let receipt3 = encode_receipt(&protected, &inclusion3, b"sig");
    let res3 = verify_transparent_statement_receipt("mst", &jwk, &receipt3, b"claims");
    assert_eq!(res3.failures[0].error_code.as_deref(), Some("MST_PATH_PARSE_ERROR"));
}

#[test]
fn receipt_verification_covers_p384_and_p521_invalid_key_material_branches() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[27u8; 32].into()).expect("sk");
    let receipt = build_receipt_es256("kid-1", "issuer.example", b"claims", &sk);

    // Valid base64, wrong sizes => triggers the curve-specific from_sec1_bytes error paths.
    let tiny = URL_SAFE_NO_PAD.encode([1u8]);
    let bad_p384 = JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-384".to_string(),
        x: tiny.clone(),
        y: tiny.clone(),
        kid: "kid-1".to_string(),
    };
    let res1 = verify_transparent_statement_receipt("mst", &bad_p384, &receipt, b"claims");
    assert!(!res1.is_valid);
    assert_eq!(res1.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));

    let bad_p521 = JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-521".to_string(),
        x: tiny.clone(),
        y: tiny,
        kid: "kid-1".to_string(),
    };
    let res2 = verify_transparent_statement_receipt("mst", &bad_p521, &receipt, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));
}

#[test]
fn receipt_verification_succeeds_when_expected_kid_is_empty_string() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[28u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid_in_receipt = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";
    let receipt = build_receipt_es256(kid_in_receipt, issuer, claims, &sk);

    let mut jwk = build_jwk_from_p256("", vk);
    jwk.kid = "".to_string();

    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, claims);
    assert!(res.is_valid, "{:?}", res.failures);
}

#[test]
fn receipt_verification_covers_p384_and_p521_jwk_conversion_success_paths() {
    // Receipt can be any well-formed ES256 receipt; we force a KID mismatch to stop early.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[29u8; 32].into()).expect("sk");
    let receipt = build_receipt_es256("kid-in-receipt", "issuer.example", b"claims", &sk);

    // P-384 key -> JWK -> SPKI conversion should succeed.
    let sk384 = p384::ecdsa::SigningKey::from_bytes(&[1u8; 48].into()).expect("sk384");
    let vk384 = sk384.verifying_key();
    let p384_point = vk384.to_encoded_point(false);
    let p384_x = p384_point.x().expect("x");
    let p384_y = p384_point.y().expect("y");
    let jwk384 = JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-384".to_string(),
        x: URL_SAFE_NO_PAD.encode(p384_x),
        y: URL_SAFE_NO_PAD.encode(p384_y),
        kid: "different-kid".to_string(),
    };
    let res1 = verify_transparent_statement_receipt("mst", &jwk384, &receipt, b"claims");
    assert!(!res1.is_valid);
    assert_eq!(res1.failures[0].error_code.as_deref(), Some("MST_KID_MISMATCH"));

    // P-521 key -> JWK -> SPKI conversion should succeed.
    let mut rng = p521::elliptic_curve::rand_core::OsRng;
    let sk521 = p521::ecdsa::SigningKey::random(&mut rng);
    let vk521 = p521::ecdsa::VerifyingKey::from(&sk521);
    let p521_point = vk521.to_encoded_point(false);
    let p521_x = p521_point.x().expect("x");
    let p521_y = p521_point.y().expect("y");
    let jwk521 = JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-521".to_string(),
        x: URL_SAFE_NO_PAD.encode(p521_x),
        y: URL_SAFE_NO_PAD.encode(p521_y),
        kid: "different-kid".to_string(),
    };
    let res2 = verify_transparent_statement_receipt("mst", &jwk521, &receipt, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_KID_MISMATCH"));
}

#[test]
fn transparent_statement_authorized_domain_normalization_ignores_empty_and_unknown() {
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[b"not-cbor".to_vec()]);
    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![
        "".to_string(),
        "__unknown-issuer::0".to_string(),
        "issuer.example".to_string(),
    ];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;

    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
}

struct PanickingFetcher;

impl JwksFetcher for PanickingFetcher {
    fn fetch_jwks(&self, _issuer_host: &str, _jwks_path: &str, _timeout_ms: u32) -> Result<Vec<u8>, String> {
        panic!("fetch_jwks should not have been called");
    }
}

struct StaticFetcher {
    bytes: Vec<u8>,
}

impl JwksFetcher for StaticFetcher {
    fn fetch_jwks(&self, _issuer_host: &str, _jwks_path: &str, _timeout_ms: u32) -> Result<Vec<u8>, String> {
        Ok(self.bytes.clone())
    }
}

struct ErrorFetcher;

impl JwksFetcher for ErrorFetcher {
    fn fetch_jwks(&self, _issuer_host: &str, _jwks_path: &str, _timeout_ms: u32) -> Result<Vec<u8>, String> {
        Err("nope".to_string())
    }
}

#[test]
fn online_verification_does_not_fetch_when_not_allowed_or_cache_hits() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[8u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);
    let receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt]);

    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();

    let mut cache = OfflineEcKeyStore::default();
    cache.insert(
        issuer,
        kid,
        ResolvedKey {
            public_key_bytes: der.as_bytes().to_vec(),
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![issuer.to_string()];

    // Not allowed => offline path.
    opts.allow_network_key_fetch = false;
    let res = verify_transparent_statement_online("mst", &statement, &mut cache, &PanickingFetcher, &opts);
    assert!(res.is_valid, "{:?}", res.failures);

    // Allowed, but cache already makes the first attempt succeed => no fetch.
    opts.allow_network_key_fetch = true;
    let res2 = verify_transparent_statement_online("mst", &statement, &mut cache, &PanickingFetcher, &opts);
    assert!(res2.is_valid, "{:?}", res2.failures);
}

#[test]
fn online_verification_fetches_and_populates_cache() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[9u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);
    let receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt]);

    // Include some keys that should be skipped to cover the "continue" branches.
    let mut jwk_good = build_jwk_from_p256(kid, vk);
    let jwk_wrong_kty = JwkEcPublicKey {
        kty: "RSA".to_string(),
        crv: "P-256".to_string(),
        x: jwk_good.x.clone(),
        y: jwk_good.y.clone(),
        kid: "skip-kty".to_string(),
    };
    let jwk_bad_coords = JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: "AA".to_string(),
        y: "AA".to_string(),
        kid: "skip-coords".to_string(),
    };
    let jwk_unsupported_curve = JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-999".to_string(),
        x: jwk_good.x.clone(),
        y: jwk_good.y.clone(),
        kid: "skip-crv".to_string(),
    };
    jwk_good.kid = kid.to_string();
    let jwks_json = serde_json::to_vec(&JwksDocument {
        keys: vec![jwk_wrong_kty, jwk_bad_coords, jwk_unsupported_curve, jwk_good],
    })
    .unwrap();
    let fetcher = StaticFetcher { bytes: jwks_json };

    let mut cache = OfflineEcKeyStore::default();
    let mut opts = VerificationOptions::default();
    opts.allow_network_key_fetch = true;
    opts.authorized_domains = vec![issuer.to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;
    opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::RequireAll;

    let res = verify_transparent_statement_online("mst", &statement, &mut cache, &fetcher, &opts);
    assert!(res.is_valid, "{:?}", res.failures);
    assert!(cache.resolve(issuer, kid).is_some());
}

#[test]
fn online_verification_fetch_failures_do_not_crash() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[10u8; 32].into()).expect("sk");

    let kid = "kid-1";
    let issuer = "issuer.example";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);
    let receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt]);

    let mut cache = OfflineEcKeyStore::default();
    let mut opts = VerificationOptions::default();
    opts.allow_network_key_fetch = true;
    opts.authorized_domains = vec![issuer.to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;
    opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::RequireAll;

    let res = verify_transparent_statement_online("mst", &statement, &mut cache, &ErrorFetcher, &opts);
    assert!(!res.is_valid);
    assert!(cache.resolve(issuer, kid).is_none());

    let fetcher_bad_json = StaticFetcher {
        bytes: b"not-json".to_vec(),
    };
    let res2 = verify_transparent_statement_online("mst", &statement, &mut cache, &fetcher_bad_json, &opts);
    assert!(!res2.is_valid);
}
