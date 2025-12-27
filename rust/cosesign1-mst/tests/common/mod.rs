// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(dead_code)]

//! Shared helpers for the `cosesign1-mst` integration tests.
//!
//! The MST test-suite intentionally constructs many small COSE_Sign1 payloads/receipts
//! by hand to exercise decoder branches and error mapping in the verifier.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cosesign1::{encode_signature1_sig_structure, parse_cose_sign1};
use cosesign1_mst::{JwkEcPublicKey, JwksFetcher};
use minicbor::Encoder;
use p256::ecdsa::signature::Signer;
use sha2::{Digest, Sha256};

pub fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().to_vec()
}

pub fn build_jwk_from_p256(kid: &str, vk: &p256::ecdsa::VerifyingKey) -> JwkEcPublicKey {
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

pub fn encode_receipt(protected_map_cbor: &[u8], inclusion_map_cbor: &[u8], signature: &[u8]) -> Vec<u8> {
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

pub fn encode_inclusion_map_with_path(claims: &[u8], path: &[(bool, &[u8])]) -> Vec<u8> {
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

pub fn encode_receipt_headers(kid: &str, issuer: Option<&str>, vds: Option<i64>, cwt_as_bytes: bool) -> Vec<u8> {
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

pub fn encode_receipt_with_vdp_value(protected_map_cbor: &[u8], vdp_value: Option<&[u8]>, signature: &[u8]) -> Vec<u8> {
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

pub fn encode_receipt_with_vdp_header_int(protected_map_cbor: &[u8], vdp_value: i64, signature: &[u8]) -> Vec<u8> {
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

pub fn encode_statement_with_receipts_value(payload: Option<&[u8]>, signature: &[u8], receipts_header_value: &[u8]) -> Vec<u8> {
    let protected_empty: Vec<u8> = Vec::new();
    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    enc.array(4).unwrap();
    enc.bytes(&protected_empty).unwrap();

    enc.map(1).unwrap();
    enc.i64(394).unwrap();
    // `receipts_header_value` is already CBOR-encoded (either an array or a wrapped value).
    // We encode it as a bstr so the verifier exercises its "wrapped" decode path.
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

pub fn encode_statement_without_unprotected_payload(payload: Option<&[u8]>, signature: &[u8]) -> Vec<u8> {
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

pub fn encode_statement_with_receipts(payload: &[u8], signature: &[u8], receipts: &[Vec<u8>]) -> Vec<u8> {
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

pub fn encode_statement_without_unprotected(payload: &[u8], signature: &[u8]) -> Vec<u8> {
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

pub fn build_receipt_es256(kid: &str, issuer: &str, claims: &[u8], sk: &p256::ecdsa::SigningKey) -> Vec<u8> {
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

pub fn build_receipt_es256_with_kid_bytes(
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

pub struct PanickingFetcher;

impl JwksFetcher for PanickingFetcher {
    fn fetch_jwks(&self, _issuer_host: &str, _jwks_path: &str, _timeout_ms: u32) -> Result<Vec<u8>, String> {
        panic!("fetch_jwks should not have been called");
    }
}

pub struct StaticFetcher {
    pub bytes: Vec<u8>,
}

impl JwksFetcher for StaticFetcher {
    fn fetch_jwks(&self, _issuer_host: &str, _jwks_path: &str, _timeout_ms: u32) -> Result<Vec<u8>, String> {
        Ok(self.bytes.clone())
    }
}

pub struct ErrorFetcher;

impl JwksFetcher for ErrorFetcher {
    fn fetch_jwks(&self, _issuer_host: &str, _jwks_path: &str, _timeout_ms: u32) -> Result<Vec<u8>, String> {
        Err("nope".to_string())
    }
}
