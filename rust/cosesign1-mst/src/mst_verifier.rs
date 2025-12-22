// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Microsoft Signing Transparency (MST) receipt verification.
//!
//! This is a Rust implementation of the MST verifier logic.
//! It focuses on offline verification (keys supplied by the caller) and is
//! designed to be consumed via the Rust API and the Rust-backed C ABI.
//! - Receipts are embedded in the transparent statement unprotected header
//!   label `394` as an array of receipt COSE_Sign1 byte strings.
//! - Receipt verification validates:
//!   - `kid` (protected header label `4`) matches the provided key id
//!   - `vds` (protected header label `395`) indicates CCF (`2`)
//!   - `vdp` (unprotected header label `396`) contains inclusion proofs
//!   - Each inclusion proof yields an accumulator that verifies the receipt
//!     signature (detached payload)
//!   - Leaf `data_hash` equals `sha256(statement_without_unprotected_headers)`
//!
//! Network JWKS fetching is exposed via a trait, but this crate does not
//! hardcode any HTTP client.

use std::collections::{HashMap, HashSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cosesign1::common::parse_cose_sign1;
use cosesign1::validation::{verify_cose_sign1, CoseAlgorithm, ValidationFailure, ValidationResult, VerifyOptions};
use cosesign1_abstractions::{CoseHeaderMap, HeaderKey, HeaderValue, ParsedCoseSign1};
use minicbor::{Decoder, Encoder};
use p256::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const COSE_HEADER_EMBEDDED_RECEIPTS: i64 = 394;
const COSE_RECEIPT_CWT_MAP_LABEL: i64 = 15;
const COSE_RECEIPT_CWT_ISS_LABEL: i64 = 1;
const COSE_PHDR_VDS_LABEL: i64 = 395;
const COSE_PHDR_VDP_LABEL: i64 = 396;
const CCF_TREE_ALG_LABEL: i64 = 2;
const COSE_RECEIPT_INCLUSION_PROOF_LABEL: i64 = -1;
const CCF_PROOF_LEAF_LABEL: i64 = 1;
const CCF_PROOF_PATH_LABEL: i64 = 2;

const UNKNOWN_ISSUER_PREFIX: &str = "__unknown-issuer::";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizedReceiptBehavior {
    VerifyAnyMatching,
    VerifyAllMatching,
    RequireAll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnauthorizedReceiptBehavior {
    VerifyAll,
    IgnoreAll,
    FailIfPresent,
}

#[derive(Debug, Clone)]
pub struct VerificationOptions {
    pub authorized_domains: Vec<String>,
    pub allow_network_key_fetch: bool,
    pub jwks_path: String,
    pub jwks_timeout_ms: u32,
    pub authorized_receipt_behavior: AuthorizedReceiptBehavior,
    pub unauthorized_receipt_behavior: UnauthorizedReceiptBehavior,
}

impl Default for VerificationOptions {
    fn default() -> Self {
        Self {
            authorized_domains: Vec::new(),
            allow_network_key_fetch: false,
            jwks_path: "/jwks".to_string(),
            jwks_timeout_ms: 5000,
            authorized_receipt_behavior: AuthorizedReceiptBehavior::RequireAll,
            unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::FailIfPresent,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedKey {
    pub public_key_bytes: Vec<u8>,
    pub expected_alg: CoseAlgorithm,
}

#[derive(Debug, Default, Clone)]
pub struct OfflineEcKeyStore {
    keys: HashMap<(String, String), ResolvedKey>,
}

impl OfflineEcKeyStore {
    pub fn insert(&mut self, issuer_host: &str, kid: &str, key: ResolvedKey) {
        self.keys
            .insert((issuer_host.to_ascii_lowercase(), kid.to_ascii_lowercase()), key);
    }

    pub fn resolve(&self, issuer_host: &str, kid: &str) -> Option<&ResolvedKey> {
        self.keys
            .get(&(issuer_host.to_ascii_lowercase(), kid.to_ascii_lowercase()))
    }
}

/// Fetches a JWKS document for a given issuer.
///
/// This crate intentionally does not pick an HTTP client; callers can implement
/// this trait with their preferred stack.
pub trait JwksFetcher {
    fn fetch_jwks(&self, issuer_host: &str, jwks_path: &str, timeout_ms: u32) -> Result<Vec<u8>, String>;
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct JwkEcPublicKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub kid: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JwksDocument {
    pub keys: Vec<JwkEcPublicKey>,
}

fn failure(message: impl Into<String>, error_code: impl Into<String>) -> ValidationFailure {
    ValidationFailure {
        message: message.into(),
        error_code: Some(error_code.into()),
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = vec![0u8; bytes.len() * 2];
    for (i, b) in bytes.iter().copied().enumerate() {
        out[i * 2] = HEX[((b >> 4) & 0x0f) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8(out).unwrap_or_default()
}

fn looks_like_printable_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| (0x20..=0x7e).contains(&b))
}

fn normalize_kid(kid_bytes: &[u8]) -> String {
    if looks_like_printable_ascii(kid_bytes) {
        return String::from_utf8_lossy(kid_bytes).to_string();
    }
    bytes_to_hex_lower(kid_bytes)
}

fn encode_cose_sign1_with_null_payload(protected_map_cbor: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + protected_map_cbor.len() + signature.len());
    {
        let mut enc = Encoder::new(&mut out);
        enc.array(4).ok();
        enc.bytes(protected_map_cbor).ok();
        enc.map(0).ok();
        enc.null().ok();
        enc.bytes(signature).ok();
    }
    out
}

fn encode_cose_sign1_with_empty_unprotected(msg: &ParsedCoseSign1) -> Vec<u8> {
    let protected_map_cbor = msg.protected_headers.encoded_map_cbor();
    let mut out = Vec::with_capacity(
        128 + protected_map_cbor.len() + msg.signature.len() + msg.payload.as_ref().map(|p| p.len()).unwrap_or(0),
    );
    {
        let mut enc = Encoder::new(&mut out);
        // Encoding into a Vec is infallible.
        enc.array(4).ok();
        enc.bytes(protected_map_cbor).ok();
        enc.map(0).ok();
        match msg.payload.as_deref() {
            Some(p) => enc.bytes(p).ok(),
            None => enc.null().ok(),
        };
        enc.bytes(&msg.signature).ok();
    }
    out
}

fn decode_header_value_from_cbor_bytes(bytes: &[u8]) -> Result<HeaderValue, String> {
    let mut dec = Decoder::new(bytes);
    let v = decode_header_value_from_decoder(&mut dec)?;
    if dec.position() != bytes.len() {
        return Err("trailing bytes".to_string());
    }
    Ok(v)
}

fn decode_header_key_from_decoder(dec: &mut Decoder<'_>) -> Result<HeaderKey, String> {
    match dec.datatype().map_err(|e| e.to_string())? {
        minicbor::data::Type::String => Ok(HeaderKey::Text(
            dec.str().map_err(|e| e.to_string())?.to_string(),
        )),
        _ => Ok(HeaderKey::Int(dec.i64().map_err(|e| e.to_string())?)),
    }
}

fn decode_header_value_from_decoder(dec: &mut Decoder<'_>) -> Result<HeaderValue, String> {
    use minicbor::data::Type;
    match dec.datatype().map_err(|e| e.to_string())? {
        Type::Null => {
            dec.null().map_err(|e| e.to_string())?;
            Ok(HeaderValue::Null)
        }
        Type::Bool => Ok(HeaderValue::Bool(dec.bool().map_err(|e| e.to_string())?)),
        Type::Bytes => Ok(HeaderValue::Bytes(dec.bytes().map_err(|e| e.to_string())?.to_vec())),
        Type::String => Ok(HeaderValue::Text(
            dec.str().map_err(|e| e.to_string())?.to_string(),
        )),
        Type::U8
        | Type::U16
        | Type::U32
        | Type::U64
        | Type::I8
        | Type::I16
        | Type::I32
        | Type::I64
        | Type::Int => Ok(HeaderValue::Int(dec.i64().map_err(|e| e.to_string())?)),
        Type::Array => {
            let len = dec
                .array()
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "indefinite-length arrays are not supported".to_string())?;
            let mut out = Vec::with_capacity(len as usize);
            for _ in 0..len {
                out.push(decode_header_value_from_decoder(dec)?);
            }
            Ok(HeaderValue::Array(out))
        }
        Type::Map => {
            let len = dec
                .map()
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "indefinite-length maps are not supported".to_string())?;
            let mut out = std::collections::BTreeMap::new();
            for _ in 0..len {
                let k = decode_header_key_from_decoder(dec)?;
                let v = decode_header_value_from_decoder(dec)?;
                out.insert(k, v);
            }
            Ok(HeaderValue::Map(out))
        }
        other => Err(format!("unsupported CBOR type: {other:?}")),
    }
}

fn read_embedded_receipts(statement: &ParsedCoseSign1) -> Result<Vec<Vec<u8>>, String> {
    let v = statement
        .unprotected_headers
        .map()
        .get(&HeaderKey::Int(COSE_HEADER_EMBEDDED_RECEIPTS))
        .ok_or_else(|| "missing embedded receipts".to_string())?;

    match v {
        HeaderValue::Array(arr) => {
            let mut receipts = Vec::new();
            for el in arr {
                match el {
                    HeaderValue::Bytes(b) => receipts.push(b.clone()),
                    _ => return Err("embedded receipt array element was not a bstr".to_string()),
                }
            }
            Ok(receipts)
        }
        HeaderValue::Bytes(bytes) => {
            // Some encoders may wrap the array in a bstr; decode it.
            let decoded = decode_header_value_from_cbor_bytes(bytes)?;
            match decoded {
                HeaderValue::Array(arr) => {
                    let mut receipts = Vec::new();
                    for el in arr {
                        match el {
                            HeaderValue::Bytes(b) => receipts.push(b),
                            _ => return Err("embedded receipt array element was not a bstr".to_string()),
                        }
                    }
                    Ok(receipts)
                }
                _ => Err("embedded receipts value was not an array".to_string()),
            }
        }
        _ => Err("embedded receipts value was not an array".to_string()),
    }
}

fn read_receipt_kid(protected: &CoseHeaderMap) -> Option<Vec<u8>> {
    protected.get_bytes(4).map(|b| b.to_vec())
}

fn read_receipt_issuer_host(protected: &CoseHeaderMap) -> Option<String> {
    let v = protected.map().get(&HeaderKey::Int(COSE_RECEIPT_CWT_MAP_LABEL))?;

    let map_val = match v {
        HeaderValue::Map(m) => HeaderValue::Map(m.clone()),
        HeaderValue::Bytes(b) => decode_header_value_from_cbor_bytes(b).ok()?,
        _ => return None,
    };

    let HeaderValue::Map(m) = map_val else { return None };
    let iss = m.get(&HeaderKey::Int(COSE_RECEIPT_CWT_ISS_LABEL))?;
    match iss {
        HeaderValue::Text(t) => Some(t.clone()),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct ProofElement {
    left: bool,
    hash: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Leaf {
    internal_transaction_hash: Vec<u8>,
    internal_evidence: String,
    data_hash: Vec<u8>,
}

fn parse_leaf(v: &HeaderValue) -> Result<Leaf, String> {
    let leaf_value = match v {
        HeaderValue::Array(a) => HeaderValue::Array(a.clone()),
        HeaderValue::Bytes(b) => decode_header_value_from_cbor_bytes(b)?,
        _ => return Err("leaf must be an array or bstr".to_string()),
    };

    let HeaderValue::Array(items) = leaf_value else { return Err("leaf must be an array".to_string()) };
    if items.len() != 3 {
        return Err("leaf array length was not 3".to_string());
    }

    let tx_hash = match &items[0] {
        HeaderValue::Bytes(b) => b.clone(),
        _ => return Err("leaf[0] must be a bstr".to_string()),
    };
    let evidence = match &items[1] {
        HeaderValue::Text(s) => s.clone(),
        _ => return Err("leaf[1] must be a tstr".to_string()),
    };
    let data_hash = match &items[2] {
        HeaderValue::Bytes(b) => b.clone(),
        _ => return Err("leaf[2] must be a bstr".to_string()),
    };

    Ok(Leaf {
        internal_transaction_hash: tx_hash,
        internal_evidence: evidence,
        data_hash,
    })
}

fn parse_proof_elements(v: &HeaderValue) -> Result<Vec<ProofElement>, String> {
    let path_value = match v {
        HeaderValue::Array(a) => HeaderValue::Array(a.clone()),
        HeaderValue::Bytes(b) => decode_header_value_from_cbor_bytes(b)?,
        _ => return Err("path must be an array or bstr".to_string()),
    };

    let HeaderValue::Array(elements) = path_value else { return Err("path must be an array".to_string()) };
    let mut out = Vec::with_capacity(elements.len());
    for el in elements {
        let HeaderValue::Array(inner) = el else { return Err("path element must be an array".to_string()) };
        if inner.len() != 2 {
            return Err("path element length was not 2".to_string());
        }
        let left = match inner[0] {
            HeaderValue::Bool(b) => b,
            _ => return Err("path element[0] must be bool".to_string()),
        };
        let hash = match &inner[1] {
            HeaderValue::Bytes(b) => b.clone(),
            _ => return Err("path element[1] must be bstr".to_string()),
        };
        out.push(ProofElement { left, hash });
    }
    Ok(out)
}

fn compute_accumulator(leaf: &Leaf, proof: &[ProofElement]) -> Vec<u8> {
    let evidence_hash = sha256(leaf.internal_evidence.as_bytes());
    let mut leaf_hash_input = Vec::with_capacity(leaf.internal_transaction_hash.len() + evidence_hash.len() + leaf.data_hash.len());
    leaf_hash_input.extend_from_slice(&leaf.internal_transaction_hash);
    leaf_hash_input.extend_from_slice(&evidence_hash);
    leaf_hash_input.extend_from_slice(&leaf.data_hash);
    let mut acc = sha256(&leaf_hash_input);
    for pe in proof {
        if pe.left {
            let mut v = Vec::with_capacity(pe.hash.len() + acc.len());
            v.extend_from_slice(&pe.hash);
            v.extend_from_slice(&acc);
            acc = sha256(&v);
        } else {
            let mut v = Vec::with_capacity(pe.hash.len() + acc.len());
            v.extend_from_slice(&acc);
            v.extend_from_slice(&pe.hash);
            acc = sha256(&v);
        }
    }
    acc
}

/// Determines the expected COSE algorithm from an EC curve name.
///
/// Matches the native helper behavior:
/// - `P-256` => `ES256`
/// - `P-384` => `ES384`
/// - `P-521` => `ES512`
pub fn expected_alg_from_crv(crv: &str) -> Option<CoseAlgorithm> {
    match crv {
        "P-256" => Some(CoseAlgorithm::ES256),
        "P-384" => Some(CoseAlgorithm::ES384),
        "P-521" => Some(CoseAlgorithm::ES512),
        _ => None,
    }
}

/// Converts an EC JWK public key into a DER-encoded SubjectPublicKeyInfo.
pub fn jwk_ec_to_spki_der(jwk: &JwkEcPublicKey) -> Result<Vec<u8>, String> {
    if jwk.kty != "EC" {
        return Err("only EC JWK supported".to_string());
    }

    let x = URL_SAFE_NO_PAD.decode(&jwk.x).map_err(|e| format!("invalid JWK x: {e}"))?;
    let y = URL_SAFE_NO_PAD.decode(&jwk.y).map_err(|e| format!("invalid JWK y: {e}"))?;

    // Convert to SEC1 uncompressed form: 0x04 || X || Y.
    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    match jwk.crv.as_str() {
        "P-256" => {
            let pk = p256::PublicKey::from_sec1_bytes(&sec1).map_err(|e| format!("invalid P-256 key: {e}"))?;
            Ok(pk.to_public_key_der().map_err(|e| e.to_string())?.as_bytes().to_vec())
        }
        "P-384" => {
            let pk = p384::PublicKey::from_sec1_bytes(&sec1).map_err(|e| format!("invalid P-384 key: {e}"))?;
            Ok(pk.to_public_key_der().map_err(|e| e.to_string())?.as_bytes().to_vec())
        }
        "P-521" => {
            let pk = p521::PublicKey::from_sec1_bytes(&sec1).map_err(|e| format!("invalid P-521 key: {e}"))?;
            Ok(pk.to_public_key_der().map_err(|e| e.to_string())?.as_bytes().to_vec())
        }
        _ => Err("unsupported EC curve".to_string()),
    }
}

/// Parses a JWKS JSON document (RFC 7517).
///
/// Supported key form:
/// - EC JWKs with (kty=EC, crv, x, y, kid)
pub fn parse_jwks(jwks_json: &[u8]) -> Result<JwksDocument, String> {
    serde_json::from_slice(jwks_json).map_err(|e| format!("invalid JWKS JSON: {e}"))
}

/// Adds supported EC JWK keys from a JWKS document into an offline key store.
///
/// Keys are inserted by `(issuer_host, kid)`.
///
/// Returns the number of keys inserted.
pub fn add_issuer_keys(store: &mut OfflineEcKeyStore, issuer_host: &str, doc: &JwksDocument) -> Result<usize, String> {
    let mut inserted = 0usize;
    for jwk in &doc.keys {
        if jwk.kty != "EC" {
            continue;
        }
        let Some(expected_alg) = expected_alg_from_crv(&jwk.crv) else {
            continue;
        };
        let spki_der = jwk_ec_to_spki_der(jwk)?;
        store.insert(
            issuer_host,
            &jwk.kid,
            ResolvedKey {
                public_key_bytes: spki_der,
                expected_alg,
            },
        );
        inserted += 1;
    }
    Ok(inserted)
}

fn read_vdp_inclusion_maps(parsed_receipt: &ParsedCoseSign1) -> Result<Vec<Vec<u8>>, ValidationFailure> {
    let v = parsed_receipt
        .unprotected_headers
        .map()
        .get(&HeaderKey::Int(COSE_PHDR_VDP_LABEL))
        .ok_or_else(|| failure("Verifiable data proof is required", "MST_VDP_MISSING"))?;

    let vdp = match v {
        HeaderValue::Map(m) => HeaderValue::Map(m.clone()),
        HeaderValue::Bytes(b) => decode_header_value_from_cbor_bytes(b).map_err(|_| failure("VDP parse error", "MST_VDP_PARSE_ERROR"))?,
        _ => return Err(failure("VDP parse error", "MST_VDP_PARSE_ERROR")),
    };

    let HeaderValue::Map(m) = vdp else { return Err(failure("VDP parse error", "MST_VDP_PARSE_ERROR")) };
    let v = m
        .get(&HeaderKey::Int(COSE_RECEIPT_INCLUSION_PROOF_LABEL))
        .ok_or_else(|| failure("At least one inclusion proof is required", "MST_INCLUSION_MISSING"))?;

    let v = match v {
        HeaderValue::Array(a) => HeaderValue::Array(a.clone()),
        HeaderValue::Bytes(b) => decode_header_value_from_cbor_bytes(b).map_err(|_| failure("Inclusion proofs parse error", "MST_INCLUSION_PARSE_ERROR"))?,
        _ => return Err(failure("Inclusion proof is required", "MST_INCLUSION_MISSING")),
    };

    let HeaderValue::Array(proofs) = v else { return Err(failure("Inclusion proof is required", "MST_INCLUSION_MISSING")) };

    let mut out = Vec::new();
    for el in proofs {
        match el {
            HeaderValue::Bytes(b) => out.push(b),
            _ => return Err(failure("Inclusion proof element must be a byte string", "MST_INCLUSION_PARSE_ERROR")),
        }
    }
    if out.is_empty() {
        return Err(failure("At least one inclusion proof is required", "MST_INCLUSION_MISSING"));
    }
    Ok(out)
}

fn verify_receipt_against_claims(
    receipt_cose_sign1: &[u8],
    input_signed_claims: &[u8],
    key: &ResolvedKey,
    expected_kid: Option<&str>,
) -> Result<(), Vec<ValidationFailure>> {
    let mut failures = Vec::new();

    let parsed_receipt = match parse_cose_sign1(receipt_cose_sign1) {
        Ok(p) => p,
        Err(_) => {
            failures.push(failure("Invalid receipt COSE_Sign1 structure", "MST_RECEIPT_PARSE_ERROR"));
            return Err(failures);
        }
    };

    let kid_bytes = read_receipt_kid(&parsed_receipt.protected_headers).ok_or_else(|| {
        let mut f = Vec::new();
        f.push(failure("Receipt KID not found", "MST_KID_MISSING"));
        f
    })?;

    if let Some(expected) = expected_kid {
        if !expected.is_empty() {
            let kid_norm = normalize_kid(&kid_bytes);
            if kid_norm.to_ascii_lowercase() != expected.to_ascii_lowercase() {
                failures.push(failure("KID mismatch", "MST_KID_MISMATCH"));
                return Err(failures);
            }
        }
    }

    let vds = parsed_receipt
        .protected_headers
        .get_i64(COSE_PHDR_VDS_LABEL)
        .ok_or_else(|| {
            let mut f = Vec::new();
            f.push(failure("Verifiable Data Structure is required", "MST_VDS_MISSING"));
            f
        })?;
    if vds != CCF_TREE_ALG_LABEL {
        failures.push(failure("Verifiable Data Structure is not CCF", "MST_VDS_NOT_CCF"));
        return Err(failures);
    }

    let claims_digest = sha256(input_signed_claims);

    let inclusion_maps = match read_vdp_inclusion_maps(&parsed_receipt) {
        Ok(v) => v,
        Err(f) => {
            failures.push(f);
            return Err(failures);
        }
    };

    for inclusion_map_bytes in inclusion_maps {
        let inclusion_map_val = decode_header_value_from_cbor_bytes(&inclusion_map_bytes)
            .map_err(|_| vec![failure("Inclusion proof map parse error", "MST_INCLUSION_PARSE_ERROR")])?;
        let HeaderValue::Map(m) = inclusion_map_val else {
            failures.push(failure("Inclusion proof map parse error", "MST_INCLUSION_PARSE_ERROR"));
            return Err(failures);
        };

        let mut leaf: Option<Leaf> = None;
        let mut path: Option<Vec<ProofElement>> = None;

        for (k, v) in m {
            let HeaderKey::Int(k) = k else { continue };
            if k == CCF_PROOF_LEAF_LABEL {
                match parse_leaf(&v) {
                    Ok(l) => leaf = Some(l),
                    Err(_) => {
                        failures.push(failure("Leaf parse error", "MST_LEAF_PARSE_ERROR"));
                        return Err(failures);
                    }
                }
                continue;
            }
            if k == CCF_PROOF_PATH_LABEL {
                match parse_proof_elements(&v) {
                    Ok(p) => path = Some(p),
                    Err(_) => {
                        failures.push(failure("Path parse error", "MST_PATH_PARSE_ERROR"));
                        return Err(failures);
                    }
                }
                continue;
            }
        }

        let leaf = match leaf {
            Some(l) => l,
            None => {
                failures.push(failure("Leaf must be present", "MST_LEAF_MISSING"));
                return Err(failures);
            }
        };
        let path = match path {
            Some(p) => p,
            None => {
                failures.push(failure("Path must be present", "MST_PATH_MISSING"));
                return Err(failures);
            }
        };

        let accumulator = compute_accumulator(&leaf, &path);

        // Verify receipt signature with detached payload = accumulator.
        let detached_receipt_for_sig = encode_cose_sign1_with_null_payload(
            parsed_receipt.protected_headers.encoded_map_cbor(),
            &parsed_receipt.signature,
        );

        let mut verify_opts = VerifyOptions::default();
        verify_opts.external_payload = Some(accumulator);
        verify_opts.public_key_bytes = Some(key.public_key_bytes.clone());
        verify_opts.expected_alg = Some(key.expected_alg);
        let sig_res = verify_cose_sign1("MstReceiptSignature", &detached_receipt_for_sig, &verify_opts);
        if !sig_res.is_valid {
            let details = sig_res
                .failures
                .first()
                .map(|f| format!(": {}: {}", f.error_code.clone().unwrap_or("UNKNOWN".to_string()), f.message))
                .unwrap_or_default();
            failures.push(failure(
                format!("Receipt signature verification failed{details}"),
                "MST_RECEIPT_SIGNATURE_INVALID",
            ));
            return Err(failures);
        }

        if leaf.data_hash != claims_digest {
            failures.push(failure("Claim digest mismatch", "MST_CLAIM_DIGEST_MISMATCH"));
            return Err(failures);
        }
    }

    Ok(())
}

/// Verifies MST receipts embedded in a COSE_Sign1 transparent statement.
pub fn verify_transparent_statement(
    validator_name: &str,
    transparent_statement_cose_sign1: &[u8],
    key_store: &OfflineEcKeyStore,
    options: &VerificationOptions,
) -> ValidationResult {
    let mut failures: Vec<ValidationFailure> = Vec::new();

    let parsed = match parse_cose_sign1(transparent_statement_cose_sign1) {
        Ok(p) => p,
        Err(_) => {
            failures.push(failure(
                "Invalid COSE_Sign1 structure (CBOR parse failed)",
                "CBOR_PARSE_ERROR",
            ));
            return ValidationResult::failure(validator_name.to_string(), failures);
        }
    };

    let receipts = match read_embedded_receipts(&parsed) {
        Ok(r) => r,
        Err(_) => {
            failures.push(failure(
                "No receipts found in the transparent statement",
                "MST_NO_RECEIPT",
            ));
            return ValidationResult::failure(validator_name.to_string(), failures);
        }
    };
    if receipts.is_empty() {
        failures.push(failure(
            "No receipts found in the transparent statement",
            "MST_NO_RECEIPT",
        ));
        return ValidationResult::failure(validator_name.to_string(), failures);
    }

    let statement_without_unprotected = encode_cose_sign1_with_empty_unprotected(&parsed);

    // Normalize authorized list.
    let mut authorized: HashSet<String> = HashSet::new();
    for d in &options.authorized_domains {
        if !d.is_empty() && !d.starts_with(UNKNOWN_ISSUER_PREFIX) {
            authorized.insert(d.to_ascii_lowercase());
        }
    }
    let user_provided_authorized = !authorized.is_empty();

    if !user_provided_authorized && options.unauthorized_receipt_behavior == UnauthorizedReceiptBehavior::IgnoreAll {
        failures.push(failure(
            "No receipts would be verified as no authorized domains were provided and unauthorized behavior is IgnoreAll",
            "MST_NO_VERIFIABLE_RECEIPTS",
        ));
        return ValidationResult::failure(validator_name.to_string(), failures);
    }

    let mut authorized_failures: Vec<ValidationFailure> = Vec::new();
    let mut unauthorized_failures: Vec<ValidationFailure> = Vec::new();
    let mut valid_authorized_domains: HashSet<String> = HashSet::new();
    let mut authorized_domains_with_receipt: HashSet<String> = HashSet::new();

    // Early failure if FailIfPresent.
    if options.unauthorized_receipt_behavior == UnauthorizedReceiptBehavior::FailIfPresent {
        for (i, receipt_bytes) in receipts.iter().enumerate() {
            let issuer = parse_cose_sign1(receipt_bytes)
                .ok()
                .and_then(|p| read_receipt_issuer_host(&p.protected_headers))
                .unwrap_or_else(|| format!("{UNKNOWN_ISSUER_PREFIX}{i}"));

            if !authorized.contains(&issuer.to_ascii_lowercase()) {
                authorized_failures.push(failure(
                    format!("Receipt issuer '{issuer}' is not in the authorized domain list"),
                    "MST_UNAUTHORIZED_RECEIPT",
                ));
            }
        }

        if !authorized_failures.is_empty() {
            return ValidationResult::failure(validator_name.to_string(), authorized_failures);
        }
    }

    for (i, receipt_bytes) in receipts.iter().enumerate() {
        let parsed_receipt = parse_cose_sign1(receipt_bytes).ok();
        let issuer = parsed_receipt
            .as_ref()
            .and_then(|p| read_receipt_issuer_host(&p.protected_headers))
            .unwrap_or_else(|| format!("{UNKNOWN_ISSUER_PREFIX}{i}"));

        let is_authorized = authorized.contains(&issuer.to_ascii_lowercase());
        if is_authorized {
            authorized_domains_with_receipt.insert(issuer.to_ascii_lowercase());
        }

        let should_verify = if is_authorized {
            true
        } else {
            matches!(options.unauthorized_receipt_behavior, UnauthorizedReceiptBehavior::VerifyAll)
        };

        if !should_verify {
            continue;
        }

        if parsed_receipt.is_none() {
            unauthorized_failures
                .push(failure("Invalid receipt COSE_Sign1 structure", "MST_RECEIPT_PARSE_ERROR"));
            continue;
        }

        if issuer.starts_with(UNKNOWN_ISSUER_PREFIX) {
            unauthorized_failures.push(failure(
                format!("Cannot verify receipt with unknown issuer '{issuer}'"),
                "MST_UNKNOWN_ISSUER",
            ));
            continue;
        }

        let parsed_receipt = parsed_receipt.expect("checked above");

        let kid_bytes = match read_receipt_kid(&parsed_receipt.protected_headers) {
            Some(k) => k,
            None => {
                unauthorized_failures.push(failure("KID not found in receipt", "MST_KID_MISSING"));
                continue;
            }
        };
        let kid_str = normalize_kid(&kid_bytes);
        let Some(key) = key_store.resolve(&issuer, &kid_str) else {
            let bucket = if is_authorized {
                &mut authorized_failures
            } else {
                &mut unauthorized_failures
            };
            bucket.push(failure(
                format!("Key with ID '{kid_str}' not found for issuer '{issuer}'"),
                "MST_KEY_NOT_FOUND",
            ));
            continue;
        };

        match verify_receipt_against_claims(receipt_bytes, &statement_without_unprotected, key, None) {
            Ok(()) => {
                if is_authorized {
                    valid_authorized_domains.insert(issuer.to_ascii_lowercase());
                }
            }
            Err(mut receipt_failures) => {
                let bucket = if is_authorized {
                    &mut authorized_failures
                } else {
                    &mut unauthorized_failures
                };
                bucket.append(&mut receipt_failures);
            }
        }
    }

    // Post-process authorized receipt behavior.
    if user_provided_authorized {
        match options.authorized_receipt_behavior {
            AuthorizedReceiptBehavior::VerifyAnyMatching => {
                if !authorized.is_empty() && valid_authorized_domains.is_empty() {
                    authorized_failures.push(failure(
                        "No valid receipts found for any authorized issuer domain",
                        "MST_NO_VALID_AUTHORIZED_RECEIPTS",
                    ));
                } else {
                    authorized_failures.clear();
                }
            }
            AuthorizedReceiptBehavior::VerifyAllMatching => {
                if !authorized.is_empty() && authorized_domains_with_receipt.is_empty() {
                    authorized_failures.push(failure(
                        "No receipts found for any authorized issuer domain",
                        "MST_NO_VALID_AUTHORIZED_RECEIPTS",
                    ));
                }
                for dom in &authorized_domains_with_receipt {
                    if !valid_authorized_domains.contains(dom) {
                        authorized_failures.push(failure(
                            format!("A receipt from the required domain '{dom}' failed verification"),
                            "MST_REQUIRED_DOMAIN_FAILED",
                        ));
                    }
                }
            }
            AuthorizedReceiptBehavior::RequireAll => {
                for dom in &authorized {
                    if !valid_authorized_domains.contains(dom) {
                        authorized_failures.push(failure(
                            format!("No valid receipt found for a required domain '{dom}'"),
                            "MST_REQUIRED_DOMAIN_MISSING",
                        ));
                    }
                }
            }
        }
    }

    failures.extend(authorized_failures);
    failures.extend(unauthorized_failures);
    if !failures.is_empty() {
        return ValidationResult::failure(validator_name.to_string(), failures);
    }

    let mut metadata = HashMap::new();
    metadata.insert("receipts".to_string(), receipts.len().to_string());
    metadata.insert(
        "verifiedAuthorizedDomains".to_string(),
        valid_authorized_domains.len().to_string(),
    );
    ValidationResult::success(validator_name.to_string(), metadata)
}

/// Verifies a single MST receipt against detached signed claims bytes.
pub fn verify_transparent_statement_receipt(
    validator_name: &str,
    jwk: &JwkEcPublicKey,
    receipt_cose_sign1: &[u8],
    input_signed_claims: &[u8],
) -> ValidationResult {
    let mut failures: Vec<ValidationFailure> = Vec::new();
    let expected_alg = match expected_alg_from_crv(&jwk.crv) {
        Some(a) => a,
        None => {
            failures.push(failure("Unsupported EC curve", "MST_JWK_ERROR"));
            return ValidationResult::failure(validator_name.to_string(), failures);
        }
    };

    let der = match jwk_ec_to_spki_der(jwk) {
        Ok(d) => d,
        Err(_) => {
            failures.push(failure("Failed to convert JWK to public key", "MST_JWK_ERROR"));
            return ValidationResult::failure(validator_name.to_string(), failures);
        }
    };

    let key = ResolvedKey {
        public_key_bytes: der,
        expected_alg,
    };

    match verify_receipt_against_claims(receipt_cose_sign1, input_signed_claims, &key, Some(&jwk.kid)) {
        Ok(()) => ValidationResult::success(validator_name.to_string(), HashMap::new()),
        Err(f) => ValidationResult::failure(validator_name.to_string(), f),
    }
}

/// Same as `verify_transparent_statement`, with optional JWKS fallback.
pub fn verify_transparent_statement_online(
    validator_name: &str,
    transparent_statement_cose_sign1: &[u8],
    key_cache: &mut OfflineEcKeyStore,
    jwks_fetcher: &dyn JwksFetcher,
    options: &VerificationOptions,
) -> ValidationResult {
    // If network fetch is disabled, this is equivalent to offline verification.
    if !options.allow_network_key_fetch {
        return verify_transparent_statement(validator_name, transparent_statement_cose_sign1, key_cache, options);
    }

    // First attempt: use whatever is already in the cache.
    let res = verify_transparent_statement(validator_name, transparent_statement_cose_sign1, key_cache, options);
    if res.is_valid {
        return res;
    }

    // Best-effort: attempt to fetch JWKS for each authorized issuer and populate cache.
    let mut issuers: HashSet<String> = HashSet::new();
    for d in &options.authorized_domains {
        if !d.is_empty() && !d.starts_with(UNKNOWN_ISSUER_PREFIX) {
            issuers.insert(d.clone());
        }
    }

    for issuer in issuers {
        let jwks_bytes = match jwks_fetcher.fetch_jwks(&issuer, &options.jwks_path, options.jwks_timeout_ms) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let doc: JwksDocument = match serde_json::from_slice(&jwks_bytes) {
            Ok(d) => d,
            Err(_) => continue,
        };
        for jwk in doc.keys {
            let der = match jwk_ec_to_spki_der(&jwk) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let Some(expected_alg) = expected_alg_from_crv(&jwk.crv) else { continue };
            key_cache.insert(
                &issuer,
                &jwk.kid,
                ResolvedKey {
                    public_key_bytes: der,
                    expected_alg,
                },
            );
        }
    }

    // Second attempt after populating cache.
    verify_transparent_statement(validator_name, transparent_statement_cose_sign1, key_cache, options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_receipt_against_claims_reports_parse_error_for_invalid_receipt_bytes() {
        let key = ResolvedKey {
            public_key_bytes: Vec::new(),
            expected_alg: CoseAlgorithm::ES256,
        };

        let err = verify_receipt_against_claims(b"not-cbor", b"claims", &key, None).unwrap_err();
        assert!(!err.is_empty());
        assert_eq!(err[0].error_code.as_deref(), Some("MST_RECEIPT_PARSE_ERROR"));
    }
}
