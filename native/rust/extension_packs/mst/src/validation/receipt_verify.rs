// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborDecoder, CborEncoder};
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue, CoseSign1Message, ProtectedHeader};
use ring::signature;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

// Inline base64url utilities
pub(crate) const BASE64_URL_SAFE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub(crate) fn base64_decode(input: &str, alphabet: &[u8; 64]) -> Result<Vec<u8>, String> {
    let mut lookup = [0xFFu8; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let input = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &b in input.as_bytes() {
        let val = lookup[b as usize];
        if val == 0xFF {
            return Err(format!("invalid base64 byte: 0x{:02x}", b));
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// Decode base64url (no padding) to bytes.
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
    base64_decode(input, BASE64_URL_SAFE)
}

#[derive(Debug)]
pub enum ReceiptVerifyError {
    ReceiptDecode(String),
    MissingAlg,
    MissingKid,
    UnsupportedAlg(i64),
    UnsupportedVds(i64),
    MissingVdp,
    MissingProof,
    MissingIssuer,
    JwksParse(String),
    JwksFetch(String),
    JwkNotFound(String),
    JwkUnsupported(String),
    StatementReencode(String),
    SigStructureEncode(String),
    DataHashMismatch,
    SignatureInvalid,
}

impl std::fmt::Display for ReceiptVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptVerifyError::ReceiptDecode(msg) => write!(f, "receipt_decode_failed: {}", msg),
            ReceiptVerifyError::MissingAlg => write!(f, "receipt_missing_alg"),
            ReceiptVerifyError::MissingKid => write!(f, "receipt_missing_kid"),
            ReceiptVerifyError::UnsupportedAlg(alg) => write!(f, "unsupported_alg: {}", alg),
            ReceiptVerifyError::UnsupportedVds(vds) => write!(f, "unsupported_vds: {}", vds),
            ReceiptVerifyError::MissingVdp => write!(f, "missing_vdp"),
            ReceiptVerifyError::MissingProof => write!(f, "missing_proof"),
            ReceiptVerifyError::MissingIssuer => write!(f, "issuer_missing"),
            ReceiptVerifyError::JwksParse(msg) => write!(f, "jwks_parse_failed: {}", msg),
            ReceiptVerifyError::JwksFetch(msg) => write!(f, "jwks_fetch_failed: {}", msg),
            ReceiptVerifyError::JwkNotFound(kid) => write!(f, "jwk_not_found_for_kid: {}", kid),
            ReceiptVerifyError::JwkUnsupported(msg) => write!(f, "jwk_unsupported: {}", msg),
            ReceiptVerifyError::StatementReencode(msg) => {
                write!(f, "statement_reencode_failed: {}", msg)
            }
            ReceiptVerifyError::SigStructureEncode(msg) => {
                write!(f, "sig_structure_encode_failed: {}", msg)
            }
            ReceiptVerifyError::DataHashMismatch => write!(f, "data_hash_mismatch"),
            ReceiptVerifyError::SignatureInvalid => write!(f, "signature_invalid"),
        }
    }
}

impl std::error::Error for ReceiptVerifyError {}

/// MST receipt protected header label: 395.
const VDS_HEADER_LABEL: i64 = 395;
/// MST receipt unprotected header label: 396.
const VDP_HEADER_LABEL: i64 = 396;

/// Receipt proof label inside VDP map: -1.
const PROOF_LABEL: i64 = -1;

/// CWT (receipt) label for claims: 15.
const CWT_CLAIMS_LABEL: i64 = 15;
/// CWT issuer claim label: 1.
const CWT_ISS_LABEL: i64 = 1;

/// COSE alg: ES384.
const COSE_ALG_ES256: i64 = -7;
const COSE_ALG_ES384: i64 = -35;

/// MST VDS value observed for Microsoft Confidential Ledger receipts.
const MST_VDS_MICROSOFT_CCF: i64 = 2;

#[derive(Clone)]
pub struct ReceiptVerifyInput<'a> {
    pub statement_bytes_with_receipts: &'a [u8],
    pub receipt_bytes: &'a [u8],
    /// Offline JWKS JSON for Microsoft receipt issuers.
    pub offline_jwks_json: Option<&'a str>,

    /// If true, the verifier may fetch JWKS online when offline keys are missing.
    pub allow_network_fetch: bool,

    /// Optional api-version query value to use when fetching `/jwks`.
    /// The CodeTransparency service typically requires this.
    pub jwks_api_version: Option<&'a str>,

    /// Optional Code Transparency client for JWKS fetching.
    /// If `None` and `allow_network_fetch` is true, a default client is created.
    pub client: Option<&'a code_transparency_client::CodeTransparencyClient>,
}

#[derive(Clone, Debug)]
pub struct ReceiptVerifyOutput {
    pub trusted: bool,
    pub details: Option<String>,
    pub issuer: String,
    pub kid: String,
    pub statement_sha256: [u8; 32],
}

/// Verify a Microsoft Secure Transparency (MST) receipt for a COSE_Sign1 statement.
///
/// This implements the same high-level verification strategy as the Azure .NET verifier:
/// - Parse the receipt as COSE_Sign1.
/// - Resolve the signing key from JWKS (offline first; optional online fallback).
/// - Re-encode the signed statement with unprotected headers cleared and compute SHA-256.
/// - Validate an inclusion proof whose `data_hash` matches the statement digest.
/// - Verify the receipt signature over the COSE Sig_structure using the CCF accumulator.
pub fn verify_mst_receipt(
    input: ReceiptVerifyInput<'_>,
) -> Result<ReceiptVerifyOutput, ReceiptVerifyError> {
    let receipt = CoseSign1Message::parse(input.receipt_bytes)
        .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

    // Extract receipt headers using typed CoseHeaderMap accessors.
    let alg = receipt
        .protected
        .alg()
        .or_else(|| receipt.unprotected.alg())
        .ok_or(ReceiptVerifyError::MissingAlg)?;

    let kid_bytes = receipt
        .protected
        .kid()
        .or_else(|| receipt.unprotected.kid())
        .ok_or(ReceiptVerifyError::MissingKid)?;

    let kid = std::str::from_utf8(kid_bytes)
        .map_err(|_| ReceiptVerifyError::MissingKid)?
        .to_string();

    let vds = receipt
        .protected
        .get(&CoseHeaderLabel::Int(VDS_HEADER_LABEL))
        .and_then(|v| v.as_i64())
        .ok_or(ReceiptVerifyError::UnsupportedVds(-1))?;
    if vds != MST_VDS_MICROSOFT_CCF {
        return Err(ReceiptVerifyError::UnsupportedVds(vds));
    }

    let issuer = get_cwt_issuer_host(&receipt.protected, CWT_CLAIMS_LABEL, CWT_ISS_LABEL)
        .ok_or(ReceiptVerifyError::MissingIssuer)?;

    // Map the COSE alg to the expected ECDSA verifier.
    // Do this early so unsupported alg values are classified as UnsupportedAlg.
    let verifier = ring_verifier_for_cose_alg(alg)?;

    // Resolve the receipt signing key.
    // Match the Azure .NET client behavior (GetServiceCertificateKey):
    // - Try offline keys first (if provided)
    // - If missing and network fallback is allowed, fetch JWKS from https://{issuer}/jwks
    // - Lookup key by kid
    let jwk = resolve_receipt_signing_key(
        issuer.as_str(),
        kid.as_str(),
        input.offline_jwks_json,
        input.allow_network_fetch,
        input.jwks_api_version,
        input.client,
    )?;
    let spki = jwk_to_spki_der(&jwk)?;
    validate_receipt_alg_against_jwk(&jwk, alg)?;

    // VDP is unprotected header label 396.
    let vdp_value = receipt
        .unprotected
        .get(&CoseHeaderLabel::Int(VDP_HEADER_LABEL))
        .ok_or(ReceiptVerifyError::MissingVdp)?;
    let proof_blobs = extract_proof_blobs(vdp_value)?;

    // The .NET verifier computes claimsDigest = SHA256(signedStatementBytes)
    // where signedStatementBytes is the COSE_Sign1 statement with unprotected headers cleared.
    let signed_statement_bytes =
        reencode_statement_with_cleared_unprotected_headers(input.statement_bytes_with_receipts)?;
    let expected_data_hash = sha256(signed_statement_bytes.as_slice());

    // COSE encodes ECDSA signatures as the fixed-length concatenation r||s.
    // Use ring's FIXED verifiers to avoid having to re-encode to ASN.1 DER.
    let pk = signature::UnparsedPublicKey::new(verifier, spki.as_slice());

    let mut any_matching_data_hash = false;
    for proof_blob in proof_blobs {
        let proof = MstCcfInclusionProof::parse(proof_blob.as_slice())?;

        // Compute CCF accumulator (leaf hash) and fold proof path.
        // If the proof doesn't match this statement, try the next blob.
        let mut acc = match ccf_accumulator_sha256(&proof, expected_data_hash) {
            Ok(acc) => {
                any_matching_data_hash = true;
                acc
            }
            Err(ReceiptVerifyError::DataHashMismatch) => continue,
            Err(e) => return Err(e),
        };
        for (is_left, sibling) in proof.path.iter() {
            let sibling: [u8; 32] = sibling.as_slice().try_into().map_err(|_| {
                ReceiptVerifyError::ReceiptDecode("unexpected_path_hash_len".to_string())
            })?;

            acc = if *is_left {
                sha256_concat_slices(&sibling, &acc)
            } else {
                sha256_concat_slices(&acc, &sibling)
            };
        }

        let sig_structure = receipt
            .sig_structure_bytes(acc.as_slice(), None)
            .map_err(|e| ReceiptVerifyError::SigStructureEncode(e.to_string()))?;
        if pk
            .verify(sig_structure.as_slice(), receipt.signature.as_slice())
            .is_ok()
        {
            return Ok(ReceiptVerifyOutput {
                trusted: true,
                details: None,
                issuer,
                kid,
                statement_sha256: expected_data_hash,
            });
        }
    }

    if !any_matching_data_hash {
        return Err(ReceiptVerifyError::DataHashMismatch);
    }

    Err(ReceiptVerifyError::SignatureInvalid)
}

/// Compute SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    out.into()
}

/// Compute SHA-256 of the concatenation of two fixed-size digests.
pub fn sha256_concat_slices(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    let out = h.finalize();
    out.into()
}

/// Re-encode a COSE_Sign1 statement with *all* unprotected headers cleared.
///
/// MST receipts bind to the SHA-256 of these normalized statement bytes.
pub fn reencode_statement_with_cleared_unprotected_headers(
    statement_bytes: &[u8],
) -> Result<Vec<u8>, ReceiptVerifyError> {
    let was_tagged =
        is_cose_sign1_tagged_18(statement_bytes).map_err(ReceiptVerifyError::StatementReencode)?;

    let msg = CoseSign1Message::parse(statement_bytes)
        .map_err(|e| ReceiptVerifyError::StatementReencode(e.to_string()))?;

    // Match .NET verifier behavior: clear *all* unprotected headers.

    // Encode tag(18) if it was present.
    let mut enc = cose_sign1_primitives::provider::encoder();

    if was_tagged {
        // tag(18) is a single-byte CBOR tag header: 0xD2.
        enc.encode_tag(18)
            .map_err(|e| ReceiptVerifyError::StatementReencode(e.to_string()))?;
    }

    enc.encode_array(4)
        .map_err(|e| ReceiptVerifyError::StatementReencode(e.to_string()))?;

    // protected header bytes are a bstr (containing map bytes)
    enc.encode_bstr(msg.protected.as_bytes())
        .map_err(|e| ReceiptVerifyError::StatementReencode(e.to_string()))?;

    // unprotected header: empty map
    enc.encode_map(0)
        .map_err(|e| ReceiptVerifyError::StatementReencode(e.to_string()))?;

    // payload: bstr / nil
    match &msg.payload {
        Some(p) => enc.encode_bstr(p.as_slice()),
        None => enc.encode_null(),
    }
    .map_err(|e| ReceiptVerifyError::StatementReencode(e.to_string()))?;

    // signature: bstr
    enc.encode_bstr(msg.signature.as_slice())
        .map_err(|e| ReceiptVerifyError::StatementReencode(e.to_string()))?;

    Ok(enc.into_bytes())
}

/// Best-effort check for an initial CBOR tag 18 (COSE_Sign1).
pub fn is_cose_sign1_tagged_18(input: &[u8]) -> Result<bool, String> {
    let mut d = cose_sign1_primitives::provider::decoder(input);
    let typ = d.peek_type().map_err(|e| e.to_string())?;
    if typ != cbor_primitives::CborType::Tag {
        return Ok(false);
    }
    let tag = d.decode_tag().map_err(|e| e.to_string())?;
    Ok(tag == 18)
}

/// Resolve the receipt signing key by `kid`, using offline JWKS first and (optionally) online JWKS.
pub(crate) fn resolve_receipt_signing_key(
    issuer: &str,
    kid: &str,
    offline_jwks_json: Option<&str>,
    allow_network_fetch: bool,
    jwks_api_version: Option<&str>,
    client: Option<&code_transparency_client::CodeTransparencyClient>,
) -> Result<Jwk, ReceiptVerifyError> {
    if let Some(jwks_json) = offline_jwks_json {
        match find_jwk_for_kid(jwks_json, kid) {
            Ok(jwk) => return Ok(jwk),
            Err(ReceiptVerifyError::JwkNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }

    if !allow_network_fetch {
        return Err(ReceiptVerifyError::JwksParse(
            "MissingOfflineJwks".to_string(),
        ));
    }

    let jwks_json = fetch_jwks_for_issuer(issuer, jwks_api_version, client)?;
    find_jwk_for_kid(jwks_json.as_str(), kid)
}

/// Fetch the JWKS JSON for a receipt issuer using the Code Transparency client.
pub(crate) fn fetch_jwks_for_issuer(
    issuer_host_or_url: &str,
    jwks_api_version: Option<&str>,
    client: Option<&code_transparency_client::CodeTransparencyClient>,
) -> Result<String, ReceiptVerifyError> {
    if let Some(ct_client) = client {
        return ct_client.get_public_keys()
            .map_err(|e| ReceiptVerifyError::JwksFetch(e.to_string()));
    }

    // Create a temporary client for the issuer endpoint
    let base = if issuer_host_or_url.contains("://") {
        issuer_host_or_url.to_string()
    } else {
        format!("https://{issuer_host_or_url}")
    };

    let endpoint = url::Url::parse(&base)
        .map_err(|e| ReceiptVerifyError::JwksFetch(e.to_string()))?;

    let mut config = code_transparency_client::CodeTransparencyClientConfig::default();
    if let Some(v) = jwks_api_version {
        config.api_version = v.to_string();
    }

    let temp_client = code_transparency_client::CodeTransparencyClient::new(endpoint, config);
    temp_client.get_public_keys()
        .map_err(|e| ReceiptVerifyError::JwksFetch(e.to_string()))
}

#[derive(Clone, Debug)]
pub struct MstCcfInclusionProof {
    pub internal_txn_hash: Vec<u8>,
    pub internal_evidence: String,
    pub data_hash: Vec<u8>,
    pub path: Vec<(bool, Vec<u8>)>,
}

impl MstCcfInclusionProof {
    /// Parse an inclusion proof blob into a structured representation.
    pub fn parse(proof_blob: &[u8]) -> Result<Self, ReceiptVerifyError> {
        Self::parse_impl(proof_blob)
    }

    fn parse_impl(proof_blob: &[u8]) -> Result<Self, ReceiptVerifyError> {
        let mut d = cose_sign1_primitives::provider::decoder(proof_blob);
        let map_len = d
            .decode_map_len()
            .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

        let mut leaf_raw: Option<Vec<u8>> = None;
        let mut path: Option<Vec<(bool, Vec<u8>)>> = None;

        for _ in 0..map_len.unwrap_or(usize::MAX) {
            let k = d
                .decode_i64()
                .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;
            if k == 1 {
                leaf_raw = Some(
                    d.decode_raw()
                        .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?
                        .to_vec(),
                );
            } else if k == 2 {
                let v_raw = d
                    .decode_raw()
                    .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?
                    .to_vec();
                path = Some(parse_path(&v_raw)?);
            } else {
                // Skip unknown keys
                d.skip()
                    .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;
            }
        }

        let leaf_raw = leaf_raw.ok_or(ReceiptVerifyError::MissingProof)?;
        let (internal_txn_hash, internal_evidence, data_hash) = parse_leaf(leaf_raw.as_slice())?;

        Ok(Self {
            internal_txn_hash,
            internal_evidence,
            data_hash,
            path: path.ok_or(ReceiptVerifyError::MissingProof)?,
        })
    }
}

/// Parse a CCF proof leaf (array) into its components.
pub fn parse_leaf(leaf_bytes: &[u8]) -> Result<(Vec<u8>, String, Vec<u8>), ReceiptVerifyError> {
    let mut d = cose_sign1_primitives::provider::decoder(leaf_bytes);
    let _arr_len = d
        .decode_array_len()
        .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

    let internal_txn_hash = d
        .decode_bstr()
        .map_err(|e| {
            ReceiptVerifyError::ReceiptDecode(format!("leaf_missing_internal_txn_hash: {}", e))
        })?
        .to_vec();

    let internal_evidence = d
        .decode_tstr()
        .map_err(|e| {
            ReceiptVerifyError::ReceiptDecode(format!("leaf_missing_internal_evidence: {}", e))
        })?
        .to_string();

    let data_hash = d
        .decode_bstr()
        .map_err(|e| ReceiptVerifyError::ReceiptDecode(format!("leaf_missing_data_hash: {}", e)))?
        .to_vec();

    Ok((internal_txn_hash, internal_evidence, data_hash))
}

/// Parse a CCF proof path value into a sequence of (direction, sibling_hash) pairs.
pub fn parse_path(bytes: &[u8]) -> Result<Vec<(bool, Vec<u8>)>, ReceiptVerifyError> {
    let mut d = cose_sign1_primitives::provider::decoder(bytes);
    let arr_len = d
        .decode_array_len()
        .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

    let mut out = Vec::new();
    for _ in 0..arr_len.unwrap_or(usize::MAX) {
        let item_raw = d
            .decode_raw()
            .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?
            .to_vec();
        let mut vd = cose_sign1_primitives::provider::decoder(&item_raw);
        let _pair_len = vd
            .decode_array_len()
            .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

        let is_left = vd
            .decode_bool()
            .map_err(|e| ReceiptVerifyError::ReceiptDecode(format!("path_missing_dir: {}", e)))?;

        let bytes_item = vd
            .decode_bstr()
            .map_err(|e| ReceiptVerifyError::ReceiptDecode(format!("path_missing_hash: {}", e)))?
            .to_vec();

        out.push((is_left, bytes_item));
    }

    Ok(out)
}

/// Extract proof blobs from the parsed VDP header value (unprotected header 396).
///
/// The MST receipt places an array of proof blobs under label `-1` in the VDP map.
pub fn extract_proof_blobs(vdp_value: &CoseHeaderValue) -> Result<Vec<Vec<u8>>, ReceiptVerifyError> {
    let pairs = match vdp_value {
        CoseHeaderValue::Map(pairs) => pairs,
        _ => {
            return Err(ReceiptVerifyError::ReceiptDecode(
                "vdp_not_a_map".to_string(),
            ))
        }
    };

    for (label, value) in pairs {
        if *label != CoseHeaderLabel::Int(PROOF_LABEL) {
            continue;
        }

        let arr = match value {
            CoseHeaderValue::Array(arr) => arr,
            _ => {
                return Err(ReceiptVerifyError::ReceiptDecode(
                    "proof_not_array".to_string(),
                ))
            }
        };

        let mut out = Vec::new();
        for item in arr {
            match item {
                CoseHeaderValue::Bytes(b) => out.push(b.clone()),
                _ => {
                    return Err(ReceiptVerifyError::ReceiptDecode(
                        "proof_item_not_bstr".to_string(),
                    ))
                }
            }
        }
        if out.is_empty() {
            return Err(ReceiptVerifyError::MissingProof);
        }
        return Ok(out);
    }

    Err(ReceiptVerifyError::MissingProof)
}

/// Map a COSE alg value to ring's fixed-length ECDSA verifier.
pub fn ring_verifier_for_cose_alg(
    alg: i64,
) -> Result<&'static dyn ring::signature::VerificationAlgorithm, ReceiptVerifyError> {
    match alg {
        COSE_ALG_ES256 => Ok(&signature::ECDSA_P256_SHA256_FIXED),
        COSE_ALG_ES384 => Ok(&signature::ECDSA_P384_SHA384_FIXED),
        _ => Err(ReceiptVerifyError::UnsupportedAlg(alg)),
    }
}

/// Validate that the receipt `alg` is compatible with the JWK curve.
pub fn validate_receipt_alg_against_jwk(jwk: &Jwk, alg: i64) -> Result<(), ReceiptVerifyError> {
    let Some(crv) = jwk.crv.as_deref() else {
        return Err(ReceiptVerifyError::JwkUnsupported(
            "missing_crv".to_string(),
        ));
    };

    let ok = matches!(
        (crv, alg),
        ("P-256", COSE_ALG_ES256) | ("P-384", COSE_ALG_ES384)
    );

    if !ok {
        return Err(ReceiptVerifyError::JwkUnsupported(format!(
            "alg_curve_mismatch: alg={alg} crv={crv}"
        )));
    }
    Ok(())
}

/// Compute the CCF accumulator (leaf hash) for an inclusion proof.
///
/// This validates expected field sizes, checks that the proof's `data_hash` matches the statement
/// digest, and then hashes `internal_txn_hash || sha256(internal_evidence) || data_hash`.
pub fn ccf_accumulator_sha256(
    proof: &MstCcfInclusionProof,
    expected_data_hash: [u8; 32],
) -> Result<[u8; 32], ReceiptVerifyError> {
    if proof.internal_txn_hash.len() != 32 {
        return Err(ReceiptVerifyError::ReceiptDecode(format!(
            "unexpected_internal_txn_hash_len: {}",
            proof.internal_txn_hash.len()
        )));
    }
    if proof.data_hash.len() != 32 {
        return Err(ReceiptVerifyError::ReceiptDecode(format!(
            "unexpected_data_hash_len: {}",
            proof.data_hash.len()
        )));
    }
    if proof.data_hash.as_slice() != expected_data_hash.as_slice() {
        return Err(ReceiptVerifyError::DataHashMismatch);
    }

    let internal_evidence_hash = sha256(proof.internal_evidence.as_bytes());

    let mut h = Sha256::new();
    h.update(proof.internal_txn_hash.as_slice());
    h.update(internal_evidence_hash);
    h.update(expected_data_hash);
    let out = h.finalize();
    Ok(out.into())
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: Option<String>,
    pub kid: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
}

pub fn find_jwk_for_kid(jwks_json: &str, kid: &str) -> Result<Jwk, ReceiptVerifyError> {
    let jwks: Jwks = serde_json::from_str(jwks_json)
        .map_err(|e| ReceiptVerifyError::JwksParse(e.to_string()))?;

    for k in jwks.keys {
        if k.kid.as_deref() == Some(kid) {
            return Ok(k);
        }
    }

    Err(ReceiptVerifyError::JwkNotFound(kid.to_string()))
}

/// Convert an EC JWK (x/y coordinates) to an uncompressed SEC1 point.
///
/// This returns the byte format accepted by ring's ECDSA public key parser.
pub fn jwk_to_spki_der(jwk: &Jwk) -> Result<Vec<u8>, ReceiptVerifyError> {
    if jwk.kty != "EC" {
        return Err(ReceiptVerifyError::JwkUnsupported(format!(
            "kty={}",
            jwk.kty
        )));
    }

    let crv = jwk
        .crv
        .as_deref()
        .ok_or_else(|| ReceiptVerifyError::JwkUnsupported("missing_crv".to_string()))?;

    if crv != "P-384" && crv != "P-256" {
        return Err(ReceiptVerifyError::JwkUnsupported(format!(
            "unsupported_crv={crv}"
        )));
    }

    let x = jwk
        .x
        .as_deref()
        .ok_or_else(|| ReceiptVerifyError::JwkUnsupported("missing_x".to_string()))?;
    let y = jwk
        .y
        .as_deref()
        .ok_or_else(|| ReceiptVerifyError::JwkUnsupported("missing_y".to_string()))?;

    let x = base64url_decode(x)
        .map_err(|e| ReceiptVerifyError::JwkUnsupported(format!("x_decode_failed: {e}")))?;
    let y = base64url_decode(y)
        .map_err(|e| ReceiptVerifyError::JwkUnsupported(format!("y_decode_failed: {e}")))?;

    let expected_len = if crv == "P-256" { 32 } else { 48 };
    if x.len() != expected_len || y.len() != expected_len {
        return Err(ReceiptVerifyError::JwkUnsupported(format!(
            "unexpected_xy_len: x={} y={} expected={}",
            x.len(),
            y.len(),
            expected_len
        )));
    }

    let mut uncompressed = Vec::with_capacity(1 + x.len() + y.len());
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);

    // ring's ECDSA public key parsers accept the SEC1 uncompressed point format.
    Ok(uncompressed)
}

/// Extract the CWT issuer hostname from a protected header's CWT claims map.
///
/// CWT claims (label `cwt_claims_label`) is a nested CBOR map containing the
/// issuer (label `iss_label`) as a text string.
pub fn get_cwt_issuer_host(
    protected: &ProtectedHeader,
    cwt_claims_label: i64,
    iss_label: i64,
) -> Option<String> {
    let cwt_value = protected.get(&CoseHeaderLabel::Int(cwt_claims_label))?;
    match cwt_value {
        CoseHeaderValue::Map(pairs) => {
            for (label, value) in pairs {
                if *label == CoseHeaderLabel::Int(iss_label) {
                    return value.as_str().map(|s| s.to_string());
                }
            }
            None
        }
        _ => None,
    }
}
