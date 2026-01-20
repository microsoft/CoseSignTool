// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use base64::Engine;
use ring::signature;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tinycbor::{Encode, Encoder};
use url::Url;

use cose_sign1_validation::fluent::CoseSign1;

#[derive(Debug, thiserror::Error)]
pub enum ReceiptVerifyError {
    #[error("receipt_decode_failed: {0}")]
    ReceiptDecode(String),

    #[error("receipt_missing_alg")]
    MissingAlg,

    #[error("receipt_missing_kid")]
    MissingKid,

    #[error("unsupported_alg: {0}")]
    UnsupportedAlg(i64),

    #[error("unsupported_vds: {0}")]
    UnsupportedVds(i64),

    #[error("missing_vdp")]
    MissingVdp,

    #[error("missing_proof")]
    MissingProof,

    #[error("issuer_missing")]
    MissingIssuer,

    #[error("jwks_parse_failed: {0}")]
    JwksParse(String),

    #[error("jwks_fetch_failed: {0}")]
    JwksFetch(String),

    #[error("jwk_not_found_for_kid: {0}")]
    JwkNotFound(String),

    #[error("jwk_unsupported: {0}")]
    JwkUnsupported(String),

    #[error("statement_reencode_failed: {0}")]
    StatementReencode(String),

    #[error("sig_structure_encode_failed: {0}")]
    SigStructureEncode(String),

    #[error("data_hash_mismatch")]
    DataHashMismatch,

    #[error("signature_invalid")]
    SignatureInvalid,
}

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

/// COSE labels.
const COSE_ALG_LABEL: i64 = 1;
const COSE_KID_LABEL: i64 = 4;

/// COSE alg: ES384.
const COSE_ALG_ES256: i64 = -7;
const COSE_ALG_ES384: i64 = -35;

/// MST VDS value observed for Microsoft Confidential Ledger receipts.
const MST_VDS_MICROSOFT_CCF: i64 = 2;

#[derive(Clone, Debug)]
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
    let receipt = CoseSign1::from_cbor(input.receipt_bytes)
        .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

    // Parse receipt headers (int-keyed only; receipt protected header may include string keys).
    let protected =
        IntKeyedMap::parse(receipt.protected_header).map_err(ReceiptVerifyError::ReceiptDecode)?;
    let unprotected = IntKeyedMap::parse(receipt.unprotected_header.as_ref())
        .map_err(ReceiptVerifyError::ReceiptDecode)?;

    let alg = protected
        .get_i64(COSE_ALG_LABEL)
        .or_else(|| unprotected.get_i64(COSE_ALG_LABEL))
        .ok_or(ReceiptVerifyError::MissingAlg)?;

    let kid_bytes = protected
        .get_bstr(COSE_KID_LABEL)
        .or_else(|| unprotected.get_bstr(COSE_KID_LABEL))
        .ok_or(ReceiptVerifyError::MissingKid)?;

    let kid = std::str::from_utf8(kid_bytes.as_slice())
        .map_err(|_| ReceiptVerifyError::MissingKid)?
        .to_string();

    let vds = protected
        .get_i64(VDS_HEADER_LABEL)
        .ok_or(ReceiptVerifyError::UnsupportedVds(-1))?;
    if vds != MST_VDS_MICROSOFT_CCF {
        return Err(ReceiptVerifyError::UnsupportedVds(vds));
    }

    let issuer = protected
        .get_cwt_issuer_host(CWT_CLAIMS_LABEL, CWT_ISS_LABEL)
        .ok_or(ReceiptVerifyError::MissingIssuer)?;

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
    )?;
    validate_receipt_alg_against_jwk(&jwk, alg)?;
    let spki = jwk_to_spki_der(&jwk)?;

    // VDP is unprotected header label 396.
    let vdp_bytes = unprotected
        .get_raw(VDP_HEADER_LABEL)
        .ok_or(ReceiptVerifyError::MissingVdp)?;
    let proof_blobs = read_proof_blobs(vdp_bytes.as_slice())?;

    // The .NET verifier computes claimsDigest = SHA256(signedStatementBytes)
    // where signedStatementBytes is the COSE_Sign1 statement with unprotected headers cleared.
    let signed_statement_bytes =
        reencode_statement_with_cleared_unprotected_headers(input.statement_bytes_with_receipts)?;
    let expected_data_hash = sha256(signed_statement_bytes.as_slice());

    // COSE encodes ECDSA signatures as the fixed-length concatenation r||s.
    // Use ring's FIXED verifiers to avoid having to re-encode to ASN.1 DER.
    let verifier = ring_verifier_for_cose_alg(alg)?;
    let pk = signature::UnparsedPublicKey::new(verifier, spki.as_slice());

    for proof_blob in proof_blobs {
        let proof = MstCcfInclusionProof::parse(proof_blob.as_slice())?;

        if proof.data_hash.as_slice() != expected_data_hash.as_slice() {
            continue;
        }

        // Compute CCF accumulator (leaf hash) and fold proof path.
        let mut acc = ccf_accumulator_sha256(&proof, expected_data_hash)?;
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

        let sig_structure =
            build_sig_structure(receipt.protected_header, acc.as_slice())?;
        if pk
            .verify(sig_structure.as_slice(), receipt.signature)
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

    Err(ReceiptVerifyError::SignatureInvalid)
}

/// Compute SHA-256 of `bytes`.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    out.into()
}

/// Compute SHA-256 of the concatenation of two fixed-size digests.
fn sha256_concat_slices(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    let out = h.finalize();
    out.into()
}

/// Build the COSE Sig_structure for a detached payload.
///
/// For MST receipts, the detached payload is the CCF accumulator (a SHA-256 digest), and the
/// protected header bytes are taken verbatim from the receipt.
fn build_sig_structure(
    protected_header_bytes: &[u8],
    detached_payload: &[u8],
) -> Result<Vec<u8>, ReceiptVerifyError> {
    // Sig_structure = [ "Signature1", body_protected, external_aad, payload ]
    let mut buf = vec![0u8; protected_header_bytes.len() + detached_payload.len() + 256];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.array(4)
        .map_err(|e| ReceiptVerifyError::SigStructureEncode(e.to_string()))?;
    "Signature1"
        .encode(&mut enc)
        .map_err(|e| ReceiptVerifyError::SigStructureEncode(e.to_string()))?;
    protected_header_bytes
        .encode(&mut enc)
        .map_err(|e| ReceiptVerifyError::SigStructureEncode(e.to_string()))?;
    b""
        .as_slice()
        .encode(&mut enc)
        .map_err(|e| ReceiptVerifyError::SigStructureEncode(e.to_string()))?;
    detached_payload
        .encode(&mut enc)
        .map_err(|e| ReceiptVerifyError::SigStructureEncode(e.to_string()))?;

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    Ok(buf)
}

/// Re-encode a COSE_Sign1 statement with *all* unprotected headers cleared.
///
/// MST receipts bind to the SHA-256 of these normalized statement bytes.
fn reencode_statement_with_cleared_unprotected_headers(
    statement_bytes: &[u8],
) -> Result<Vec<u8>, ReceiptVerifyError> {
    let was_tagged =
        is_cose_sign1_tagged_18(statement_bytes).map_err(ReceiptVerifyError::StatementReencode)?;

    let msg = CoseSign1::from_cbor(statement_bytes)
        .map_err(|e| ReceiptVerifyError::StatementReencode(e.to_string()))?;

    // Match .NET verifier behavior: clear *all* unprotected headers.

    // Encode tag(18) if it was present.
    let mut buf = vec![0u8; statement_bytes.len() + 128];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    if was_tagged {
        // tag(18) is a single-byte CBOR tag header: 0xD2.
        let remaining = std::mem::take(&mut enc.0);
        let (head, tail) = remaining.split_at_mut(1);
        head[0] = 0xD2;
        enc.0 = tail;
    }

    enc.array(4)
        .map_err(|e| ReceiptVerifyError::StatementReencode(e.to_string()))?;

    // protected header bytes are a bstr (containing map bytes)
    msg.protected_header
        .encode(&mut enc)
        .map_err(|e| ReceiptVerifyError::StatementReencode(e.to_string()))?;

    // unprotected header: empty map
    enc.map(0)
        .map_err(|e| ReceiptVerifyError::StatementReencode(e.to_string()))?;

    // payload: bstr / nil
    msg.payload
        .encode(&mut enc)
        .map_err(|e| ReceiptVerifyError::StatementReencode(e.to_string()))?;

    // signature: bstr
    msg.signature
        .encode(&mut enc)
        .map_err(|e| ReceiptVerifyError::StatementReencode(e.to_string()))?;

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    Ok(buf)
}

/// Best-effort check for an initial CBOR tag 18 (COSE_Sign1).
fn is_cose_sign1_tagged_18(input: &[u8]) -> Result<bool, String> {
    let first = match input.first() {
        Some(b) => *b,
        None => return Ok(false),
    };

    let major = first >> 5;
    if major != 6 {
        return Ok(false);
    }

    // Tag encoding.
    let ai = first & 0x1f;
    let (tag, _used) = decode_cbor_uint_value(ai, &input[1..])
        .ok_or_else(|| "invalid CBOR tag encoding".to_string())?;
    Ok(tag == 18)
}

/// Decode a CBOR-encoded integer and require that it fully consumes `bytes`.
fn decode_cbor_i64_one(bytes: &[u8]) -> Option<i64> {
    decode_cbor_i64(bytes).map(|(n, _used)| n)
}

/// Decode a CBOR-encoded signed integer.
///
/// Returns `(value, bytes_consumed)`.
fn decode_cbor_i64(bytes: &[u8]) -> Option<(i64, usize)> {
    let first = *bytes.first()?;
    let major = first >> 5;
    let ai = first & 0x1f;

    let (unsigned, used) = decode_cbor_uint_value(ai, &bytes[1..])?;

    match major {
        0 => i64::try_from(unsigned).ok().map(|v| (v, 1 + used)),
        1 => {
            let n = i64::try_from(unsigned).ok()?;
            Some((-1 - n, 1 + used))
        }
        _ => None,
    }
}

/// Decode the unsigned integer value for a CBOR additional-information (AI) field.
///
/// Returns `(value, bytes_consumed_from_rest)`.
fn decode_cbor_uint_value(ai: u8, rest: &[u8]) -> Option<(u64, usize)> {
    match ai {
        0..=23 => Some((ai as u64, 0)),
        24 => Some((u64::from(*rest.first()?), 1)),
        25 => {
            let b = rest.get(0..2)?;
            Some((u16::from_be_bytes([b[0], b[1]]) as u64, 2))
        }
        26 => {
            let b = rest.get(0..4)?;
            Some((u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64, 4))
        }
        27 => {
            let b = rest.get(0..8)?;
            Some((
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
                8,
            ))
        }
        _ => None,
    }
}

/// Resolve the receipt signing key by `kid`, using offline JWKS first and (optionally) online JWKS.
fn resolve_receipt_signing_key(
    issuer: &str,
    kid: &str,
    offline_jwks_json: Option<&str>,
    allow_network_fetch: bool,
    jwks_api_version: Option<&str>,
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

    let jwks_json = fetch_jwks_for_issuer(issuer, jwks_api_version)?;
    find_jwk_for_kid(jwks_json.as_str(), kid)
}

/// Fetch the JWKS JSON for a receipt issuer.
///
/// The issuer may be a host or a full URL; it is normalized to a base URL and `/jwks` is fetched.
fn fetch_jwks_for_issuer(
    issuer_host_or_url: &str,
    jwks_api_version: Option<&str>,
) -> Result<String, ReceiptVerifyError> {
    // C# builds a client for each issuer using https://{issuer}.
    // The receipt issuer can be a host or a URL; normalize to a URL.
    let base = if issuer_host_or_url.contains("://") {
        issuer_host_or_url.to_string()
    } else {
        format!("https://{issuer_host_or_url}")
    };

    let mut url =
        Url::parse(base.as_str()).map_err(|e| ReceiptVerifyError::JwksFetch(e.to_string()))?;
    url.set_path("/jwks");
    url.set_query(None);
    if let Some(v) = jwks_api_version {
        url.query_pairs_mut().append_pair("api-version", v);
    }

    let resp = ureq::get(url.as_str())
        .set("Accept", "application/json")
        .timeout(Duration::from_secs(10))
        .call();

    match resp {
        Ok(r) => {
            if r.status() != 200 {
                return Err(ReceiptVerifyError::JwksFetch(format!(
                    "http_status_{}",
                    r.status()
                )));
            }
            r.into_string()
                .map_err(|e| ReceiptVerifyError::JwksFetch(e.to_string()))
        }
        Err(ureq::Error::Status(code, r)) => {
            let body = r.into_string().unwrap_or_default();
            Err(ReceiptVerifyError::JwksFetch(format!(
                "http_status_{code}: {body}"
            )))
        }
        Err(e) => Err(ReceiptVerifyError::JwksFetch(e.to_string())),
    }
}

#[derive(Clone, Debug)]
struct MstCcfInclusionProof {
    internal_txn_hash: Vec<u8>,
    internal_evidence: String,
    data_hash: Vec<u8>,
    path: Vec<(bool, Vec<u8>)>,
}

impl MstCcfInclusionProof {
    /// Parse an inclusion proof blob into a structured representation.
    fn parse(proof_blob: &[u8]) -> Result<Self, ReceiptVerifyError> {
        let mut d = tinycbor::Decoder(proof_blob);
        let mut map = d
            .map_visitor()
            .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

        let mut leaf_raw: Option<Vec<u8>> = None;
        let mut path: Option<Vec<(bool, Vec<u8>)>> = None;

        while let Some(entry) = map.visit::<i64, tinycbor::Any<'_>>() {
            let (k, v_any) = entry.map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;
            if k == 1 {
                leaf_raw = Some(v_any.as_ref().to_vec());
            } else if k == 2 {
                path = Some(parse_path(v_any.as_ref())?);
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
fn parse_leaf(leaf_bytes: &[u8]) -> Result<(Vec<u8>, String, Vec<u8>), ReceiptVerifyError> {
    let mut d = tinycbor::Decoder(leaf_bytes);
    let mut arr = d
        .array_visitor()
        .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

    let internal_txn_hash = arr
        .visit::<&[u8]>()
        .ok_or_else(|| {
            ReceiptVerifyError::ReceiptDecode("leaf_missing_internal_txn_hash".to_string())
        })?
        .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?
        .to_vec();

    let internal_evidence = arr
        .visit::<String>()
        .ok_or_else(|| {
            ReceiptVerifyError::ReceiptDecode("leaf_missing_internal_evidence".to_string())
        })?
        .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

    let data_hash = arr
        .visit::<&[u8]>()
        .ok_or_else(|| ReceiptVerifyError::ReceiptDecode("leaf_missing_data_hash".to_string()))?
        .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?
        .to_vec();

    Ok((internal_txn_hash, internal_evidence, data_hash))
}

/// Parse a CCF proof path value into a sequence of (direction, sibling_hash) pairs.
fn parse_path(bytes: &[u8]) -> Result<Vec<(bool, Vec<u8>)>, ReceiptVerifyError> {
    let mut d = tinycbor::Decoder(bytes);
    let mut arr = d
        .array_visitor()
        .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

    let mut out = Vec::new();
    while let Some(item) = arr.visit::<tinycbor::Any<'_>>() {
        let any = item.map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;
        let mut vd = tinycbor::Decoder(any.as_ref());
        let mut pair = vd
            .array_visitor()
            .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

        let is_left = pair
            .visit::<bool>()
            .ok_or_else(|| ReceiptVerifyError::ReceiptDecode("path_missing_dir".to_string()))?
            .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

        let bytes_item = pair
            .visit::<&[u8]>()
            .ok_or_else(|| ReceiptVerifyError::ReceiptDecode("path_missing_hash".to_string()))?
            .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

        out.push((is_left, bytes_item.to_vec()));
    }

    Ok(out)
}

/// Extract proof blobs from the VDP map (unprotected header 396).
///
/// The MST receipt places an array of proof blobs under label `-1`.
fn read_proof_blobs(vdp_bytes: &[u8]) -> Result<Vec<Vec<u8>>, ReceiptVerifyError> {
    let mut d = tinycbor::Decoder(vdp_bytes);
    let mut map = d
        .map_visitor()
        .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

    while let Some(entry) = map.visit::<i64, tinycbor::Any<'_>>() {
        let (k, v_any) = entry.map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;
        if k != PROOF_LABEL {
            continue;
        }

        let mut vd = tinycbor::Decoder(v_any.as_ref());
        let mut arr = vd
            .array_visitor()
            .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?;

        let mut out = Vec::new();
        while let Some(item) = arr.visit::<&[u8]>() {
            let bytes = item
                .map_err(|e| ReceiptVerifyError::ReceiptDecode(e.to_string()))?
                .to_vec();
            out.push(bytes);
        }
        if out.is_empty() {
            return Err(ReceiptVerifyError::MissingProof);
        }
        return Ok(out);
    }

    Err(ReceiptVerifyError::MissingProof)
}

/// Map a COSE alg value to ring's fixed-length ECDSA verifier.
fn ring_verifier_for_cose_alg(
    alg: i64,
) -> Result<&'static dyn ring::signature::VerificationAlgorithm, ReceiptVerifyError> {
    match alg {
        COSE_ALG_ES256 => Ok(&signature::ECDSA_P256_SHA256_FIXED),
        COSE_ALG_ES384 => Ok(&signature::ECDSA_P384_SHA384_FIXED),
        _ => Err(ReceiptVerifyError::UnsupportedAlg(alg)),
    }
}

/// Validate that the receipt `alg` is compatible with the JWK curve.
fn validate_receipt_alg_against_jwk(jwk: &Jwk, alg: i64) -> Result<(), ReceiptVerifyError> {
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
fn ccf_accumulator_sha256(
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
struct Jwk {
    kty: String,
    crv: Option<String>,
    kid: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

fn find_jwk_for_kid(jwks_json: &str, kid: &str) -> Result<Jwk, ReceiptVerifyError> {
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
fn jwk_to_spki_der(jwk: &Jwk) -> Result<Vec<u8>, ReceiptVerifyError> {
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

    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let x = engine
        .decode(x)
        .map_err(|e| ReceiptVerifyError::JwkUnsupported(format!("x_decode_failed: {e}")))?;
    let y = engine
        .decode(y)
        .map_err(|e| ReceiptVerifyError::JwkUnsupported(format!("y_decode_failed: {e}")))?;

    let expected_len = match crv {
        "P-256" => 32,
        "P-384" => 48,
        _ => unreachable!(),
    };
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

#[derive(Clone, Debug, Default)]
struct IntKeyedMap {
    entries: std::collections::BTreeMap<i64, Vec<u8>>,
}

impl IntKeyedMap {
    /// Parse a CBOR map and retain only integer keys.
    ///
    /// Values are stored as their original encoded CBOR bytes.
    fn parse(map_bytes: &[u8]) -> Result<Self, String> {
        let mut d = tinycbor::Decoder(map_bytes);
        let mut map = d.map_visitor().map_err(|e| e.to_string())?;

        let mut entries = std::collections::BTreeMap::new();

        // Key type can be int or text; we only keep int keys.
        while let Some(entry) = map.visit::<tinycbor::Any<'_>, tinycbor::Any<'_>>() {
            let (k_any, v_any) = entry.map_err(|e| e.to_string())?;
            let k = {
                let kb = k_any.as_ref();
                decode_cbor_i64_one(kb)
            };
            if let Some(k) = k {
                entries.insert(k, v_any.as_ref().to_vec());
            }
        }

        Ok(Self { entries })
    }

    /// Return the raw CBOR bytes for `label`.
    fn get_raw(&self, label: i64) -> Option<Vec<u8>> {
        self.entries.get(&label).cloned()
    }

    /// Decode the value at `label` as a CBOR integer.
    fn get_i64(&self, label: i64) -> Option<i64> {
        self.entries
            .get(&label)
            .and_then(|b| decode_cbor_i64_one(b.as_slice()))
    }

    /// Decode the value at `label` as a CBOR bstr (including indefinite-length bstr).
    fn get_bstr(&self, label: i64) -> Option<Vec<u8>> {
        let bytes = self.entries.get(&label)?;
        let mut d = tinycbor::Decoder(bytes.as_slice());
        let it = d.bytes_iter().ok()?;
        let mut out = Vec::new();
        for part in it {
            out.extend_from_slice(part.ok()?);
        }
        Some(out)
    }

    /// Read the CWT `iss` claim value and return it as a string.
    ///
    /// This helper assumes the CWT claims are stored under `cwt_claims_label` in a CBOR map and
    /// that `iss_label` is an integer key whose value is a CBOR text string.
    fn get_cwt_issuer_host(&self, cwt_claims_label: i64, iss_label: i64) -> Option<String> {
        let cwt_bytes = self.entries.get(&cwt_claims_label)?;
        let mut d = tinycbor::Decoder(cwt_bytes.as_slice());
        let mut map = d.map_visitor().ok()?;
        while let Some(entry) = map.visit::<i64, tinycbor::Any<'_>>() {
            let (k, v_any) = entry.ok()?;
            if k != iss_label {
                continue;
            }
            let mut vd = tinycbor::Decoder(v_any.as_ref());
            let s = <String as tinycbor::Decode>::decode(&mut vd).ok()?;
            return Some(s);
        }
        None
    }
}
