// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE_Sign1 signature verification.
//!
//! This module provides the core verification path used by the Rust port:
//! - Parse COSE_Sign1 bytes into structured fields.
//! - Determine the COSE `alg` header.
//! - Build the COSE Sig_structure to be verified.
//! - Verify the signature using the provided public key material.
//!
//! Public key inputs are intentionally flexible to support common calling patterns:
//! - DER X.509 certificate (the SubjectPublicKeyInfo is extracted)
//! - DER SubjectPublicKeyInfo (SPKI)
//! - Algorithm-specific raw public key bytes (ML-DSA only)
//!
//! Notes:
//! - This verifier is intentionally strict about required inputs (e.g., public key bytes).
//! - For detached payload COSE_Sign1, callers must provide the external payload.

use cosesign1_common::{encode_signature1_sig_structure, parse_cose_sign1, ParsedCoseSign1};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use rsa::pkcs1v15;
use rsa::pss;
use rsa::pkcs8::DecodePublicKey as _;
use rsa::RsaPublicKey;
use sha2::Sha256;
use signature::Verifier;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use x509_parser::prelude::FromDer as _;

use crate::validation_result::ValidationResult;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(i64)]
pub enum CoseAlgorithm {
    /// ECDSA w/ SHA-256 over P-256.
    ES256 = -7,
    /// ECDSA w/ SHA-384 over P-384.
    ES384 = -35,
    /// ECDSA w/ SHA-512 over P-521.
    ES512 = -36,
    // Provisional COSE algorithm IDs used by this repo for ML-DSA (post-quantum).
    /// ML-DSA-44 (provisional COSE alg id used by this repo).
    MLDsa44 = -48,
    /// ML-DSA-65 (provisional COSE alg id used by this repo).
    MLDsa65 = -49,
    /// ML-DSA-87 (provisional COSE alg id used by this repo).
    MLDsa87 = -50,
    /// RSASSA-PSS w/ SHA-256.
    PS256 = -37,
    /// RSASSA-PKCS1v1.5 w/ SHA-256.
    RS256 = -257,
}

#[derive(Default, Clone)]
pub struct VerifyOptions {
    /// External payload bytes.
    ///
    /// COSE_Sign1 supports “detached content” where the payload is not embedded.
    /// In that case, verification requires passing the payload bytes via this field.
    pub external_payload: Option<Vec<u8>>,

    /// Public key input bytes.
    ///
    /// Accepted encodings depend on algorithm:
    /// - ECDSA/RSA: DER SPKI or DER X.509 certificate.
    /// - ML-DSA: raw encoded verifying key bytes OR DER SPKI/cert (subjectPublicKey extracted).
    pub public_key_bytes: Option<Vec<u8>>,

    /// If set, verification fails unless the COSE `alg` header equals this value.
    pub expected_alg: Option<CoseAlgorithm>,
}

/// Verify a COSE_Sign1 byte array.
///
/// This is the typical entry point:
/// - Parses the COSE bytes.
/// - Selects the payload bytes (embedded or external).
/// - Delegates to `verify_parsed_cose_sign1`.
pub fn verify_cose_sign1(validator_name: &str, cose_sign1: &[u8], options: &VerifyOptions) -> ValidationResult {
    // Parse the outer COSE_Sign1 structure and headers.
    let parsed = match parse_cose_sign1(cose_sign1) {
        Ok(p) => p,
        Err(e) => return ValidationResult::failure_message(validator_name, e, Some("COSE_PARSE_ERROR".to_string())),
    };

    // Determine the payload bytes that will be signed.
    // - Prefer an explicit external payload provided by the caller.
    // - Otherwise use the embedded payload (if present).
    let external = options
        .external_payload
        .as_deref()
        .or_else(|| parsed.payload.as_deref());

    verify_parsed_cose_sign1(validator_name, &parsed, external, options)
}

/// Verify a previously parsed COSE_Sign1.
///
/// This function implements the core verification flow:
/// 1) Resolve `alg` (from protected headers first, then unprotected).
/// 2) Optionally enforce the expected `alg`.
/// 3) Build the Sig_structure bytes.
/// 4) Verify the signature against the caller-provided public key bytes.
pub fn verify_parsed_cose_sign1(
    validator_name: &str,
    parsed: &ParsedCoseSign1,
    external_payload: Option<&[u8]>,
    options: &VerifyOptions,
) -> ValidationResult {
    // COSE specifies `alg` in either protected or unprotected header maps.
    // We require it and reject missing/invalid values.
    let alg = match cose_alg(parsed) {
        Ok(a) => a,
        Err(e) => return ValidationResult::failure_message(validator_name, e, Some("MISSING_OR_INVALID_ALG".to_string())),
    };

    // Optional hardening: allow the caller to require a specific algorithm.
    // This is useful when the algorithm is known out-of-band and prevents “alg confusion”.
    if let Some(expected) = options.expected_alg {
        if expected != alg {
            return ValidationResult::failure_message(
                validator_name,
                format!("alg header mismatch: expected {expected:?}, got {alg:?}"),
                Some("ALG_MISMATCH".to_string()),
            );
        }
    }

    // COSE signature verification is performed over a canonical Sig_structure.
    // The Sig_structure includes protected headers and (embedded or external) payload.
    let sig_structure = match encode_signature1_sig_structure(parsed, external_payload) {
        Ok(b) => b,
        Err(e) => return ValidationResult::failure_message(validator_name, e, Some("SIGSTRUCT_ERROR".to_string())),
    };

    // This verifier currently requires callers to supply the public key bytes.
    // (Future plugins/verifiers may support extracting keys from x5c or other sources.)
    let key_bytes = match options.public_key_bytes.as_deref() {
        Some(k) => k,
        None => {
            return ValidationResult::failure_message(
                validator_name,
                "public key bytes not provided",
                Some("MISSING_PUBLIC_KEY".to_string()),
            )
        }
    };

    // Dispatch to the per-algorithm verifier.
    match verify_signature(alg, key_bytes, &sig_structure, &parsed.signature) {
        Ok(()) => ValidationResult::success(validator_name, Default::default()),
        Err((code, msg)) => ValidationResult::failure_message(validator_name, msg, Some(code)),
    }
}

/// Extract the COSE `alg` header from the parsed structure.
///
/// COSE label `1` is the standard header parameter for algorithm.
/// We check protected headers first (preferred), then unprotected.
fn cose_alg(parsed: &ParsedCoseSign1) -> Result<CoseAlgorithm, String> {
    // COSE alg header label is 1.
    let v = parsed
        .protected_headers
        .get_i64(1)
        .or_else(|| parsed.unprotected_headers.get_i64(1))
        .ok_or_else(|| "missing alg header".to_string())?;

    match v {
        -7 => Ok(CoseAlgorithm::ES256),
        -35 => Ok(CoseAlgorithm::ES384),
        -36 => Ok(CoseAlgorithm::ES512),
        -48 => Ok(CoseAlgorithm::MLDsa44),
        -49 => Ok(CoseAlgorithm::MLDsa65),
        -50 => Ok(CoseAlgorithm::MLDsa87),
        -37 => Ok(CoseAlgorithm::PS256),
        -257 => Ok(CoseAlgorithm::RS256),
        _ => Err(format!("unsupported alg: {v}")),
    }
}

/// Verify a COSE signature for a given COSE algorithm id.
///
/// `sig_structure` is the exact byte array that must be verified per RFC 8152.
/// `cose_signature` is the signature byte string from the COSE_Sign1 structure.
fn verify_signature(
    alg: CoseAlgorithm,
    public_key_bytes: &[u8],
    sig_structure: &[u8],
    cose_signature: &[u8],
) -> Result<(), (String, String)> {
    match alg {
        CoseAlgorithm::ES256 => verify_ecdsa_p256(public_key_bytes, sig_structure, cose_signature),
        CoseAlgorithm::ES384 => verify_ecdsa_p384(public_key_bytes, sig_structure, cose_signature),
        CoseAlgorithm::ES512 => verify_ecdsa_p521(public_key_bytes, sig_structure, cose_signature),
        CoseAlgorithm::RS256 => verify_rsa_pkcs1(public_key_bytes, sig_structure, cose_signature),
        CoseAlgorithm::PS256 => verify_rsa_pss(public_key_bytes, sig_structure, cose_signature),
        CoseAlgorithm::MLDsa44 => {
            // When key material is DER SPKI/cert, we can sanity check the SPKI algorithm OID
            // to ensure the caller didn't accidentally provide a mismatched key.
            verify_ml_dsa::<MlDsa44>(public_key_bytes, sig_structure, cose_signature, Some("2.16.840.1.101.3.4.3.17"))
        }
        CoseAlgorithm::MLDsa65 => {
            verify_ml_dsa::<MlDsa65>(public_key_bytes, sig_structure, cose_signature, Some("2.16.840.1.101.3.4.3.18"))
        }
        CoseAlgorithm::MLDsa87 => {
            verify_ml_dsa::<MlDsa87>(public_key_bytes, sig_structure, cose_signature, Some("2.16.840.1.101.3.4.3.19"))
        }
    }
}

/// Verify an ML-DSA signature.
///
/// ML-DSA keys are carried in different encodings depending on context:
/// - Raw encoded verifying key bytes (what `ml-dsa` expects for `EncodedVerifyingKey`)
/// - DER SPKI or DER X.509 certificate (we extract `subjectPublicKey` BIT STRING)
///
/// If `expected_spki_oid` is provided and we successfully parse a cert/SPKI,
/// we validate the algorithm OID to reduce key/algorithm mismatches.
fn verify_ml_dsa<P: ml_dsa::MlDsaParams>(
    public_key_bytes: &[u8],
    msg: &[u8],
    sig: &[u8],
    expected_spki_oid: Option<&'static str>,
) -> Result<(), (String, String)> {
    // Extract the raw ML-DSA public key bytes.
    // When parsing DER cert/SPKI, we also capture the public key algorithm OID.
    let (encoded_vk_bytes, spki_oid) = extract_ml_dsa_public_key_bytes_and_oid(public_key_bytes)
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), e))?;

    if let (Some(expected), Some(oid)) = (expected_spki_oid, spki_oid.as_deref()) {
        // Only check OID when we were able to parse cert/SPKI.
        if oid != expected {
            return Err((
                "INVALID_PUBLIC_KEY".to_string(),
                format!("unexpected public key algorithm OID: expected {expected}, got {oid}"),
            ));
        }
    }

    // `ml-dsa` represents the public key in a compact encoded format.
    // We validate the encoding and then decode into a verifying key.
    let enc_vk = ml_dsa::EncodedVerifyingKey::<P>::try_from(encoded_vk_bytes.as_slice())
        .map_err(|_| ("INVALID_PUBLIC_KEY".to_string(), "bad ML-DSA public key bytes".to_string()))?;
    let vk = ml_dsa::VerifyingKey::<P>::decode(&enc_vk);

    // Parse and validate the signature byte representation.
    let signature = ml_dsa::Signature::<P>::try_from(sig)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "bad ML-DSA signature bytes".to_string()))?;

    // Perform cryptographic signature verification.
    vk.verify(msg, &signature)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "signature verification failed".to_string()))
}

/// Extract ML-DSA public key bytes from either DER cert/SPKI or raw key bytes.
///
/// Returns:
/// - The raw public key bytes that `ml-dsa` expects.
/// - Optionally the parsed public key algorithm OID when DER decoding succeeded.
fn extract_ml_dsa_public_key_bytes_and_oid(der_or_raw: &[u8]) -> Result<(Vec<u8>, Option<String>), String> {
    // Accept:
    // - DER X.509 certificate
    // - DER SubjectPublicKeyInfo
    // - Raw ML-DSA encoded verifying key bytes
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(der_or_raw) {
        // If this is a certificate, use the certificate's SubjectPublicKeyInfo.
        let spki = &cert.tbs_certificate.subject_pki;
        let oid = Some(spki.algorithm.algorithm.to_string());
        let pk = spki.subject_public_key.data.to_vec();
        return Ok((pk, oid));
    }

    if let Ok((_, spki)) = x509_parser::x509::SubjectPublicKeyInfo::from_der(der_or_raw) {
        // If this is an SPKI, extract the BIT STRING public key bytes.
        let oid = Some(spki.algorithm.algorithm.to_string());
        let pk = spki.subject_public_key.data.to_vec();
        return Ok((pk, oid));
    }

    // Otherwise treat the input as raw key bytes.
    Ok((der_or_raw.to_vec(), None))
}

/// Helper: normalize ECDSA/RSA public key inputs.
///
/// For ECDSA and RSA we primarily operate on DER SubjectPublicKeyInfo.
/// If the caller supplies a DER certificate instead, we extract the SPKI DER.
fn extract_spki_der_from_der_key_or_cert(der: &[u8]) -> Result<Vec<u8>, (String, String)> {
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) {
        // `raw` is the DER encoding of the SPKI structure inside the certificate.
        return Ok(cert.tbs_certificate.subject_pki.raw.to_vec());
    }
    // Assume the input is already SPKI DER.
    Ok(der.to_vec())
}

/// Verify ES256 (P-256 ECDSA).
fn verify_ecdsa_p256(pub_bytes: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), (String, String)> {
    // Normalize input into SPKI DER, then decode into the curve public key type.
    let spki = extract_spki_der_from_der_key_or_cert(pub_bytes)?;
    let pk = p256::PublicKey::from_public_key_der(&spki)
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-256 public key: {e}")))?;

    // Convert to SEC1 encoded point bytes expected by the ECDSA verifying key.
    let ep = pk.to_encoded_point(false);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(ep.as_bytes())
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-256 public key: {e}")))?;

    // COSE carries ECDSA signatures as the raw `r || s` concatenation.
    let signature = p256::ecdsa::Signature::from_slice(sig)
        .map_err(|e| ("BAD_SIGNATURE".to_string(), format!("bad ES256 signature: {e}")))?;
    vk.verify(msg, &signature)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "signature verification failed".to_string()))
}

/// Verify ES384 (P-384 ECDSA).
fn verify_ecdsa_p384(pub_bytes: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), (String, String)> {
    let spki = extract_spki_der_from_der_key_or_cert(pub_bytes)?;
    let pk = p384::PublicKey::from_public_key_der(&spki)
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-384 public key: {e}")))?;
    let ep = pk.to_encoded_point(false);
    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(ep.as_bytes())
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-384 public key: {e}")))?;
    let signature = p384::ecdsa::Signature::from_slice(sig)
        .map_err(|e| ("BAD_SIGNATURE".to_string(), format!("bad ES384 signature: {e}")))?;
    vk.verify(msg, &signature)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "signature verification failed".to_string()))
}

/// Verify ES512 (P-521 ECDSA).
fn verify_ecdsa_p521(pub_bytes: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), (String, String)> {
    let spki = extract_spki_der_from_der_key_or_cert(pub_bytes)?;
    let pk = p521::PublicKey::from_public_key_der(&spki)
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-521 public key: {e}")))?;
    let ep = pk.to_encoded_point(false);
    let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(ep.as_bytes())
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-521 public key: {e}")))?;
    let signature = p521::ecdsa::Signature::from_slice(sig)
        .map_err(|e| ("BAD_SIGNATURE".to_string(), format!("bad ES512 signature: {e}")))?;
    vk.verify(msg, &signature)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "signature verification failed".to_string()))
}

/// Decode an RSA public key from DER certificate or DER SPKI.
fn rsa_public_key(pub_bytes: &[u8]) -> Result<RsaPublicKey, (String, String)> {
    let spki = extract_spki_der_from_der_key_or_cert(pub_bytes)?;
    RsaPublicKey::from_public_key_der(&spki)
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad RSA public key: {e}")))
}

/// Verify RS256 (RSASSA-PKCS1v1.5 + SHA-256).
fn verify_rsa_pkcs1(pub_bytes: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), (String, String)> {
    let key = rsa_public_key(pub_bytes)?;
    let vk = pkcs1v15::VerifyingKey::<Sha256>::new(key);
    let signature = pkcs1v15::Signature::try_from(sig)
        .map_err(|e| ("BAD_SIGNATURE".to_string(), format!("bad RS256 signature bytes: {e}")))?;
    vk.verify(msg, &signature)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "signature verification failed".to_string()))
}

/// Verify PS256 (RSASSA-PSS + SHA-256).
fn verify_rsa_pss(pub_bytes: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), (String, String)> {
    let key = rsa_public_key(pub_bytes)?;
    let vk = pss::VerifyingKey::<Sha256>::new(key);
    let signature = pss::Signature::try_from(sig)
        .map_err(|e| ("BAD_SIGNATURE".to_string(), format!("bad PS256 signature bytes: {e}")))?;
    vk.verify(msg, &signature)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "signature verification failed".to_string()))
}
