// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
    ES256 = -7,
    ES384 = -35,
    ES512 = -36,
    // Provisional COSE algorithm IDs used by this repo for ML-DSA (post-quantum).
    MLDsa44 = -48,
    MLDsa65 = -49,
    MLDsa87 = -50,
    PS256 = -37,
    RS256 = -257,
}

#[derive(Default, Clone)]
pub struct VerifyOptions {
    pub external_payload: Option<Vec<u8>>,
    pub public_key_bytes: Option<Vec<u8>>,
    pub expected_alg: Option<CoseAlgorithm>,
}

pub fn verify_cose_sign1(validator_name: &str, cose_sign1: &[u8], options: &VerifyOptions) -> ValidationResult {
    let parsed = match parse_cose_sign1(cose_sign1) {
        Ok(p) => p,
        Err(e) => return ValidationResult::failure_message(validator_name, e, Some("COSE_PARSE_ERROR".to_string())),
    };

    let external = options
        .external_payload
        .as_deref()
        .or_else(|| parsed.payload.as_deref());

    verify_parsed_cose_sign1(validator_name, &parsed, external, options)
}

pub fn verify_parsed_cose_sign1(
    validator_name: &str,
    parsed: &ParsedCoseSign1,
    external_payload: Option<&[u8]>,
    options: &VerifyOptions,
) -> ValidationResult {
    let alg = match cose_alg(parsed) {
        Ok(a) => a,
        Err(e) => return ValidationResult::failure_message(validator_name, e, Some("MISSING_OR_INVALID_ALG".to_string())),
    };

    if let Some(expected) = options.expected_alg {
        if expected != alg {
            return ValidationResult::failure_message(
                validator_name,
                format!("alg header mismatch: expected {expected:?}, got {alg:?}"),
                Some("ALG_MISMATCH".to_string()),
            );
        }
    }

    let sig_structure = match encode_signature1_sig_structure(parsed, external_payload) {
        Ok(b) => b,
        Err(e) => return ValidationResult::failure_message(validator_name, e, Some("SIGSTRUCT_ERROR".to_string())),
    };

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

    match verify_signature(alg, key_bytes, &sig_structure, &parsed.signature) {
        Ok(()) => ValidationResult::success(validator_name, Default::default()),
        Err((code, msg)) => ValidationResult::failure_message(validator_name, msg, Some(code)),
    }
}

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

fn verify_ml_dsa<P: ml_dsa::MlDsaParams>(
    public_key_bytes: &[u8],
    msg: &[u8],
    sig: &[u8],
    expected_spki_oid: Option<&'static str>,
) -> Result<(), (String, String)> {
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

    let enc_vk = ml_dsa::EncodedVerifyingKey::<P>::try_from(encoded_vk_bytes.as_slice())
        .map_err(|_| ("INVALID_PUBLIC_KEY".to_string(), "bad ML-DSA public key bytes".to_string()))?;
    let vk = ml_dsa::VerifyingKey::<P>::decode(&enc_vk);

    let signature = ml_dsa::Signature::<P>::try_from(sig)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "bad ML-DSA signature bytes".to_string()))?;

    vk.verify(msg, &signature)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "signature verification failed".to_string()))
}

fn extract_ml_dsa_public_key_bytes_and_oid(der_or_raw: &[u8]) -> Result<(Vec<u8>, Option<String>), String> {
    // Accept:
    // - DER X.509 certificate
    // - DER SubjectPublicKeyInfo
    // - Raw ML-DSA encoded verifying key bytes
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(der_or_raw) {
        let spki = &cert.tbs_certificate.subject_pki;
        let oid = Some(spki.algorithm.algorithm.to_string());
        let pk = spki.subject_public_key.data.to_vec();
        return Ok((pk, oid));
    }

    if let Ok((_, spki)) = x509_parser::x509::SubjectPublicKeyInfo::from_der(der_or_raw) {
        let oid = Some(spki.algorithm.algorithm.to_string());
        let pk = spki.subject_public_key.data.to_vec();
        return Ok((pk, oid));
    }

    Ok((der_or_raw.to_vec(), None))
}

fn extract_spki_der_from_der_key_or_cert(der: &[u8]) -> Result<Vec<u8>, (String, String)> {
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) {
        return Ok(cert.tbs_certificate.subject_pki.raw.to_vec());
    }
    Ok(der.to_vec())
}

fn verify_ecdsa_p256(pub_bytes: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), (String, String)> {
    let spki = extract_spki_der_from_der_key_or_cert(pub_bytes)?;
    let pk = p256::PublicKey::from_public_key_der(&spki)
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-256 public key: {e}")))?;
    let ep = pk.to_encoded_point(false);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(ep.as_bytes())
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-256 public key: {e}")))?;
    let signature = p256::ecdsa::Signature::from_slice(sig)
        .map_err(|e| ("BAD_SIGNATURE".to_string(), format!("bad ES256 signature: {e}")))?;
    vk.verify(msg, &signature)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "signature verification failed".to_string()))
}

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

fn rsa_public_key(pub_bytes: &[u8]) -> Result<RsaPublicKey, (String, String)> {
    let spki = extract_spki_der_from_der_key_or_cert(pub_bytes)?;
    RsaPublicKey::from_public_key_der(&spki)
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad RSA public key: {e}")))
}

fn verify_rsa_pkcs1(pub_bytes: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), (String, String)> {
    let key = rsa_public_key(pub_bytes)?;
    let vk = pkcs1v15::VerifyingKey::<Sha256>::new(key);
    let signature = pkcs1v15::Signature::try_from(sig)
        .map_err(|e| ("BAD_SIGNATURE".to_string(), format!("bad RS256 signature bytes: {e}")))?;
    vk.verify(msg, &signature)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "signature verification failed".to_string()))
}

fn verify_rsa_pss(pub_bytes: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), (String, String)> {
    let key = rsa_public_key(pub_bytes)?;
    let vk = pss::VerifyingKey::<Sha256>::new(key);
    let signature = pss::Signature::try_from(sig)
        .map_err(|e| ("BAD_SIGNATURE".to_string(), format!("bad PS256 signature bytes: {e}")))?;
    vk.verify(msg, &signature)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "signature verification failed".to_string()))
}
