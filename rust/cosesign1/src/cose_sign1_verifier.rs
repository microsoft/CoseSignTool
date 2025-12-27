// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE_Sign1 signature verification.

use crate::{encode_signature1_sig_structure, parse_cose_sign1, CoseAlgorithm, VerifyOptions};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rsa::pkcs1v15;
use rsa::pkcs8::DecodePublicKey as _;
use rsa::pss;
use rsa::RsaPublicKey;
use sha2::Sha256;
use sha2::{Digest as _, Sha384, Sha512};
use signature::hazmat::PrehashVerifier;
use signature::Verifier;
use std::io::SeekFrom;
use x509_parser::prelude::FromDer as _;

use cosesign1_abstractions::{ParsedCoseSign1, ValidationResult};

pub fn verify_cose_sign1(
    validator_name: &str,
    cose_sign1: &[u8],
    options: &VerifyOptions,
) -> ValidationResult {
    let parsed = match parse_cose_sign1(cose_sign1) {
        Ok(p) => p,
        Err(e) => {
            return ValidationResult::failure_message(
                validator_name,
                e,
                Some("COSE_PARSE_ERROR".to_string()),
            )
        }
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
        Err(e) => {
            return ValidationResult::failure_message(
                validator_name,
                e,
                Some("MISSING_OR_INVALID_ALG".to_string()),
            )
        }
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
        Err(e) => {
            return ValidationResult::failure_message(
                validator_name,
                e,
                Some("SIGSTRUCT_ERROR".to_string()),
            )
        }
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

    match verify_sig_structure(alg, key_bytes, &sig_structure, &parsed.signature) {
        Ok(()) => ValidationResult::success(validator_name, Default::default()),
        Err((code, msg)) => ValidationResult::failure_message(validator_name, msg, Some(code)),
    }
}

/// Verify a parsed COSE_Sign1 *detached payload* signature using a stream.
///
/// This avoids buffering the detached payload in memory by hashing the Sig_structure
/// incrementally and using prehash verification.
///
/// Notes:
/// - Requires `payload` to be `null` in the COSE message.
/// - Requires `payload_reader` to be seekable so we can determine payload length
///   (CBOR byte string encoding is length-prefixed).
/// - Supports true streaming for ES256/ES384/ES512/RS256/PS256.
/// - ML-DSA is supported via a buffering fallback (payload will be read into memory).
/// - Other algorithms will return `SIGSTRUCT_ERROR`.
pub fn verify_parsed_cose_sign1_detached_payload_reader(
    validator_name: &str,
    parsed: &ParsedCoseSign1,
    payload_reader: &mut dyn crate::ReadSeek,
    options: &VerifyOptions,
) -> ValidationResult {
    if parsed.payload.is_some() {
        return ValidationResult::failure_message(
            validator_name,
            "streaming detached payload verification requires COSE payload to be null",
            Some("SIGSTRUCT_ERROR".to_string()),
        );
    }

    let alg = match cose_alg(parsed) {
        Ok(a) => a,
        Err(e) => {
            return ValidationResult::failure_message(
                validator_name,
                e,
                Some("MISSING_OR_INVALID_ALG".to_string()),
            )
        }
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

    let res = verify_sig_structure_detached_reader(
        alg,
        key_bytes,
        parsed,
        payload_reader,
        &parsed.signature,
    );
    match res {
        Ok(()) => ValidationResult::success(validator_name, Default::default()),
        Err((code, msg)) => ValidationResult::failure_message(validator_name, msg, Some(code)),
    }
}

fn cbor_definite_bstr_header(len: u64) -> Vec<u8> {
    // CBOR major type 2 (byte string) with definite length.
    // https://www.rfc-editor.org/rfc/rfc8949.html
    if len < 24 {
        return vec![0x40u8 | (len as u8)];
    }
    if len <= u8::MAX as u64 {
        return vec![0x58, len as u8];
    }
    if len <= u16::MAX as u64 {
        return vec![0x59, (len >> 8) as u8, len as u8];
    }
    if len <= u32::MAX as u64 {
        return vec![
            0x5A,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ];
    }
    vec![
        0x5B,
        (len >> 56) as u8,
        (len >> 48) as u8,
        (len >> 40) as u8,
        (len >> 32) as u8,
        (len >> 24) as u8,
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
    ]
}

fn sig_structure_prefix_for_detached_payload(msg: &ParsedCoseSign1, payload_len: u64) -> Vec<u8> {
    // Sig_structure = [ "Signature1", protected, external_aad, payload ]
    // We always encode with definite length items and external_aad = empty bstr.
    let protected = msg.protected_headers.encoded_map_cbor();

    let mut out = Vec::with_capacity(64 + protected.len());
    // array(4)
    out.push(0x84);
    // "Signature1" (10 bytes)
    out.push(0x6A);
    out.extend_from_slice(b"Signature1");
    // protected: bstr(protected_map_bytes)
    out.extend_from_slice(&cbor_definite_bstr_header(protected.len() as u64));
    out.extend_from_slice(protected);
    // external_aad: empty bstr
    out.push(0x40);
    // payload: bstr(payload_len) + payload bytes follow
    out.extend_from_slice(&cbor_definite_bstr_header(payload_len));
    out
}

fn stream_into_digest(
    reader: &mut dyn crate::ReadSeek,
    digest: &mut dyn FnMut(&[u8]),
) -> Result<(), String> {
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("failed to read detached payload: {e}"))?;
        if n == 0 {
            break;
        }
        digest(&buf[..n]);
    }
    Ok(())
}

fn stream_into_vec(reader: &mut dyn crate::ReadSeek, out: &mut Vec<u8>) -> Result<(), String> {
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("failed to read detached payload: {e}"))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(())
}

fn verify_sig_structure_detached_reader(
    alg: CoseAlgorithm,
    public_key_bytes: &[u8],
    msg: &ParsedCoseSign1,
    payload_reader: &mut dyn crate::ReadSeek,
    cose_signature: &[u8],
) -> Result<(), (String, String)> {
    // Determine payload length (required to reproduce Sig_structure CBOR encoding).
    let start = payload_reader
        .stream_position()
        .map_err(|e| ("SIGSTRUCT_ERROR".to_string(), format!("failed to read payload position: {e}")))?;
    let end = payload_reader
        .seek(SeekFrom::End(0))
        .map_err(|e| ("SIGSTRUCT_ERROR".to_string(), format!("failed to seek payload: {e}")))?;
    let payload_len = end.checked_sub(start).ok_or_else(|| {
        (
            "SIGSTRUCT_ERROR".to_string(),
            "invalid payload stream position".to_string(),
        )
    })?;
    payload_reader
        .seek(SeekFrom::Start(start))
        .map_err(|e| ("SIGSTRUCT_ERROR".to_string(), format!("failed to seek payload: {e}")))?;

    let prefix = sig_structure_prefix_for_detached_payload(msg, payload_len);

    match alg {
        CoseAlgorithm::ES256 => {
            let mut h = Sha256::new();
            h.update(&prefix);
            stream_into_digest(payload_reader, &mut |chunk| h.update(chunk))
                .map_err(|e| ("SIGSTRUCT_ERROR".to_string(), e))?;
            let prehash = h.finalize();
            verify_ecdsa_p256_prehash(public_key_bytes, prehash.as_ref(), cose_signature)
        }
        CoseAlgorithm::ES384 => {
            let mut h = Sha384::new();
            h.update(&prefix);
            stream_into_digest(payload_reader, &mut |chunk| h.update(chunk))
                .map_err(|e| ("SIGSTRUCT_ERROR".to_string(), e))?;
            let prehash = h.finalize();
            verify_ecdsa_p384_prehash(public_key_bytes, prehash.as_ref(), cose_signature)
        }
        CoseAlgorithm::ES512 => {
            let mut h = Sha512::new();
            h.update(&prefix);
            stream_into_digest(payload_reader, &mut |chunk| h.update(chunk))
                .map_err(|e| ("SIGSTRUCT_ERROR".to_string(), e))?;
            let prehash = h.finalize();
            verify_ecdsa_p521_prehash(public_key_bytes, prehash.as_ref(), cose_signature)
        }

        CoseAlgorithm::RS256 => {
            let mut h = Sha256::new();
            h.update(&prefix);
            stream_into_digest(payload_reader, &mut |chunk| h.update(chunk))
                .map_err(|e| ("SIGSTRUCT_ERROR".to_string(), e))?;
            let prehash = h.finalize();
            verify_rsa_pkcs1_prehash(public_key_bytes, prehash.as_ref(), cose_signature)
        }
        CoseAlgorithm::PS256 => {
            let mut h = Sha256::new();
            h.update(&prefix);
            stream_into_digest(payload_reader, &mut |chunk| h.update(chunk))
                .map_err(|e| ("SIGSTRUCT_ERROR".to_string(), e))?;
            let prehash = h.finalize();
            verify_rsa_pss_prehash(public_key_bytes, prehash.as_ref(), cose_signature)
        }

        // ML-DSA does not currently expose a prehash verifier API in the upstream crate,
        // so we buffer the Sig_structure bytes.
        CoseAlgorithm::MLDsa44 => {
            if payload_len > (usize::MAX as u64) {
                return Err((
                    "SIGSTRUCT_ERROR".to_string(),
                    "detached payload too large to buffer for ML-DSA verification".to_string(),
                ));
            }
            let mut sig_structure = prefix;
            stream_into_vec(payload_reader, &mut sig_structure)
                .map_err(|e| ("SIGSTRUCT_ERROR".to_string(), e))?;
            verify_ml_dsa::<MlDsa44>(
                public_key_bytes,
                &sig_structure,
                cose_signature,
                Some("2.16.840.1.101.3.4.3.17"),
            )
        }
        CoseAlgorithm::MLDsa65 => {
            if payload_len > (usize::MAX as u64) {
                return Err((
                    "SIGSTRUCT_ERROR".to_string(),
                    "detached payload too large to buffer for ML-DSA verification".to_string(),
                ));
            }
            let mut sig_structure = prefix;
            stream_into_vec(payload_reader, &mut sig_structure)
                .map_err(|e| ("SIGSTRUCT_ERROR".to_string(), e))?;
            verify_ml_dsa::<MlDsa65>(
                public_key_bytes,
                &sig_structure,
                cose_signature,
                Some("2.16.840.1.101.3.4.3.18"),
            )
        }
        CoseAlgorithm::MLDsa87 => {
            if payload_len > (usize::MAX as u64) {
                return Err((
                    "SIGSTRUCT_ERROR".to_string(),
                    "detached payload too large to buffer for ML-DSA verification".to_string(),
                ));
            }
            let mut sig_structure = prefix;
            stream_into_vec(payload_reader, &mut sig_structure)
                .map_err(|e| ("SIGSTRUCT_ERROR".to_string(), e))?;
            verify_ml_dsa::<MlDsa87>(
                public_key_bytes,
                &sig_structure,
                cose_signature,
                Some("2.16.840.1.101.3.4.3.19"),
            )
        }
    }
}

fn cose_alg(parsed: &ParsedCoseSign1) -> Result<CoseAlgorithm, String> {
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

pub fn verify_sig_structure(
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
        CoseAlgorithm::MLDsa44 => verify_ml_dsa::<MlDsa44>(
            public_key_bytes,
            sig_structure,
            cose_signature,
            Some("2.16.840.1.101.3.4.3.17"),
        ),
        CoseAlgorithm::MLDsa65 => verify_ml_dsa::<MlDsa65>(
            public_key_bytes,
            sig_structure,
            cose_signature,
            Some("2.16.840.1.101.3.4.3.18"),
        ),
        CoseAlgorithm::MLDsa87 => verify_ml_dsa::<MlDsa87>(
            public_key_bytes,
            sig_structure,
            cose_signature,
            Some("2.16.840.1.101.3.4.3.19"),
        ),
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
        if oid != expected {
            return Err((
                "INVALID_PUBLIC_KEY".to_string(),
                format!("unexpected public key algorithm OID: expected {expected}, got {oid}"),
            ));
        }
    }

    let enc_vk = ml_dsa::EncodedVerifyingKey::<P>::try_from(encoded_vk_bytes.as_slice()).map_err(|_| {
        (
            "INVALID_PUBLIC_KEY".to_string(),
            "bad ML-DSA public key bytes".to_string(),
        )
    })?;
    let vk = ml_dsa::VerifyingKey::<P>::decode(&enc_vk);

    let signature = ml_dsa::Signature::<P>::try_from(sig).map_err(|_| {
        (
            "BAD_SIGNATURE".to_string(),
            "bad ML-DSA signature bytes".to_string(),
        )
    })?;

    vk.verify(msg, &signature)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "signature verification failed".to_string()))
}

fn extract_ml_dsa_public_key_bytes_and_oid(
    der_or_raw: &[u8],
) -> Result<(Vec<u8>, Option<String>), String> {
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

fn verify_ecdsa_p256_prehash(
    pub_bytes: &[u8],
    prehash: &[u8],
    sig: &[u8],
) -> Result<(), (String, String)> {
    let spki = extract_spki_der_from_der_key_or_cert(pub_bytes)?;
    let pk = p256::PublicKey::from_public_key_der(&spki)
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-256 public key: {e}")))?;

    let ep = pk.to_encoded_point(false);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(ep.as_bytes())
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-256 public key: {e}")))?;

    let signature = p256::ecdsa::Signature::from_slice(sig)
        .map_err(|e| ("BAD_SIGNATURE".to_string(), format!("bad ES256 signature: {e}")))?;

    vk.verify_prehash(prehash, &signature)
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

fn verify_ecdsa_p384_prehash(
    pub_bytes: &[u8],
    prehash: &[u8],
    sig: &[u8],
) -> Result<(), (String, String)> {
    let spki = extract_spki_der_from_der_key_or_cert(pub_bytes)?;
    let pk = p384::PublicKey::from_public_key_der(&spki)
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-384 public key: {e}")))?;
    let ep = pk.to_encoded_point(false);
    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(ep.as_bytes())
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-384 public key: {e}")))?;
    let signature = p384::ecdsa::Signature::from_slice(sig)
        .map_err(|e| ("BAD_SIGNATURE".to_string(), format!("bad ES384 signature: {e}")))?;
    vk.verify_prehash(prehash, &signature)
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

fn verify_ecdsa_p521_prehash(
    pub_bytes: &[u8],
    prehash: &[u8],
    sig: &[u8],
) -> Result<(), (String, String)> {
    let spki = extract_spki_der_from_der_key_or_cert(pub_bytes)?;
    let pk = p521::PublicKey::from_public_key_der(&spki)
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-521 public key: {e}")))?;
    let ep = pk.to_encoded_point(false);
    let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(ep.as_bytes())
        .map_err(|e| ("INVALID_PUBLIC_KEY".to_string(), format!("bad P-521 public key: {e}")))?;
    let signature = p521::ecdsa::Signature::from_slice(sig)
        .map_err(|e| ("BAD_SIGNATURE".to_string(), format!("bad ES512 signature: {e}")))?;
    vk.verify_prehash(prehash, &signature)
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

fn verify_rsa_pkcs1_prehash(
    pub_bytes: &[u8],
    prehash: &[u8],
    sig: &[u8],
) -> Result<(), (String, String)> {
    let key = rsa_public_key(pub_bytes)?;
    // Preserve existing "bad signature bytes" mapping behavior.
    let _ = pkcs1v15::Signature::try_from(sig)
        .map_err(|e| ("BAD_SIGNATURE".to_string(), format!("bad RS256 signature bytes: {e}")))?;
    key.verify(pkcs1v15::Pkcs1v15Sign::new::<Sha256>(), prehash, sig)
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

fn verify_rsa_pss_prehash(
    pub_bytes: &[u8],
    prehash: &[u8],
    sig: &[u8],
) -> Result<(), (String, String)> {
    let key = rsa_public_key(pub_bytes)?;
    let _ = pss::Signature::try_from(sig)
        .map_err(|e| ("BAD_SIGNATURE".to_string(), format!("bad PS256 signature bytes: {e}")))?;
    key.verify(pss::Pss::new::<Sha256>(), prehash, sig)
        .map_err(|_| ("BAD_SIGNATURE".to_string(), "signature verification failed".to_string()))
}
