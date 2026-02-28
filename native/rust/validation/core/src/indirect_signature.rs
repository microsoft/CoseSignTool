// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::validator::{PostSignatureValidationContext, PostSignatureValidator, ValidationResult};
use cbor_primitives::CborDecoder;
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};
use cose_sign1_validation_primitives::CoseHeaderLocation;
use once_cell::sync::Lazy;
use regex::Regex;
use sha1::Digest as _;
use std::io::Read;

static COSE_HASH_V: Lazy<Regex> = Lazy::new(|| Regex::new("(?i)\\+cose-hash-v").unwrap());
static HASH_LEGACY: Lazy<Regex> =
    Lazy::new(|| Regex::new("(?i)\\+hash-([\\w_]+)").unwrap());

const VALIDATOR_NAME: &str = "Indirect Signature Content Validation";

const COSE_HEADER_LABEL_CONTENT_TYPE: i64 = 3;

// COSE Hash Envelope header labels.
const COSE_HASH_ENVELOPE_PAYLOAD_HASH_ALG: i64 = 258;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndirectSignatureKind {
    LegacyHashExtension,
    CoseHashV,
    CoseHashEnvelope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha1,
}

impl HashAlgorithm {
    fn name(&self) -> &'static str {
        match self {
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
            Self::Sha1 => "SHA1",
        }
    }
}

fn cose_hash_alg_from_cose_alg_value(value: i64) -> Option<HashAlgorithm> {
    // COSE hash algorithm IDs (IANA):
    // -16 SHA-256, -43 SHA-384, -44 SHA-512
    // (We also accept SHA-1 (-14) for legacy compatibility.)
    match value {
        -16 => Some(HashAlgorithm::Sha256),
        -43 => Some(HashAlgorithm::Sha384),
        -44 => Some(HashAlgorithm::Sha512),
        -14 => Some(HashAlgorithm::Sha1),
        _ => None,
    }
}

fn legacy_hash_alg_from_name(name: &str) -> Option<HashAlgorithm> {
    let upper = name.trim().to_ascii_uppercase();
    match upper.as_str() {
        "SHA256" => Some(HashAlgorithm::Sha256),
        "SHA384" => Some(HashAlgorithm::Sha384),
        "SHA512" => Some(HashAlgorithm::Sha512),
        "SHA1" => Some(HashAlgorithm::Sha1),
        _ => None,
    }
}

/// Get a text or UTF-8 bytes value from a CoseHeaderMap.
fn header_text_or_utf8_bytes(map: &CoseHeaderMap, label: i64) -> Option<String> {
    let key = CoseHeaderLabel::Int(label);
    let v = map.get(&key)?;
    match v {
        CoseHeaderValue::Text(s) => Some(s.clone()),
        CoseHeaderValue::Bytes(b) => std::str::from_utf8(b).ok().map(|s| s.to_string()),
        _ => None,
    }
}

/// Get an i64 value from a CoseHeaderMap.
fn header_i64(map: &CoseHeaderMap, label: i64) -> Option<i64> {
    let key = CoseHeaderLabel::Int(label);
    match map.get(&key)? {
        CoseHeaderValue::Int(n) => Some(*n),
        CoseHeaderValue::Uint(n) if *n <= i64::MAX as u64 => Some(*n as i64),
        _ => None,
    }
}

fn detect_indirect_signature_kind(protected: &CoseHeaderMap, content_type: Option<&str>) -> Option<IndirectSignatureKind> {
    let hash_alg_label = CoseHeaderLabel::Int(COSE_HASH_ENVELOPE_PAYLOAD_HASH_ALG);
    if protected.get(&hash_alg_label).is_some() {
        return Some(IndirectSignatureKind::CoseHashEnvelope);
    }

    let ct = content_type?;

    if COSE_HASH_V.is_match(ct) {
        return Some(IndirectSignatureKind::CoseHashV);
    }

    if HASH_LEGACY.is_match(ct) {
        return Some(IndirectSignatureKind::LegacyHashExtension);
    }

    None
}

fn compute_hash_bytes(alg: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlgorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
        HashAlgorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
        HashAlgorithm::Sha1 => sha1::Sha1::digest(data).to_vec(),
    }
}

fn compute_hash_reader(alg: HashAlgorithm, mut reader: impl Read) -> Result<Vec<u8>, String> {
    let mut buf = [0u8; 64 * 1024];
    match alg {
        HashAlgorithm::Sha256 => {
            let mut hasher = sha2::Sha256::new();
            loop {
                let read = reader
                    .read(&mut buf)
                    .map_err(|e| format!("detached_payload_read_failed: {e}"))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buf[..read]);
            }
            Ok(hasher.finalize().to_vec())
        }
        HashAlgorithm::Sha384 => {
            let mut hasher = sha2::Sha384::new();
            loop {
                let read = reader
                    .read(&mut buf)
                    .map_err(|e| format!("detached_payload_read_failed: {e}"))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buf[..read]);
            }
            Ok(hasher.finalize().to_vec())
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = sha2::Sha512::new();
            loop {
                let read = reader
                    .read(&mut buf)
                    .map_err(|e| format!("detached_payload_read_failed: {e}"))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buf[..read]);
            }
            Ok(hasher.finalize().to_vec())
        }
        HashAlgorithm::Sha1 => {
            let mut hasher = sha1::Sha1::new();
            loop {
                let read = reader
                    .read(&mut buf)
                    .map_err(|e| format!("detached_payload_read_failed: {e}"))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buf[..read]);
            }
            Ok(hasher.finalize().to_vec())
        }
    }
}

fn compute_hash_from_detached_payload(
    alg: HashAlgorithm,
    payload: &cose_sign1_primitives::payload::Payload,
) -> Result<Vec<u8>, String> {
    match payload {
        cose_sign1_primitives::payload::Payload::Bytes(b) => {
            if b.is_empty() {
                return Err("detached payload was empty".to_string());
            }
            Ok(compute_hash_bytes(alg, b.as_ref()))
        }
        cose_sign1_primitives::payload::Payload::Streaming(s) => {
            let reader = s.open()
                .map_err(|e| format!("detached_payload_open_failed: {}", e))?;
            compute_hash_reader(alg, reader)
        }
    }
}

fn parse_cose_hash_v(payload: &[u8]) -> Result<(HashAlgorithm, Vec<u8>), String> {
    let mut d = cose_sign1_primitives::provider::decoder(payload);
    
    let len = d
        .decode_array_len()
        .map_err(|e| format!("invalid COSE_Hash_V: {e}"))?
        .ok_or_else(|| "invalid COSE_Hash_V: indefinite array not supported".to_string())?;
        
    if len != 2 {
        return Err("invalid COSE_Hash_V: expected array of 2 elements".to_string());
    }

    let alg = d.decode_i64()
        .map_err(|e| format!("invalid COSE_Hash_V alg: {e}"))?;

    let hash_bytes = d.decode_bstr_owned()
        .map_err(|e| format!("invalid COSE_Hash_V hash: {e}"))?;

    let alg = cose_hash_alg_from_cose_alg_value(alg)
        .ok_or_else(|| format!("unsupported COSE_Hash_V algorithm {alg}"))?;

    if hash_bytes.is_empty() {
        return Err("invalid COSE_Hash_V: empty hash".to_string());
    }

    Ok((alg, hash_bytes))
}

/// Post-signature validator for indirect signatures.
///
/// This validator verifies that detached payloads match the hash embedded
/// in the COSE_Sign1 payload for indirect signature formats.
pub struct IndirectSignaturePostSignatureValidator;

impl PostSignatureValidator for IndirectSignaturePostSignatureValidator {
    fn validate(&self, context: &PostSignatureValidationContext<'_>) -> ValidationResult {
        let Some(detached_payload) = context.options.detached_payload.as_ref() else {
            // Treat this as "signature-only verification".
            return ValidationResult::not_applicable(
                VALIDATOR_NAME,
                Some("No detached payload provided (signature-only verification)"),
            );
        };

        let message = context.message;
        let protected = message.protected.headers();
        let unprotected = &message.unprotected;

        let mut content_type = header_text_or_utf8_bytes(protected, COSE_HEADER_LABEL_CONTENT_TYPE);
        let mut kind = detect_indirect_signature_kind(protected, content_type.as_deref());

        // Some producers may place Content-Type in the unprotected header. Only consult
        // unprotected headers when the caller's configuration allows it.
        if context.options.certificate_header_location == CoseHeaderLocation::Any
            && kind.is_none()
            && content_type.is_none()
        {
            content_type = header_text_or_utf8_bytes(unprotected, COSE_HEADER_LABEL_CONTENT_TYPE);
            kind = detect_indirect_signature_kind(protected, content_type.as_deref());
        }

        let kind = match kind {
            Some(k) => k,
            None => {
                return ValidationResult::not_applicable(VALIDATOR_NAME, Some("Not an indirect signature"))
            }
        };

        // Validate minimal envelope rules when detected (matches V1 expectations).
        if kind == IndirectSignatureKind::CoseHashEnvelope {
            let hash_alg_label = CoseHeaderLabel::Int(COSE_HASH_ENVELOPE_PAYLOAD_HASH_ALG);
            if unprotected.get(&hash_alg_label).is_some() {
                return ValidationResult::failure_message(
                    VALIDATOR_NAME,
                    "CoseHashEnvelope payload-hash-alg (258) must not be present in unprotected headers",
                    Some("INDIRECT_SIGNATURE_INVALID_HEADERS"),
                );
            }
        }

        let Some(payload) = message.payload.as_ref() else {
            return ValidationResult::failure_message(
                VALIDATOR_NAME,
                "Indirect signature validation requires an embedded payload",
                Some("INDIRECT_SIGNATURE_MISSING_HASH"),
            );
        };

        // Determine the hash algorithm and the stored expected hash.
        let (alg, expected_hash, format_name) = match kind {
            IndirectSignatureKind::LegacyHashExtension => {
                let ct = content_type.unwrap_or_default();
                let caps = HASH_LEGACY
                    .captures(&ct)
                    .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));

                let Some(alg_name) = caps else {
                    return ValidationResult::failure_message(
                        VALIDATOR_NAME,
                        "Indirect signature content-type did not contain a +hash-* extension",
                        Some("INDIRECT_SIGNATURE_UNSUPPORTED_FORMAT"),
                    );
                };

                let Some(alg) = legacy_hash_alg_from_name(&alg_name) else {
                    return ValidationResult::failure_message(
                        VALIDATOR_NAME,
                        format!("Unsupported legacy hash algorithm '{alg_name}'"),
                        Some("INDIRECT_SIGNATURE_UNSUPPORTED_ALGORITHM"),
                    );
                };

                (alg, payload.to_vec(), "Legacy+hash-*")
            }
            IndirectSignatureKind::CoseHashV => match parse_cose_hash_v(payload) {
                Ok((alg, hash)) => (alg, hash, "COSE_Hash_V"),
                Err(e) => {
                    return ValidationResult::failure_message(
                        VALIDATOR_NAME,
                        e,
                        Some("INDIRECT_SIGNATURE_INVALID_COSE_HASH_V"),
                    )
                }
            },
            IndirectSignatureKind::CoseHashEnvelope => {
                let Some(alg_raw) = header_i64(protected, COSE_HASH_ENVELOPE_PAYLOAD_HASH_ALG) else {
                    return ValidationResult::failure_message(
                        VALIDATOR_NAME,
                        "CoseHashEnvelope payload-hash-alg (258) missing from protected headers",
                        Some("INDIRECT_SIGNATURE_INVALID_HEADERS"),
                    );
                };

                let Some(alg) = cose_hash_alg_from_cose_alg_value(alg_raw) else {
                    return ValidationResult::failure_message(
                        VALIDATOR_NAME,
                        format!("Unsupported CoseHashEnvelope hash algorithm {alg_raw}"),
                        Some("INDIRECT_SIGNATURE_UNSUPPORTED_ALGORITHM"),
                    );
                };

                (alg, payload.to_vec(), "CoseHashEnvelope")
            }
        };

        // Compute the artifact hash and compare.
        let actual_hash = match compute_hash_from_detached_payload(alg, detached_payload) {
            Ok(v) => v,
            Err(e) => {
                return ValidationResult::failure_message(
                    VALIDATOR_NAME,
                    e,
                    Some("INDIRECT_SIGNATURE_PAYLOAD_READ_FAILED"),
                )
            }
        };

        if actual_hash == expected_hash {
            let mut metadata = std::collections::BTreeMap::new();
            metadata.insert("IndirectSignature.Format".to_string(), format_name.to_string());
            metadata.insert("IndirectSignature.HashAlgorithm".to_string(), alg.name().to_string());
            ValidationResult::success(VALIDATOR_NAME, Some(metadata))
        } else {
            ValidationResult::failure_message(
                VALIDATOR_NAME,
                format!(
                    "Indirect signature content did not match ({format_name}, {})",
                    alg.name()
                ),
                Some("INDIRECT_SIGNATURE_CONTENT_MISMATCH"),
            )
        }
    }

    fn validate_async<'a>(
        &'a self,
        context: &'a PostSignatureValidationContext<'a>,
    ) -> crate::validator::BoxFuture<'a, ValidationResult> {
        // Implementation is synchronous (hashing is done with a blocking reader).
        Box::pin(async move { self.validate(context) })
    }
}
