// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! High-level COSE_Sign1 verification facade.
//!
//! This crate provides a clean, opinionated entry point for verifying COSE_Sign1
//! messages with:
//! - Optional external payload for detached signatures.
//! - Optional public key bytes.
//! - Automatic public key extraction via supported providers (currently: x5c).
//! - Optional indirect payload verification for COSE Hash Envelope.

pub mod common;
pub mod validation;

use cosesign1_abstractions::ParsedCoseSign1;
use crate::validation::VerifyOptions;
use std::collections::HashMap;
use std::io::{Read, Seek};

/// Helper trait for `Read + Seek` as a single trait object.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

pub use cosesign1_abstractions::{ValidationFailure, ValidationResult};

pub struct SignatureVerificationSettings {
    _private: (),
}

impl SignatureVerificationSettings {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

pub struct VerificationSettings {
    /// If true, verify the COSE signature. If false, skip signature verification.
    ///
    /// This is useful for verification models that do not require trusting the COSE signing key,
    /// such as receipt-based verification (e.g., MST), where the receipt binds to the statement.
    require_cose_signature: bool,

    signature: SignatureVerificationSettings,

    /// Validators to run, by ID.
    ///
    /// Validator crates should export a stable `MessageValidatorId` constant (e.g. `cosesign1_mst::MST_VALIDATOR_ID`)
    /// so consumers never need to type a string.
    enabled_validators: Vec<cosesign1_abstractions::MessageValidatorId>,

    /// Options for message validators, keyed by validator ID.
    validator_options: HashMap<
        cosesign1_abstractions::MessageValidatorId,
        cosesign1_abstractions::OpaqueOptions,
    >,
}

impl VerificationSettings {
    /// Skip cryptographic COSE signature verification.
    ///
    /// This is useful for receipt/attestation-based verification models (e.g., MST)
    /// where trust does not come from the COSE signing key.
    pub fn without_cose_signature(mut self) -> Self {
        self.require_cose_signature = false;
        self
    }

    /// Add a message validator by ID.
    pub fn with_validator(mut self, id: cosesign1_abstractions::MessageValidatorId) -> Self {
        if !self.enabled_validators.contains(&id) {
            self.enabled_validators.push(id);
        }
        self
    }

    /// Configure a message validator (options) in one call.
    ///
    /// Intended usage is a single one-liner with a validator helper, e.g.:
    /// `settings.with_validator_options(cosesign1_mst::mst_message_validation_options(store, opt))`
    pub fn with_validator_options(
        mut self,
        opt: (
            cosesign1_abstractions::MessageValidatorId,
            cosesign1_abstractions::OpaqueOptions,
        ),
    ) -> Self {
        self.validator_options.insert(opt.0, opt.1);
        self.with_validator(opt.0)
    }
}

impl Default for VerificationSettings {
    fn default() -> Self {
        Self {
            require_cose_signature: true,
            signature: Default::default(),
            enabled_validators: Vec::new(),
            validator_options: HashMap::new(),
        }
    }
}

impl Default for SignatureVerificationSettings {
    fn default() -> Self {
        Self::new()
    }
}

/// COSE Hash Envelope header label: payload-hash-alg.
///
/// See: draft-ietf-cose-hash-envelope and IANA COSE header parameters.
const HDR_PAYLOAD_HASH_ALG: i64 = 258;

/// Supported hash algorithms for COSE Hash Envelope (IANA COSE Algorithms registry).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CoseHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

fn hash_alg_from_cose_i64(v: i64) -> Option<CoseHashAlgorithm> {
    match v {
        -16 => Some(CoseHashAlgorithm::Sha256),
        -43 => Some(CoseHashAlgorithm::Sha384),
        -44 => Some(CoseHashAlgorithm::Sha512),
        _ => None,
    }
}

fn is_cose_hash_envelope(parsed: &ParsedCoseSign1) -> Result<Option<CoseHashAlgorithm>, String> {
    // Payload Hash Envelope requirements (as used by the .NET implementation in this repo):
    // - Message must not be detached.
    // - Label 258 MUST be present in protected headers.
    // - Label 258 MUST NOT be present in unprotected headers.

    if parsed.payload.as_deref().is_none() {
        return Ok(None);
    }

    if parsed.unprotected_headers.get_i64(HDR_PAYLOAD_HASH_ALG).is_some() {
        return Err("payload-hash-alg (258) must not be present in unprotected headers".to_string());
    }

    let Some(v) = parsed.protected_headers.get_i64(HDR_PAYLOAD_HASH_ALG) else {
        return Ok(None);
    };

    let alg = hash_alg_from_cose_i64(v)
        .ok_or_else(|| format!("unsupported payload-hash-alg value: {v}"))?;

    Ok(Some(alg))
}

fn hash_matches(alg: CoseHashAlgorithm, expected_hash: &[u8], payload: &[u8]) -> bool {
    match alg {
        CoseHashAlgorithm::Sha256 => {
            use sha2::Digest as _;
            let got = sha2::Sha256::digest(payload);
            AsRef::<[u8]>::as_ref(&got) == expected_hash
        }
        CoseHashAlgorithm::Sha384 => {
            use sha2::Digest as _;
            let got = sha2::Sha384::digest(payload);
            AsRef::<[u8]>::as_ref(&got) == expected_hash
        }
        CoseHashAlgorithm::Sha512 => {
            use sha2::Digest as _;
            let got = sha2::Sha512::digest(payload);
            AsRef::<[u8]>::as_ref(&got) == expected_hash
        }
    }
}

fn hash_matches_reader(
    alg: CoseHashAlgorithm,
    expected_hash: &[u8],
    payload_reader: &mut dyn Read,
) -> Result<bool, String> {
    let mut buf = [0u8; 64 * 1024];

    match alg {
        CoseHashAlgorithm::Sha256 => {
            use sha2::Digest as _;
            let mut h = sha2::Sha256::new();
            loop {
                let n = payload_reader
                    .read(&mut buf)
                    .map_err(|e| format!("failed to read payload: {e}"))?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(AsRef::<[u8]>::as_ref(&h.finalize()) == expected_hash)
        }
        CoseHashAlgorithm::Sha384 => {
            use sha2::Digest as _;
            let mut h = sha2::Sha384::new();
            loop {
                let n = payload_reader
                    .read(&mut buf)
                    .map_err(|e| format!("failed to read payload: {e}"))?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(AsRef::<[u8]>::as_ref(&h.finalize()) == expected_hash)
        }
        CoseHashAlgorithm::Sha512 => {
            use sha2::Digest as _;
            let mut h = sha2::Sha512::new();
            loop {
                let n = payload_reader
                    .read(&mut buf)
                    .map_err(|e| format!("failed to read payload: {e}"))?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
            Ok(AsRef::<[u8]>::as_ref(&h.finalize()) == expected_hash)
        }
    }
}

/// A parsed COSE_Sign1 message.
#[derive(Debug, Clone)]
pub struct CoseSign1 {
    pub bytes: Vec<u8>,
    pub parsed: ParsedCoseSign1,
}

impl CoseSign1 {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let parsed = crate::common::parse_cose_sign1(bytes)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            parsed,
        })
    }

    /// Verify the COSE signature.
    ///
    /// Behavior:
    /// - If `public_key_bytes` is provided, it is used directly.
    /// - Otherwise, the verifier attempts supported key-extractor providers (currently: x5c).
    /// - If the message is a COSE Hash Envelope and `payload_to_verify` is provided,
    ///   it verifies the payload hash matches the embedded hash.
    ///
    /// Notes:
    /// - For embedded payload COSE_Sign1, `payload_to_verify` does not affect signature verification.
    /// - For detached payload COSE_Sign1 (`null`), `payload_to_verify` must be provided.
    pub fn verify_signature(
        &self,
        payload_to_verify: Option<&[u8]>,
        public_key_bytes: Option<&[u8]>,
    ) -> ValidationResult {
        self.verify_signature_with_settings(payload_to_verify, public_key_bytes, &Default::default())
    }

    /// Verify the COSE signature using a streamed payload.
    ///
    /// Supported cases:
    /// - Detached payload (`null`): verifies signature by streaming payload bytes (no buffering).
    /// - COSE Hash Envelope: verifies the provided payload stream hashes to the embedded digest.
    ///
    /// Notes:
    /// - For detached payload signatures, the reader must be seekable so we can determine
    ///   the CBOR bstr length prefix for Sig_structure.
    pub fn verify_signature_with_payload_reader(
        &self,
        payload_reader: &mut dyn ReadSeek,
        public_key_bytes: Option<&[u8]>,
    ) -> ValidationResult {
        // If this is a COSE Hash Envelope, verify the preimage payload matches by streaming.
        match is_cose_hash_envelope(&self.parsed) {
            Ok(Some(hash_alg)) => {
                let expected = self.parsed.payload.as_deref().unwrap_or_default();
                if expected.is_empty() {
                    return ValidationResult::failure_message(
                        "Signature",
                        "COSE Hash Envelope payload hash bytes were empty",
                        Some("INVALID_INDIRECT_SIGNATURE".to_string()),
                    );
                }

                match hash_matches_reader(hash_alg, expected, payload_reader) {
                    Ok(true) => {}
                    Ok(false) => {
                        return ValidationResult::failure(
                            "Signature".to_string(),
                            vec![ValidationFailure {
                                message: "payload does not match embedded COSE Hash Envelope digest".to_string(),
                                error_code: Some("PAYLOAD_MISMATCH".to_string()),
                            }],
                        )
                    }
                    Err(e) => {
                        return ValidationResult::failure_message(
                            "Signature",
                            e,
                            Some("PAYLOAD_READ_ERROR".to_string()),
                        )
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                return ValidationResult::failure_message(
                    "Signature",
                    e,
                    Some("INVALID_INDIRECT_SIGNATURE".to_string()),
                )
            }
        }

        let mut opts = VerifyOptions {
            external_payload: None,
            public_key_bytes: public_key_bytes.map(|b| b.to_vec()),
            expected_alg: None,
        };

        // If we resolve a key via provider, we keep it so we can optionally validate it later.
        let mut resolved_by_provider: Option<cosesign1_abstractions::ResolvedSigningKey> = None;

        // If no key was supplied, consult registered providers.
        if opts.public_key_bytes.is_none() {
            match cosesign1_abstractions::resolve_signing_key(&self.parsed) {
                Ok(resolved) => {
                    opts.public_key_bytes = Some(resolved.public_key_bytes.clone());
                    resolved_by_provider = Some(resolved);
                }
                Err(cosesign1_abstractions::ResolvePublicKeyError::NoProviderMatched) => {
                    return ValidationResult::failure_message(
                        "Signature",
                        "public key not provided and no supported key provider found in message",
                        Some("MISSING_PUBLIC_KEY".to_string()),
                    )
                }
                Err(e) => {
                    return ValidationResult::failure_message(
                        "Signature",
                        e.to_string(),
                        Some("PUBLIC_KEY_PROVIDER_ERROR".to_string()),
                    )
                }
            }
        }

        let mut sig = if self.parsed.payload.is_none() {
            crate::validation::verify_parsed_cose_sign1_detached_payload_reader(
                "Signature",
                &self.parsed,
                payload_reader,
                &opts,
            )
        } else {
            crate::validation::verify_parsed_cose_sign1(
                "Signature",
                &self.parsed,
                self.parsed.payload.as_deref(),
                &opts,
            )
        };

        // Record the key source.
        if public_key_bytes.is_some() {
            sig.metadata
                .insert("signing_key.provider".to_string(), "override".to_string());
        } else if let Some(resolved) = resolved_by_provider.as_ref() {
            sig.metadata
                .insert("signing_key.provider".to_string(), resolved.provider_name.to_string());
        }

        sig
    }

    /// Verify a COSE message using a configurable pipeline.
    ///
    /// This can:
    /// - Verify the COSE signature (optional).
    /// - Run additional message validators (e.g., MST receipt verification).
    pub fn verify(
        &self,
        payload_to_verify: Option<&[u8]>,
        public_key_bytes: Option<&[u8]>,
        settings: &VerificationSettings,
    ) -> ValidationResult {
        let sig = if settings.require_cose_signature {
            Some(self.verify_signature_with_settings(payload_to_verify, public_key_bytes, &settings.signature))
        } else {
            None
        };

        // Start with signature result if it ran, otherwise success.
        let mut out = sig
            .clone()
            .unwrap_or_else(|| ValidationResult::success("Verify", Default::default()));

        if !settings.require_cose_signature {
            out.metadata
                .insert("signature.verified".to_string(), "false".to_string());
        } else {
            out.metadata
                .insert("signature.verified".to_string(), "true".to_string());
        }

        // If signature was required and failed, return early.
        if settings.require_cose_signature {
            if let Some(sig) = sig.as_ref() {
                if !sig.is_valid {
                    return out;
                }
            }
        }

        // Run enabled message validators.
        for id in &settings.enabled_validators {
            let ctx = cosesign1_abstractions::MessageValidationContext {
                cose_bytes: &self.bytes,
                parsed: &self.parsed,
                payload_to_verify,
                signature_result: sig.as_ref(),
            };

            let opt = settings.validator_options.get(id);
            let validator_key = cosesign1_abstractions::validator_name(*id)
                .map(|n| n.to_string())
                .unwrap_or_else(|| id.0.to_string());

            match cosesign1_abstractions::run_validator_by_id(*id, &ctx, opt) {
                Ok(Some(mut vr)) => {
                    out.metadata
                        .insert(format!("validator.{validator_key}.ran"), "true".to_string());
                    out.metadata.extend(vr.metadata.drain());
                    if !vr.failures.is_empty() {
                        out.failures.extend(vr.failures.drain(..));
                    }
                    if !vr.is_valid {
                        out.is_valid = false;
                    }
                }
                Ok(None) => {
                    out.metadata
                        .insert(format!("validator.{validator_key}.ran"), "false".to_string());
                }
                Err(e) => {
                    return ValidationResult::failure_message(
                        "Verify",
                        e.to_string(),
                        Some("MESSAGE_VALIDATOR_ERROR".to_string()),
                    )
                }
            }
        }

        out
    }

    pub fn verify_signature_with_settings(
        &self,
        payload_to_verify: Option<&[u8]>,
        public_key_bytes: Option<&[u8]>,
        settings: &SignatureVerificationSettings,
    ) -> ValidationResult {
        self.verify_signature_impl(payload_to_verify, public_key_bytes, settings)
    }

    fn verify_signature_impl(
        &self,
        payload_to_verify: Option<&[u8]>,
        public_key_bytes: Option<&[u8]>,
        _settings: &SignatureVerificationSettings,
    ) -> ValidationResult {
        // If this is a COSE Hash Envelope, optionally verify the preimage payload matches.
        match is_cose_hash_envelope(&self.parsed) {
            Ok(Some(hash_alg)) => {
                if let Some(payload) = payload_to_verify {
                    let expected = self.parsed.payload.as_deref().unwrap_or_default();
                    if expected.is_empty() {
                        return ValidationResult::failure_message(
                            "Signature",
                            "COSE Hash Envelope payload hash bytes were empty",
                            Some("INVALID_INDIRECT_SIGNATURE".to_string()),
                        );
                    }

                    if !hash_matches(hash_alg, expected, payload) {
                        return ValidationResult::failure(
                            "Signature".to_string(),
                            vec![ValidationFailure {
                                message: "payload does not match embedded COSE Hash Envelope digest".to_string(),
                                error_code: Some("PAYLOAD_MISMATCH".to_string()),
                            }],
                        );
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                return ValidationResult::failure_message(
                    "Signature",
                    e,
                    Some("INVALID_INDIRECT_SIGNATURE".to_string()),
                )
            }
        }

        // For detached payload signatures, we must provide external payload bytes.
        let external_payload = if self.parsed.payload.is_some() {
            None
        } else {
            payload_to_verify.map(|p| p.to_vec())
        };

        // If the message is detached and no external payload was provided, fail early.
        if self.parsed.payload.is_none() && external_payload.is_none() {
            return ValidationResult::failure_message(
                "Signature",
                "detached payload requires external payload bytes",
                Some("MISSING_PAYLOAD".to_string()),
            );
        }

        let mut opts = VerifyOptions {
            external_payload,
            public_key_bytes: public_key_bytes.map(|b| b.to_vec()),
            expected_alg: None,
        };

        // If we resolve a key via provider, we keep it so we can optionally validate it later.
        let mut resolved_by_provider: Option<cosesign1_abstractions::ResolvedSigningKey> = None;

        // If no key was supplied, consult registered providers.
        if opts.public_key_bytes.is_none() {
            match cosesign1_abstractions::resolve_signing_key(&self.parsed) {
                Ok(resolved) => {
                    opts.public_key_bytes = Some(resolved.public_key_bytes.clone());
                    resolved_by_provider = Some(resolved);
                }
                Err(cosesign1_abstractions::ResolvePublicKeyError::NoProviderMatched) => {
                    return ValidationResult::failure_message(
                        "Signature",
                        "public key not provided and no supported key provider found in message",
                        Some("MISSING_PUBLIC_KEY".to_string()),
                    )
                }
                Err(e) => {
                    return ValidationResult::failure_message(
                        "Signature",
                        e.to_string(),
                        Some("PUBLIC_KEY_PROVIDER_ERROR".to_string()),
                    )
                }
            }
        }

        // Perform signature verification using the resolved key.
        let external = opts
            .external_payload
            .as_deref()
            .or_else(|| self.parsed.payload.as_deref());
        let mut sig = crate::validation::verify_parsed_cose_sign1("Signature", &self.parsed, external, &opts);

        // Record the key source.
        if public_key_bytes.is_some() {
            sig.metadata
                .insert("signing_key.provider".to_string(), "override".to_string());
        } else if let Some(resolved) = resolved_by_provider.as_ref() {
            sig.metadata
            .insert("signing_key.provider".to_string(), resolved.provider_name.to_string());
        }

        // If signature failed, don't bother validating the signing key.
        if !sig.is_valid {
            return sig;
        }

        sig
    }
}
