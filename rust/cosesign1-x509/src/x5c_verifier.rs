// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509 chain validation helpers for COSE `x5c`.
//!
//! The COSE header parameter `x5c` (label 33) contains a certificate chain.
//! This module validates the chain against a trust model defined by
//! `X509ChainVerifyOptions`.

use cosesign1_abstractions::ValidationResult;

#[cfg(not(windows))]
use sha2::{Sha256, Sha384, Sha512};

#[cfg(not(windows))]
use rsa::pkcs1v15;
#[cfg(not(windows))]
use rsa::pkcs8::DecodePublicKey as _;
#[cfg(not(windows))]
use rsa::RsaPublicKey;
#[cfg(not(windows))]
use signature::Verifier as _;
#[cfg(not(windows))]
use p256::elliptic_curve::sec1::ToEncodedPoint as _;

#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum X509TrustMode {
    /// Use system trust.
    System = 0,
    /// Use explicitly provided trusted roots.
    CustomRoots = 1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum X509RevocationMode {
    /// Do not perform revocation checks.
    NoCheck = 0,
    /// Perform online revocation checks.
    Online = 1,
    /// Perform offline revocation checks.
    Offline = 2,
}

#[derive(Debug, Clone)]
pub struct X509ChainVerifyOptions {
    /// Trust mode used for evaluating the chain.
    pub trust_mode: X509TrustMode,
    /// Revocation checking mode.
    pub revocation_mode: X509RevocationMode,
    /// Root certificates (DER) used when `trust_mode` is `CustomRoots`.
    pub trusted_roots_der: Vec<Vec<u8>>,
    /// Diagnostic/compatibility mode. When true, allow untrusted roots.
    pub allow_untrusted_roots: bool,
}

impl Default for X509ChainVerifyOptions {
    fn default() -> Self {
        Self {
            trust_mode: X509TrustMode::System,
            revocation_mode: X509RevocationMode::Online,
            trusted_roots_der: Vec::new(),
            allow_untrusted_roots: false,
        }
    }
}

#[cfg(not(windows))]
#[derive(Debug, Clone)]
struct ParsedCert {
    der: Vec<u8>,
    subject_dn: String,
    issuer_dn: String,
    spki_der: Vec<u8>,
    tbs_der: Vec<u8>,
    signature_oid: String,
    signature: Vec<u8>,
}

#[cfg(not(windows))]
fn parse_cert_der(der: &[u8]) -> Result<ParsedCert, String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| format!("invalid cert DER: {e}"))?;

    Ok(ParsedCert {
        der: der.to_vec(),
        subject_dn: cert.tbs_certificate.subject.to_string(),
        issuer_dn: cert.tbs_certificate.issuer.to_string(),
        spki_der: cert.tbs_certificate.subject_pki.raw.to_vec(),
        // `x509-parser` keeps the raw DER for TBSCertificate; expose it via `AsRef`.
        tbs_der: cert.tbs_certificate.as_ref().to_vec(),
        signature_oid: cert.signature_algorithm.algorithm.to_string(),
        signature: cert.signature_value.data.to_vec(),
    })
}

#[cfg(not(windows))]
fn rsa_public_key_from_spki(spki_der: &[u8]) -> Result<RsaPublicKey, String> {
    RsaPublicKey::from_public_key_der(spki_der).map_err(|e| format!("bad RSA public key: {e}"))
}

#[cfg(not(windows))]
fn verify_cert_signature(issuer_spki_der: &[u8], tbs_der: &[u8], signature_oid: &str, signature: &[u8]) -> Result<(), String> {
    match signature_oid {
        // sha256WithRSAEncryption / sha384WithRSAEncryption / sha512WithRSAEncryption
        "1.2.840.113549.1.1.11" => {
            let key = rsa_public_key_from_spki(issuer_spki_der)?;
            let vk = pkcs1v15::VerifyingKey::<Sha256>::new(key);
            let sig = pkcs1v15::Signature::try_from(signature).map_err(|e| format!("bad RSA signature bytes: {e}"))?;
            vk.verify(tbs_der, &sig).map_err(|_| "certificate signature verification failed".to_string())
        }
        "1.2.840.113549.1.1.12" => {
            let key = rsa_public_key_from_spki(issuer_spki_der)?;
            let vk = pkcs1v15::VerifyingKey::<Sha384>::new(key);
            let sig = pkcs1v15::Signature::try_from(signature).map_err(|e| format!("bad RSA signature bytes: {e}"))?;
            vk.verify(tbs_der, &sig).map_err(|_| "certificate signature verification failed".to_string())
        }
        "1.2.840.113549.1.1.13" => {
            let key = rsa_public_key_from_spki(issuer_spki_der)?;
            let vk = pkcs1v15::VerifyingKey::<Sha512>::new(key);
            let sig = pkcs1v15::Signature::try_from(signature).map_err(|e| format!("bad RSA signature bytes: {e}"))?;
            vk.verify(tbs_der, &sig).map_err(|_| "certificate signature verification failed".to_string())
        }

        // ecdsa-with-SHA256 / SHA384 / SHA512
        "1.2.840.10045.4.3.2" => {
            let pk = p256::PublicKey::from_public_key_der(issuer_spki_der)
                .map_err(|e| format!("bad P-256 issuer public key: {e}"))?;
            let ep = pk.to_encoded_point(false);
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(ep.as_bytes())
                .map_err(|e| format!("bad P-256 issuer public key: {e}"))?;
            let sig = p256::ecdsa::Signature::from_der(signature)
                .map_err(|e| format!("bad ECDSA signature bytes: {e}"))?;
            vk.verify(tbs_der, &sig).map_err(|_| "certificate signature verification failed".to_string())
        }
        "1.2.840.10045.4.3.3" => {
            let pk = p384::PublicKey::from_public_key_der(issuer_spki_der)
                .map_err(|e| format!("bad P-384 issuer public key: {e}"))?;
            let ep = pk.to_encoded_point(false);
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(ep.as_bytes())
                .map_err(|e| format!("bad P-384 issuer public key: {e}"))?;
            let sig = p384::ecdsa::Signature::from_der(signature)
                .map_err(|e| format!("bad ECDSA signature bytes: {e}"))?;
            vk.verify(tbs_der, &sig).map_err(|_| "certificate signature verification failed".to_string())
        }
        "1.2.840.10045.4.3.4" => {
            let pk = p521::PublicKey::from_public_key_der(issuer_spki_der)
                .map_err(|e| format!("bad P-521 issuer public key: {e}"))?;
            let ep = pk.to_encoded_point(false);
            let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(ep.as_bytes())
                .map_err(|e| format!("bad P-521 issuer public key: {e}"))?;
            let sig = p521::ecdsa::Signature::from_der(signature)
                .map_err(|e| format!("bad ECDSA signature bytes: {e}"))?;
            vk.verify(tbs_der, &sig).map_err(|_| "certificate signature verification failed".to_string())
        }

        _ => Err(format!("unsupported certificate signature algorithm OID: {signature_oid}")),
    }
}

#[cfg(not(windows))]
fn load_system_roots() -> Result<Vec<ParsedCert>, String> {
    let roots = rustls_native_certs::load_native_certs();
    let mut out = Vec::new();
    for r in roots.certs {
        // `rustls-native-certs` returns cert DER bytes. Parse best-effort.
        let der = r.as_ref().to_vec();
        if der.is_empty() {
            continue;
        }
        if let Ok(pc) = parse_cert_der(&der) {
            out.push(pc);
        }
    }
    Ok(out)
}

#[cfg(windows)]
pub fn validate_x5c_chain(validator_name: &str, x5c_certs_der: &[Vec<u8>], chain_options: &X509ChainVerifyOptions) -> ValidationResult {
    // Windows implementation: use CryptoAPI for chain building, trust, and revocation.
    unsafe {
        if x5c_certs_der.is_empty() || x5c_certs_der[0].is_empty() {
            let mut r = ValidationResult::failure_message(
                validator_name,
                "x5c header (label 33) not found or invalid",
                Some("MISSING_X5C".to_string()),
            );
            r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
            return r;
        }

        let leaf_der = &x5c_certs_der[0];
        let leaf = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            leaf_der.as_ptr(),
            leaf_der.len() as u32,
        );
        if leaf.is_null() {
            let mut r = ValidationResult::failure_message(
                validator_name,
                "x5c leaf certificate was invalid DER",
                Some("INVALID_X5C".to_string()),
            );
            r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
            return r;
        }

        struct CertCtx(*const CERT_CONTEXT);
        impl Drop for CertCtx {
            fn drop(&mut self) {
                unsafe {
                    if !self.0.is_null() {
                        CertFreeCertificateContext(self.0);
                    }
                }
            }
        }
        let leaf = CertCtx(leaf);

        struct Store(HCERTSTORE);
        impl Drop for Store {
            fn drop(&mut self) {
                unsafe {
                    if !self.0.is_null() {
                        CertCloseStore(self.0, 0);
                    }
                }
            }
        }

        let extra_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, std::ptr::null());
        if extra_store.is_null() {
            let mut r = ValidationResult::failure_message(
                validator_name,
                "failed to create certificate store",
                Some("CERT_CHAIN_STORE_ERROR".to_string()),
            );
            r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
            return r;
        }
        let extra_store = Store(extra_store);

        let add_der_to_store = |store: HCERTSTORE, der: &[u8]| -> bool {
            if store.is_null() || der.is_empty() {
                return false;
            }
            CertAddEncodedCertificateToStore(
                store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                der.as_ptr(),
                der.len() as u32,
                CERT_STORE_ADD_ALWAYS,
                std::ptr::null_mut(),
            ) != 0
        };

        // Add intermediates.
        for der in x5c_certs_der.iter().skip(1) {
            if der.is_empty() {
                continue;
            }
            let _ = add_der_to_store(extra_store.0, der);
        }

        // In custom-roots mode, add caller-provided roots into the store so the chain builder can locate them.
        if chain_options.trust_mode == X509TrustMode::CustomRoots {
            if chain_options.trusted_roots_der.is_empty() {
                let mut r = ValidationResult::failure_message(
                    validator_name,
                    "custom root trust mode requires at least one trusted root",
                    Some("CERT_CHAIN_NO_TRUST_ANCHORS".to_string()),
                );
                r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
                return r;
            }
            for root_der in &chain_options.trusted_roots_der {
                if !add_der_to_store(extra_store.0, root_der) {
                    let mut r = ValidationResult::failure_message(
                        validator_name,
                        "failed to add a trusted root certificate",
                        Some("CERT_CHAIN_TRUST_ANCHOR_ERROR".to_string()),
                    );
                    r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
                    return r;
                }
            }
        }

        let flags: u32 = match chain_options.revocation_mode {
            X509RevocationMode::Online => CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
            X509RevocationMode::Offline => {
                CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY
            }
            X509RevocationMode::NoCheck => 0,
        };

        let mut chain_para: CERT_CHAIN_PARA = std::mem::zeroed();
        chain_para.cbSize = std::mem::size_of::<CERT_CHAIN_PARA>() as u32;

        let mut chain_ctx: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
        let ok = CertGetCertificateChain(
            0,
            leaf.0,
            std::ptr::null(),
            extra_store.0,
            &mut chain_para,
            flags,
            std::ptr::null_mut(),
            &mut chain_ctx,
        );

        if ok == 0 || chain_ctx.is_null() {
            let mut r = ValidationResult::failure_message(
                validator_name,
                "failed to build certificate chain",
                Some("CERT_CHAIN_BUILD_ERROR".to_string()),
            );
            r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
            return r;
        }

        struct ChainCtx(*mut CERT_CHAIN_CONTEXT);
        impl Drop for ChainCtx {
            fn drop(&mut self) {
                unsafe {
                    if !self.0.is_null() {
                        CertFreeCertificateChain(self.0);
                    }
                }
            }
        }
        let chain_ctx = ChainCtx(chain_ctx);

        let mut error_status = (*chain_ctx.0).TrustStatus.dwErrorStatus;

        // In custom-roots mode, enforce exact DER match for the chain root.
        if chain_options.trust_mode == X509TrustMode::CustomRoots && (*chain_ctx.0).cChain > 0 {
            let simple = *(*chain_ctx.0).rgpChain;
            if !simple.is_null() && (*simple).cElement > 0 {
                let last = *(*simple).rgpElement.add(((*simple).cElement - 1) as usize);
                let root_ctx = if last.is_null() { std::ptr::null() } else { (*last).pCertContext };

                let mut exact_match = false;
                if !root_ctx.is_null() && !(*root_ctx).pbCertEncoded.is_null() && (*root_ctx).cbCertEncoded > 0 {
                    let root_bytes = std::slice::from_raw_parts((*root_ctx).pbCertEncoded, (*root_ctx).cbCertEncoded as usize);
                    for trusted in &chain_options.trusted_roots_der {
                        if trusted.as_slice() == root_bytes {
                            exact_match = true;
                            break;
                        }
                    }
                }

                if !exact_match {
                    let mut r = ValidationResult::failure_message(
                        validator_name,
                        "Certificate chain did not build to one of the caller-provided trusted roots.",
                        Some("CERT_CHAIN_NOT_AN_EXACT_TRUST_ANCHOR".to_string()),
                    );
                    r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
                    return r;
                }

                // If we matched an exact caller-provided root, treat that root as trusted.
                error_status &= !CERT_TRUST_IS_UNTRUSTED_ROOT;
            }
        }

        if error_status == CERT_TRUST_NO_ERROR {
            let mut ok = ValidationResult::success(validator_name, Default::default());
            ok.metadata.insert("x5c.chain_valid".to_string(), "true".to_string());
            return ok;
        }

        let (code, message) = if (error_status & CERT_TRUST_IS_UNTRUSTED_ROOT) != 0 {
            ("CERT_CHAIN_UNTRUSTED_ROOT", "Certificate chain ends in an untrusted root.")
        } else {
            ("CERT_CHAIN_INVALID", "Certificate chain validation failed.")
        };

        let mut r = ValidationResult::failure_message(validator_name, message, Some(code.to_string()));
        r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
        r
    }
}

#[cfg(not(windows))]
pub fn validate_x5c_chain(validator_name: &str, x5c_certs_der: &[Vec<u8>], chain_options: &X509ChainVerifyOptions) -> ValidationResult {
    // Match native behavior: non-Windows revocation is unsupported.
    if chain_options.revocation_mode != X509RevocationMode::NoCheck {
        let mut r = ValidationResult::failure_message(
            validator_name,
            "revocation checking is not supported on this platform",
            Some("CERT_CHAIN_REVOCATION_NOT_SUPPORTED".to_string()),
        );
        r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
        return r;
    }

    if x5c_certs_der.is_empty() || x5c_certs_der[0].is_empty() {
        let mut r = ValidationResult::failure_message(
            validator_name,
            "x5c header (label 33) not found or invalid",
            Some("MISSING_X5C".to_string()),
        );
        r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
        return r;
    }

    let leaf = match parse_cert_der(&x5c_certs_der[0]) {
        Ok(c) => c,
        Err(_) => {
            let mut r = ValidationResult::failure_message(
                validator_name,
                "x5c leaf certificate was invalid DER",
                Some("INVALID_X5C".to_string()),
            );
            r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
            return r;
        }
    };

    let mut provided_intermediates = Vec::new();
    for der in x5c_certs_der.iter().skip(1) {
        if der.is_empty() {
            continue;
        }
        if let Ok(c) = parse_cert_der(der) {
            provided_intermediates.push(c);
        }
    }

    // Build trust anchors.
    let anchors: Vec<ParsedCert> = match chain_options.trust_mode {
        X509TrustMode::System => match load_system_roots() {
            Ok(v) => v,
            Err(_) => {
                let mut r = ValidationResult::failure_message(
                    validator_name,
                    "failed to load system trust store",
                    Some("CERT_CHAIN_STORE_ERROR".to_string()),
                );
                r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
                return r;
            }
        },
        X509TrustMode::CustomRoots => {
            if chain_options.trusted_roots_der.is_empty() {
                let mut r = ValidationResult::failure_message(
                    validator_name,
                    "custom root trust mode requires at least one trusted root",
                    Some("CERT_CHAIN_NO_TRUST_ANCHORS".to_string()),
                );
                r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
                return r;
            }

            let mut out = Vec::new();
            for root_der in &chain_options.trusted_roots_der {
                match parse_cert_der(root_der) {
                    Ok(c) => out.push(c),
                    Err(_) => {
                        let mut r = ValidationResult::failure_message(
                            validator_name,
                            "failed to parse a trusted root certificate",
                            Some("CERT_CHAIN_TRUST_ANCHOR_ERROR".to_string()),
                        );
                        r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
                        return r;
                    }
                }
            }
            out
        }
    };

    // Special-case: leaf itself is an allowed custom root.
    if chain_options.trust_mode == X509TrustMode::CustomRoots
        && chain_options
            .trusted_roots_der
            .iter()
            .any(|r| r.as_slice() == leaf.der.as_slice())
    {
        let mut ok = ValidationResult::success(validator_name, Default::default());
        ok.metadata.insert("x5c.chain_valid".to_string(), "true".to_string());
        return ok;
    }

    // Attempt to build a chain leaf -> ... -> anchor.
    let mut current = leaf;
    let mut depth = 0usize;
    const MAX_DEPTH: usize = 16;
    while depth < MAX_DEPTH {
        depth += 1;

        // Prefer issuers from the provided x5c intermediates, then fall back to trust anchors.
        let mut found: Option<ParsedCert> = None;

        for issuer in provided_intermediates.iter().chain(anchors.iter()) {
            if issuer.subject_dn != current.issuer_dn {
                continue;
            }

            if verify_cert_signature(&issuer.spki_der, &current.tbs_der, &current.signature_oid, &current.signature).is_ok() {
                found = Some(issuer.clone());
                break;
            }
        }

        let Some(issuer) = found else {
            // Unable to build to a trusted root.
            let mut r = ValidationResult::failure_message(
                validator_name,
                "certificate chain ends in an untrusted root",
                Some("CERT_CHAIN_UNTRUSTED_ROOT".to_string()),
            );
            r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
            return r;
        };

        // If the issuer we found is one of our trust anchors, the chain is valid.
        let issuer_is_anchor = anchors.iter().any(|a| a.der == issuer.der);
        if issuer_is_anchor {
            // In custom-roots mode, enforce exact DER match semantics for the terminating root.
            if chain_options.trust_mode == X509TrustMode::CustomRoots
                && !chain_options
                    .trusted_roots_der
                    .iter()
                    .any(|r| r.as_slice() == issuer.der.as_slice())
            {
                let mut r = ValidationResult::failure_message(
                    validator_name,
                    "certificate chain did not terminate at an exact trusted root",
                    Some("CERT_CHAIN_NOT_AN_EXACT_TRUST_ANCHOR".to_string()),
                );
                r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
                return r;
            }

            let mut ok = ValidationResult::success(validator_name, Default::default());
            ok.metadata.insert("x5c.chain_valid".to_string(), "true".to_string());
            return ok;
        }

        current = issuer;
    }

    let mut r = ValidationResult::failure_message(
        validator_name,
        "failed to build certificate chain",
        Some("CERT_CHAIN_BUILD_ERROR".to_string()),
    );
    r.metadata.insert("x5c.chain_valid".to_string(), "false".to_string());
    r
}


