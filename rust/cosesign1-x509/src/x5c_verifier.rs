// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Verification entry points that use the COSE `x5c` header.
//!
//! The COSE header parameter `x5c` (label 33) contains a certificate chain.
//! This module:
//! - Extracts the leaf certificate DER from `x5c[0]`.
//! - Uses that DER certificate as the public key input to the core verifier.
//!
//! This provides a practical interoperability bridge while full X.509 chain
//! evaluation is still being built in the Rust port.

use cosesign1_common::{parse_cose_sign1, HeaderValue, ParsedCoseSign1};
use cosesign1_validation::{verify_parsed_cose_sign1, ValidationResult, VerifyOptions};

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

pub fn verify_cose_sign1_with_x5c(
    validator_name: &str,
    cose_sign1: &[u8],
    options: &VerifyOptions,
    chain_options: Option<&X509ChainVerifyOptions>,
) -> ValidationResult {
    // Parse first; x5c extraction requires the headers.
    let parsed = match parse_cose_sign1(cose_sign1) {
        Ok(p) => p,
        Err(e) => return ValidationResult::failure_message(validator_name, e, Some("COSE_PARSE_ERROR".to_string())),
    };

    verify_parsed_cose_sign1_with_x5c(validator_name, &parsed, options, chain_options)
}

pub fn verify_parsed_cose_sign1_with_x5c(
    validator_name: &str,
    parsed: &ParsedCoseSign1,
    options: &VerifyOptions,
    chain_options: Option<&X509ChainVerifyOptions>,
) -> ValidationResult {
    // x5c header label is 33.
    // COSE allows headers to be in protected or unprotected maps.
    let x5c = parsed
        .protected_headers
        .get_array(33)
        .or_else(|| parsed.unprotected_headers.get_array(33));

    let Some(x5c) = x5c else {
        return ValidationResult::failure_message(validator_name, "missing x5c header", Some("MISSING_X5C".to_string()));
    };

    let mut certs_der = Vec::new();
    // x5c must be an array of bstr elements.
    for v in x5c {
        match v {
            HeaderValue::Bytes(b) => certs_der.push(b.clone()),
            _ => return ValidationResult::failure_message(validator_name, "x5c must be array of bstr", Some("X5C_TYPE_ERROR".to_string())),
        }
    }

    let Some(leaf_der) = certs_der.first() else {
        return ValidationResult::failure_message(validator_name, "x5c is empty", Some("X5C_EMPTY".to_string()));
    };

    match chain_options {
        Some(chain) => {
            // Parity gap: revocation checking is not implemented in the Rust port.
            if chain.revocation_mode != X509RevocationMode::NoCheck {
                return ValidationResult::failure_message(
                    validator_name,
                    "revocation checking not implemented in Rust yet",
                    Some("REVOCATION_UNSUPPORTED".to_string()),
                );
            }

            // Parity note: full X.509 path building + trust evaluation is not implemented yet.
            // We only support allow_untrusted_roots=true as a diagnostic mode for now.
            if !chain.allow_untrusted_roots {
                return ValidationResult::failure_message(
                    validator_name,
                    "X.509 chain trust evaluation not implemented in Rust yet",
                    Some("CHAIN_VERIFY_UNSUPPORTED".to_string()),
                );
            }
        }
        None => {}
    }

    // Clone and override the public key input so the core verifier uses the leaf certificate.
    // The core verifier accepts cert DER and will extract SPKI as needed.
    let mut opts = options.clone();
    opts.public_key_bytes = Some(leaf_der.clone());

    // Detached payload handling is delegated to the core verifier.
    let external = options.external_payload.as_deref().or_else(|| parsed.payload.as_deref());
    verify_parsed_cose_sign1(validator_name, parsed, external, &opts)
}
