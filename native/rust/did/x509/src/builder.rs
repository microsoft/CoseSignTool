// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::constants::*;
use crate::error::DidX509Error;
use crate::models::policy::{DidX509Policy, SanType};
use crate::parsing::percent_encoding;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_parser::prelude::*;

// Inline base64url utilities
const BASE64_URL_SAFE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64_encode(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 2 < input.len() {
        let n = (input[i] as u32) << 16 | (input[i + 1] as u32) << 8 | input[i + 2] as u32;
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 6) & 0x3F) as usize] as char);
        out.push(alphabet[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        if pad {
            out.push_str("==");
        }
    } else if rem == 2 {
        let n = (input[i] as u32) << 16 | (input[i + 1] as u32) << 8;
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 6) & 0x3F) as usize] as char);
        if pad {
            out.push('=');
        }
    }
    out
}

/// Encode bytes as base64url (no padding).
fn base64url_encode(input: &[u8]) -> String {
    base64_encode(input, BASE64_URL_SAFE, false)
}

/// Builder for constructing DID:x509 identifiers from certificate chains.
pub struct DidX509Builder;

impl DidX509Builder {
    /// Build a DID:x509 string from a CA certificate and policies.
    ///
    /// # Arguments
    /// * `ca_cert_der` - DER-encoded CA (trust anchor) certificate
    /// * `policies` - Policies to include (eku, subject, san, fulcio-issuer)
    /// * `hash_algorithm` - Hash algorithm name ("sha256", "sha384", "sha512")
    ///
    /// # Returns
    /// DID string like `did:x509:0:sha256:<fingerprint>::eku:<oid1>:<oid2>`
    pub fn build(
        ca_cert_der: &[u8],
        policies: &[DidX509Policy],
        hash_algorithm: &str,
    ) -> Result<String, DidX509Error> {
        // 1. Hash the CA cert DER to get fingerprint
        let fingerprint = Self::compute_fingerprint(ca_cert_der, hash_algorithm)?;
        let fingerprint_base64url = Self::encode_base64url(&fingerprint);

        // 2. Start building: did:x509:0:<hash_alg>:<fingerprint>
        let mut did = format!(
            "{}:{}:{}",
            FULL_DID_PREFIX, hash_algorithm, fingerprint_base64url
        );

        // 3. Append each policy
        for policy in policies {
            did.push_str(POLICY_SEPARATOR);
            did.push_str(&Self::encode_policy(policy)?);
        }

        Ok(did)
    }

    /// Convenience: build with SHA-256 (most common)
    pub fn build_sha256(
        ca_cert_der: &[u8],
        policies: &[DidX509Policy],
    ) -> Result<String, DidX509Error> {
        Self::build(ca_cert_der, policies, HASH_ALGORITHM_SHA256)
    }

    /// Build from a certificate chain (leaf-first order).
    /// Uses the LAST cert in chain (root/CA) as the trust anchor.
    pub fn build_from_chain(
        chain: &[&[u8]],
        policies: &[DidX509Policy],
    ) -> Result<String, DidX509Error> {
        if chain.is_empty() {
            return Err(DidX509Error::InvalidChain("Empty chain".into()));
        }
        let ca_cert = chain.last().unwrap();
        Self::build_sha256(ca_cert, policies)
    }

    /// Build with EKU policy extracted from the leaf certificate.
    /// This is the most common pattern for SCITT compliance.
    pub fn build_from_chain_with_eku(chain: &[&[u8]]) -> Result<String, DidX509Error> {
        if chain.is_empty() {
            return Err(DidX509Error::InvalidChain("Empty chain".into()));
        }
        // Parse leaf cert to extract EKU OIDs
        let leaf_der = chain[0];
        let (_, leaf_cert) = X509Certificate::from_der(leaf_der)
            .map_err(|e| DidX509Error::CertificateParseError(e.to_string()))?;

        let eku_oids = crate::x509_extensions::extract_eku_oids(&leaf_cert)?;
        if eku_oids.is_empty() {
            return Err(DidX509Error::PolicyValidationFailed(
                "No EKU found on leaf cert".into(),
            ));
        }

        let policy = DidX509Policy::Eku(eku_oids);
        Self::build_from_chain(chain, &[policy])
    }

    fn compute_fingerprint(cert_der: &[u8], hash_algorithm: &str) -> Result<Vec<u8>, DidX509Error> {
        match hash_algorithm {
            HASH_ALGORITHM_SHA256 => Ok(Sha256::digest(cert_der).to_vec()),
            HASH_ALGORITHM_SHA384 => Ok(Sha384::digest(cert_der).to_vec()),
            HASH_ALGORITHM_SHA512 => Ok(Sha512::digest(cert_der).to_vec()),
            _ => Err(DidX509Error::UnsupportedHashAlgorithm(
                hash_algorithm.to_string(),
            )),
        }
    }

    fn encode_base64url(data: &[u8]) -> String {
        base64url_encode(data)
    }

    fn encode_policy(policy: &DidX509Policy) -> Result<String, DidX509Error> {
        match policy {
            DidX509Policy::Eku(oids) => {
                // eku:<oid1>:<oid2>:...
                let encoded: Vec<String> = oids
                    .iter()
                    .map(|oid| percent_encoding::percent_encode(oid))
                    .collect();
                Ok(format!("{}:{}", POLICY_EKU, encoded.join(VALUE_SEPARATOR)))
            }
            DidX509Policy::Subject(attrs) => {
                // subject:<attr1>:<val1>:<attr2>:<val2>:...
                let mut parts = vec![POLICY_SUBJECT.to_string()];
                for (attr, val) in attrs {
                    parts.push(percent_encoding::percent_encode(attr));
                    parts.push(percent_encoding::percent_encode(val));
                }
                Ok(parts.join(VALUE_SEPARATOR))
            }
            DidX509Policy::San(san_type, value) => {
                let type_str = match san_type {
                    SanType::Email => SAN_TYPE_EMAIL,
                    SanType::Dns => SAN_TYPE_DNS,
                    SanType::Uri => SAN_TYPE_URI,
                    SanType::Dn => SAN_TYPE_DN,
                };
                Ok(format!(
                    "{}:{}:{}",
                    POLICY_SAN,
                    type_str,
                    percent_encoding::percent_encode(value)
                ))
            }
            DidX509Policy::FulcioIssuer(issuer) => Ok(format!(
                "{}:{}",
                POLICY_FULCIO_ISSUER,
                percent_encoding::percent_encode(issuer)
            )),
        }
    }
}
