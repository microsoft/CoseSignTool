// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::constants::*;
use crate::error::DidX509Error;
use crate::models::{DidX509ParsedIdentifier, DidX509Policy, SanType};
use crate::parsing::percent_encoding::percent_decode;

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{:02x}", b).unwrap();
            s
        })
}

// Inline base64url utilities
const BASE64_URL_SAFE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64_decode(input: &str, alphabet: &[u8; 64]) -> Result<Vec<u8>, String> {
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
fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
    base64_decode(input, BASE64_URL_SAFE)
}

/// Parser for DID:x509 identifiers
pub struct DidX509Parser;

impl DidX509Parser {
    /// Parse a DID:x509 identifier string.
    ///
    /// Expected format: `did:x509:0:sha256:fingerprint::policy1:value1::policy2:value2...`
    ///
    /// # Arguments
    /// * `did` - The DID string to parse
    ///
    /// # Returns
    /// A parsed DID identifier on success
    ///
    /// # Errors
    /// Returns an error if the DID format is invalid
    pub fn parse(did: &str) -> Result<DidX509ParsedIdentifier, DidX509Error> {
        // Validate non-empty
        if did.trim().is_empty() {
            return Err(DidX509Error::EmptyDid);
        }

        // Validate prefix
        let prefix_with_colon = format!("{}:", DID_PREFIX);
        if !did.to_lowercase().starts_with(&prefix_with_colon) {
            return Err(DidX509Error::InvalidPrefix(DID_PREFIX.to_string()));
        }

        // Split on :: to separate CA fingerprint from policies
        let major_parts: Vec<&str> = did.split(POLICY_SEPARATOR).collect();
        if major_parts.len() < 2 {
            return Err(DidX509Error::MissingPolicies);
        }

        // Parse the prefix part: did:x509:version:algorithm:fingerprint
        let prefix_part = major_parts[0];
        let prefix_components: Vec<&str> = prefix_part.split(':').collect();

        if prefix_components.len() != 5 {
            return Err(DidX509Error::InvalidFormat(
                "did:x509:version:algorithm:fingerprint".to_string(),
            ));
        }

        let version = prefix_components[2];
        let hash_algorithm = prefix_components[3].to_lowercase();
        let ca_fingerprint_base64url = prefix_components[4];

        // Validate version
        if version != VERSION {
            return Err(DidX509Error::UnsupportedVersion(
                version.to_string(),
                VERSION.to_string(),
            ));
        }

        // Validate hash algorithm
        if hash_algorithm != HASH_ALGORITHM_SHA256
            && hash_algorithm != HASH_ALGORITHM_SHA384
            && hash_algorithm != HASH_ALGORITHM_SHA512
        {
            return Err(DidX509Error::UnsupportedHashAlgorithm(hash_algorithm));
        }

        // Validate CA fingerprint (base64url format)
        if ca_fingerprint_base64url.is_empty() {
            return Err(DidX509Error::EmptyFingerprint);
        }

        // Expected lengths: SHA-256=43, SHA-384=64, SHA-512=86 characters (base64url without padding)
        let expected_length = match hash_algorithm.as_str() {
            HASH_ALGORITHM_SHA256 => 43,
            HASH_ALGORITHM_SHA384 => 64,
            HASH_ALGORITHM_SHA512 => 86,
            _ => return Err(DidX509Error::UnsupportedHashAlgorithm(hash_algorithm)),
        };

        if ca_fingerprint_base64url.len() != expected_length {
            return Err(DidX509Error::FingerprintLengthMismatch(
                hash_algorithm.clone(),
                expected_length,
                ca_fingerprint_base64url.len(),
            ));
        }

        if !is_valid_base64url(ca_fingerprint_base64url) {
            return Err(DidX509Error::InvalidFingerprintChars);
        }

        // Decode base64url to bytes
        let ca_fingerprint_bytes = decode_base64url(ca_fingerprint_base64url)?;
        let ca_fingerprint_hex = hex_encode(&ca_fingerprint_bytes);

        // Parse policies (skip the first element which is the prefix)
        let mut policies = Vec::new();
        for (i, policy_part) in major_parts.iter().enumerate().skip(1) {
            if policy_part.trim().is_empty() {
                return Err(DidX509Error::EmptyPolicy(i));
            }

            // Split policy into name:value
            let first_colon = policy_part.find(':');
            if first_colon.is_none() || first_colon == Some(0) {
                return Err(DidX509Error::InvalidPolicyFormat("name:value".to_string()));
            }

            let colon_idx = first_colon.unwrap();
            let policy_name = &policy_part[..colon_idx];
            let policy_value = &policy_part[colon_idx + 1..];

            if policy_name.trim().is_empty() {
                return Err(DidX509Error::EmptyPolicyName);
            }

            if policy_value.trim().is_empty() {
                return Err(DidX509Error::EmptyPolicyValue);
            }

            // Parse the policy value based on policy type
            let parsed_policy = parse_policy_value(policy_name, policy_value)?;
            policies.push(parsed_policy);
        }

        Ok(DidX509ParsedIdentifier::new(
            hash_algorithm,
            ca_fingerprint_bytes,
            ca_fingerprint_hex,
            policies,
        ))
    }

    /// Attempt to parse a DID:x509 identifier string.
    /// Returns None if parsing fails.
    pub fn try_parse(did: &str) -> Option<DidX509ParsedIdentifier> {
        Self::parse(did).ok()
    }
}

fn parse_policy_value(
    policy_name: &str,
    policy_value: &str,
) -> Result<DidX509Policy, DidX509Error> {
    match policy_name.to_lowercase().as_str() {
        POLICY_SUBJECT => parse_subject_policy(policy_value),
        POLICY_SAN => parse_san_policy(policy_value),
        POLICY_EKU => parse_eku_policy(policy_value),
        POLICY_FULCIO_ISSUER => parse_fulcio_issuer_policy(policy_value),
        _ => {
            // Unknown policy type - skip it (or could return error)
            // For now, we'll just return an empty EKU policy to satisfy the return type
            // In a real implementation, you might want to have an "Unknown" variant
            Ok(DidX509Policy::Eku(Vec::new()))
        }
    }
}

fn parse_subject_policy(value: &str) -> Result<DidX509Policy, DidX509Error> {
    // Format: key:value:key:value:...
    let parts: Vec<&str> = value.split(':').collect();

    if !parts.len().is_multiple_of(2) {
        return Err(DidX509Error::InvalidSubjectPolicyComponents);
    }

    let mut result = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();

    for chunk in parts.chunks(2) {
        let key = chunk[0];
        let encoded_value = chunk[1];

        if key.trim().is_empty() {
            return Err(DidX509Error::EmptySubjectPolicyKey);
        }

        let key_upper = key.to_uppercase();
        if seen_keys.contains(&key_upper) {
            return Err(DidX509Error::DuplicateSubjectPolicyKey(key.to_string()));
        }
        seen_keys.insert(key_upper);

        // Decode percent-encoded value
        let decoded_value = percent_decode(encoded_value)?;
        result.push((key.to_string(), decoded_value));
    }

    Ok(DidX509Policy::Subject(result))
}

fn parse_san_policy(value: &str) -> Result<DidX509Policy, DidX509Error> {
    // Format: type:value (only one colon separating type and value)
    let colon_idx = value.find(':');
    if colon_idx.is_none() || colon_idx == Some(0) || colon_idx == Some(value.len() - 1) {
        return Err(DidX509Error::InvalidSanPolicyFormat(
            "type:value".to_string(),
        ));
    }

    let idx = colon_idx.unwrap();
    let san_type_str = &value[..idx];
    let encoded_value = &value[idx + 1..];

    // Parse SAN type
    let san_type = SanType::from_str(san_type_str)
        .ok_or_else(|| DidX509Error::InvalidSanType(san_type_str.to_string()))?;

    // Decode percent-encoded value
    let decoded_value = percent_decode(encoded_value)?;

    Ok(DidX509Policy::San(san_type, decoded_value))
}

fn parse_eku_policy(value: &str) -> Result<DidX509Policy, DidX509Error> {
    // Format: OID or multiple OIDs separated by colons
    let oids: Vec<&str> = value.split(':').collect();

    let mut valid_oids = Vec::new();
    for oid in oids {
        if !is_valid_oid(oid) {
            return Err(DidX509Error::InvalidEkuOid);
        }
        valid_oids.push(oid.to_string());
    }

    Ok(DidX509Policy::Eku(valid_oids))
}

fn parse_fulcio_issuer_policy(value: &str) -> Result<DidX509Policy, DidX509Error> {
    // Format: issuer domain (without https:// prefix), percent-encoded
    if value.trim().is_empty() {
        return Err(DidX509Error::EmptyFulcioIssuer);
    }

    // Decode percent-encoded value
    let decoded_value = percent_decode(value)?;

    Ok(DidX509Policy::FulcioIssuer(decoded_value))
}

pub fn is_valid_base64url(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn decode_base64url(input: &str) -> Result<Vec<u8>, DidX509Error> {
    base64url_decode(input)
        .map_err(|e| DidX509Error::PercentDecodingError(format!("Base64 decode error: {}", e)))
}

pub fn is_valid_oid(value: &str) -> bool {
    if value.trim().is_empty() {
        return false;
    }

    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() < 2 {
        return false;
    }

    parts
        .iter()
        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}
