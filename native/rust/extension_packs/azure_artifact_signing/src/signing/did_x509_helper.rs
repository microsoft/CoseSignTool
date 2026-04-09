// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DID:x509 identifier construction for Azure Artifact Signing certificates.
//!
//! Maps V2 `AzureArtifactSigningDidX509` — generates DID:x509 identifiers
//! using the "deepest greatest" Microsoft EKU from the leaf certificate.
//!
//! Format: `did:x509:0:sha256:{base64url-hash}::eku:{oid}`

use crate::error::AasError;

/// Microsoft reserved EKU OID prefix used by Azure Artifact Signing certificates.
const MICROSOFT_EKU_PREFIX: &str = "1.3.6.1.4.1.311";

/// Build a DID:x509 identifier from an AAS-issued certificate chain.
///
/// Uses AAS-specific logic:
/// 1. Extract EKU OIDs from the leaf certificate
/// 2. Filter to Microsoft EKUs (prefix `1.3.6.1.4.1.311`)
/// 3. Select the "deepest greatest" Microsoft EKU (most segments, then highest last segment)
/// 4. Build DID:x509 with that specific EKU policy
///
/// Falls back to generic `build_from_chain_with_eku()` if no Microsoft EKU is found.
pub fn build_did_x509_from_ats_chain(chain_ders: &[&[u8]]) -> Result<String, AasError> {
    // Try AAS-specific Microsoft EKU selection first
    if let Some(microsoft_eku) = find_deepest_greatest_microsoft_eku(chain_ders) {
        // Build DID:x509 with the specific Microsoft EKU
        let policy = did_x509::DidX509Policy::Eku(vec![microsoft_eku.into()]);
        did_x509::DidX509Builder::build_from_chain(chain_ders, &[policy])
            .map_err(|e| AasError::DidX509Error(e.to_string()))
    } else {
        // No Microsoft EKU found — use generic EKU-based builder
        did_x509::DidX509Builder::build_from_chain_with_eku(chain_ders)
            .map_err(|e| AasError::DidX509Error(e.to_string()))
    }
}

/// Find the "deepest greatest" Microsoft EKU from the leaf certificate.
///
/// Maps V2 `AzureArtifactSigningDidX509.GetDeepestGreatestMicrosoftEku()`.
///
/// Selection criteria:
/// 1. Filter to Microsoft EKUs (starting with `1.3.6.1.4.1.311`)
/// 2. Select the OID with the most segments (deepest)
/// 3. If tied, select the one with the greatest last segment value
fn find_deepest_greatest_microsoft_eku(chain_ders: &[&[u8]]) -> Option<String> {
    if chain_ders.is_empty() {
        return None;
    }

    // Parse the leaf certificate to extract EKU OIDs
    let leaf_der = chain_ders[0];
    let ekus = extract_eku_oids(leaf_der)?;

    // Filter to Microsoft EKUs
    let microsoft_ekus: Vec<&String> = ekus
        .iter()
        .filter(|oid| oid.starts_with(MICROSOFT_EKU_PREFIX))
        .collect();

    if microsoft_ekus.is_empty() {
        return None;
    }

    // Select deepest (most segments), then greatest (highest last segment)
    microsoft_ekus
        .into_iter()
        .max_by(|a, b| {
            let segments_a = a.split('.').count();
            let segments_b = b.split('.').count();
            segments_a
                .cmp(&segments_b)
                .then_with(|| last_segment_value(a).cmp(&last_segment_value(b)))
        })
        .cloned()
}

/// Extract EKU OIDs from a DER-encoded X.509 certificate.
///
/// Uses `x509-parser` to parse the certificate and extract Extended Key Usage
/// OIDs from the EKU extension.
///
/// Returns None if parsing fails or no EKU extension is present.
fn extract_eku_oids(cert_der: &[u8]) -> Option<Vec<String>> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let eku_ext = cert.extended_key_usage().ok().flatten()?;
    let eku = &eku_ext.value;

    let mut oids = Vec::new();
    if eku.any {
        oids.push("2.5.29.37.0".to_string());
    }
    if eku.server_auth {
        oids.push("1.3.6.1.5.5.7.3.1".to_string());
    }
    if eku.client_auth {
        oids.push("1.3.6.1.5.5.7.3.2".to_string());
    }
    if eku.code_signing {
        oids.push("1.3.6.1.5.5.7.3.3".to_string());
    }
    if eku.email_protection {
        oids.push("1.3.6.1.5.5.7.3.4".to_string());
    }
    if eku.time_stamping {
        oids.push("1.3.6.1.5.5.7.3.8".to_string());
    }
    if eku.ocsp_signing {
        oids.push("1.3.6.1.5.5.7.3.9".to_string());
    }
    for other_oid in &eku.other {
        oids.push(other_oid.to_id_string());
    }

    if oids.is_empty() {
        None
    } else {
        Some(oids)
    }
}

/// Get the numeric value of the last segment of an OID.
fn last_segment_value(oid: &str) -> u64 {
    oid.rsplit('.')
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}
