// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE_Sign1 certificate extension functions.
//!
//! Provides utilities to extract and verify certificate-related headers (x5chain, x5t).

use crate::error::CertificateError;
use crate::thumbprint::CoseX509Thumbprint;

/// x5chain header label (certificate chain).
pub const X5CHAIN_LABEL: i64 = 33;

/// x5t header label (certificate thumbprint).
pub const X5T_LABEL: i64 = 34;

/// Extracts the x5chain (certificate chain) from COSE headers.
///
/// The x5chain header (label 33) can be encoded as:
/// - A single byte string (single certificate)
/// - An array of byte strings (certificate chain)
///
/// Returns certificates in the order they appear in the header (typically leaf-first).
pub fn extract_x5chain(
    headers: &cose_sign1_primitives::CoseHeaderMap,
) -> Result<Vec<Vec<u8>>, CertificateError> {
    let label = cose_sign1_primitives::CoseHeaderLabel::Int(X5CHAIN_LABEL);
    
    // Use the existing one_or_many helper from headers
    if let Some(items) = headers.get_bytes_one_or_many(&label) {
        Ok(items)
    } else {
        Ok(Vec::new())
    }
}

/// Extracts the x5t (certificate thumbprint) from COSE headers.
///
/// The x5t header (label 34) is encoded as a CBOR array: [hash_id, thumbprint_bytes].
pub fn extract_x5t(
    headers: &cose_sign1_primitives::CoseHeaderMap,
) -> Result<Option<CoseX509Thumbprint>, CertificateError> {
    let label = cose_sign1_primitives::CoseHeaderLabel::Int(X5T_LABEL);
    
    if let Some(value) = headers.get(&label) {
        // The value should be Raw CBOR bytes containing [hash_id, thumbprint]
        let cbor_bytes = match value {
            cose_sign1_primitives::CoseHeaderValue::Raw(bytes) => bytes,
            cose_sign1_primitives::CoseHeaderValue::Bytes(bytes) => bytes,
            _ => {
                return Err(CertificateError::InvalidCertificate(
                    "x5t header value must be raw CBOR or bytes".to_string()
                ));
            }
        };
        
        let thumbprint = CoseX509Thumbprint::deserialize(cbor_bytes)?;
        Ok(Some(thumbprint))
    } else {
        Ok(None)
    }
}

/// Verifies that the x5t thumbprint matches the first certificate in x5chain.
///
/// Returns `true` if:
/// - Both x5t and x5chain are present
/// - The x5chain has at least one certificate
/// - The x5t thumbprint matches the first certificate
///
/// Returns `false` if either header is missing or they don't match.
pub fn verify_x5t_matches_chain(
    headers: &cose_sign1_primitives::CoseHeaderMap,
) -> Result<bool, CertificateError> {
    // Extract x5t
    let Some(x5t) = extract_x5t(headers)? else {
        return Ok(false);
    };
    
    // Extract x5chain
    let chain = extract_x5chain(headers)?;
    if chain.is_empty() {
        return Ok(false);
    }
    
    // Check if x5t matches the first certificate in the chain
    x5t.matches(&chain[0])
}


