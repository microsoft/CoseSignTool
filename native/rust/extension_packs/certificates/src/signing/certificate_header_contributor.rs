// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate header contributor.
//!
//! Adds x5t and x5chain headers to PROTECTED headers.

use sha2::{Digest, Sha256};

use cbor_primitives::CborEncoder;
use cose_sign1_primitives::{CoseHeaderMap, CoseHeaderValue};
use cose_sign1_signing::{HeaderContributor, HeaderContributorContext, HeaderMergeStrategy};

use crate::error::CertificateError;

/// Header contributor that adds certificate thumbprint and chain to protected headers.
///
/// Maps V2 `CertificateHeaderContributor`.
/// Adds x5t (label 34) and x5chain (label 33) to PROTECTED headers.
pub struct CertificateHeaderContributor {
    x5t_bytes: Vec<u8>,
    x5chain_bytes: Vec<u8>,
}

impl CertificateHeaderContributor {
    /// x5t header label (certificate thumbprint).
    pub const X5T_LABEL: i64 = 34;
    /// x5chain header label (certificate chain).
    pub const X5CHAIN_LABEL: i64 = 33;

    /// Creates a new certificate header contributor.
    ///
    /// # Arguments
    ///
    /// * `signing_cert` - The signing certificate DER bytes
    /// * `chain` - Certificate chain in leaf-first order (DER-encoded)
    /// * `provider` - CBOR provider for encoding
    ///
    /// # Returns
    ///
    /// CertificateHeaderContributor or error if validation fails
    pub fn new(
        signing_cert: &[u8],
        chain: &[&[u8]],
    ) -> Result<Self, CertificateError> {
        // Validate first chain cert matches signing cert if chain is non-empty
        if !chain.is_empty() && chain[0] != signing_cert {
            return Err(CertificateError::InvalidCertificate(
                "First chain certificate does not match signing certificate".to_string(),
            ));
        }

        // Build x5t: CBOR array [alg_id, thumbprint]
        let x5t_bytes = Self::build_x5t(signing_cert)?;

        // Build x5chain: CBOR array of bstr (cert DER)
        let x5chain_bytes = Self::build_x5chain(chain)?;

        Ok(Self {
            x5t_bytes,
            x5chain_bytes,
        })
    }

    /// Builds x5t (certificate thumbprint) as CBOR array [alg_id, thumbprint].
    ///
    /// Uses SHA-256 hash of certificate DER bytes.
    fn build_x5t(
        cert_der: &[u8],
    ) -> Result<Vec<u8>, CertificateError> {
        // Compute SHA-256 thumbprint
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let thumbprint = hasher.finalize();

        let mut encoder = cose_sign1_primitives::provider::encoder();
        encoder.encode_array(2).map_err(|e| {
            CertificateError::SigningError(format!("Failed to encode x5t array: {}", e))
        })?;
        encoder.encode_i64(-16).map_err(|e| {
            CertificateError::SigningError(format!("Failed to encode x5t alg: {}", e))
        })?;
        encoder.encode_bstr(&thumbprint).map_err(|e| {
            CertificateError::SigningError(format!("Failed to encode x5t thumbprint: {}", e))
        })?;

        Ok(encoder.into_bytes())
    }

    /// Builds x5chain as CBOR array of bstr (cert DER).
    fn build_x5chain(
        chain: &[&[u8]],
    ) -> Result<Vec<u8>, CertificateError> {
        let mut encoder = cose_sign1_primitives::provider::encoder();
        encoder.encode_array(chain.len()).map_err(|e| {
            CertificateError::SigningError(format!("Failed to encode x5chain array: {}", e))
        })?;

        for cert_der in chain {
            encoder.encode_bstr(cert_der).map_err(|e| {
                CertificateError::SigningError(format!("Failed to encode x5chain cert: {}", e))
            })?;
        }

        Ok(encoder.into_bytes())
    }
}

impl HeaderContributor for CertificateHeaderContributor {
    fn merge_strategy(&self) -> HeaderMergeStrategy {
        HeaderMergeStrategy::Replace
    }

    fn contribute_protected_headers(
        &self,
        headers: &mut CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        // Add x5t (certificate thumbprint)
        headers.insert(
            cose_sign1_primitives::CoseHeaderLabel::Int(Self::X5T_LABEL),
            CoseHeaderValue::Raw(self.x5t_bytes.clone()),
        );

        // Add x5chain (certificate chain)
        headers.insert(
            cose_sign1_primitives::CoseHeaderLabel::Int(Self::X5CHAIN_LABEL),
            CoseHeaderValue::Raw(self.x5chain_bytes.clone()),
        );
    }

    fn contribute_unprotected_headers(
        &self,
        _headers: &mut CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        // No-op: x5t and x5chain are always in protected headers
    }
}
