// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SCITT CWT claims builder.
//!
//! Maps V2 SCITT compliance logic from CertificateSigningService.

use cose_sign1_headers::{CwtClaims, CwtClaimsHeaderContributor};
use did_x509::DidX509Builder;

use crate::error::CertificateError;

/// Builds CWT claims for SCITT compliance.
///
/// Creates claims with DID:X509 issuer derived from certificate chain.
///
/// # Arguments
///
/// * `chain` - Certificate chain in leaf-first order (DER-encoded)
/// * `custom_claims` - Optional custom claims to merge
///
/// # Returns
///
/// CwtClaims with issuer, subject, issued_at, not_before
pub fn build_scitt_cwt_claims(
    chain: &[&[u8]],
    custom_claims: Option<&CwtClaims>,
) -> Result<CwtClaims, CertificateError> {
    // Generate DID:X509 issuer from certificate chain
    let did_issuer = DidX509Builder::build_from_chain_with_eku(chain).map_err(|e| {
        CertificateError::InvalidCertificate(format!("DID:X509 generation failed: {}", e))
    })?;

    // Build base claims with builder pattern
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut claims = CwtClaims::new()
        .with_issuer(did_issuer)
        .with_subject(CwtClaims::DEFAULT_SUBJECT)
        .with_issued_at(now)
        .with_not_before(now);

    // Merge custom claims if provided (copy fields from custom to claims)
    if let Some(custom) = custom_claims {
        if let Some(ref iss) = custom.issuer {
            claims.issuer = Some(iss.clone());
        }
        if let Some(ref sub) = custom.subject {
            claims.subject = Some(sub.clone());
        }
        if let Some(ref aud) = custom.audience {
            claims.audience = Some(aud.clone());
        }
        if let Some(exp) = custom.expiration_time {
            claims.expiration_time = Some(exp);
        }
        if let Some(nbf) = custom.not_before {
            claims.not_before = Some(nbf);
        }
        if let Some(iat) = custom.issued_at {
            claims.issued_at = Some(iat);
        }
    }

    Ok(claims)
}

/// Creates a CWT claims header contributor for SCITT compliance.
///
/// # Arguments
///
/// * `chain` - Certificate chain in leaf-first order (DER-encoded)
/// * `custom_claims` - Optional custom claims to merge
/// * `provider` - CBOR provider for encoding
///
/// # Returns
///
/// CwtClaimsHeaderContributor configured for SCITT
pub fn create_scitt_contributor(
    chain: &[&[u8]],
    custom_claims: Option<&CwtClaims>,
) -> Result<CwtClaimsHeaderContributor, CertificateError> {
    let claims = build_scitt_cwt_claims(chain, custom_claims)?;
    let contributor = CwtClaimsHeaderContributor::new(&claims).map_err(|e| {
        CertificateError::SigningError(format!("Failed to encode CWT claims: {}", e))
    })?;
    Ok(contributor)
}
