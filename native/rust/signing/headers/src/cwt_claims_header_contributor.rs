// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CWT Claims Header Contributor.
//!
//! Maps V2 `CWTClaimsHeaderExtender` class (note: different name in V2).

use cose_sign1_primitives::{ArcSlice, CoseHeaderMap, CoseHeaderValue};
use cose_sign1_signing::{HeaderContributor, HeaderContributorContext, HeaderMergeStrategy};

use crate::cwt_claims::CwtClaims;

/// Header contributor that adds CWT claims to protected headers.
///
/// Maps V2 `CWTClaimsHeaderExtender` class.
/// Always adds to PROTECTED headers (label 15) for SCITT compliance.
#[derive(Debug)]
pub struct CwtClaimsHeaderContributor {
    claims_bytes: ArcSlice,
}

impl CwtClaimsHeaderContributor {
    /// Creates a new CWT claims header contributor.
    ///
    /// # Arguments
    ///
    /// * `claims` - The CWT claims
    /// * `provider` - CBOR provider for encoding claims
    pub fn new(claims: &CwtClaims) -> Result<Self, String> {
        let claims_bytes: ArcSlice = claims.to_cbor_bytes()
            .map_err(|e| format!("Failed to encode CWT claims: {}", e))?
            .into();
        Ok(Self { claims_bytes })
    }

    /// CWT claims header label (label 15).
    pub const CWT_CLAIMS_LABEL: i64 = 15;
}

impl HeaderContributor for CwtClaimsHeaderContributor {
    fn merge_strategy(&self) -> HeaderMergeStrategy {
        HeaderMergeStrategy::Replace
    }

    fn contribute_protected_headers(
        &self,
        headers: &mut CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        headers.insert(
            cose_sign1_primitives::CoseHeaderLabel::Int(Self::CWT_CLAIMS_LABEL),
            CoseHeaderValue::Bytes(self.claims_bytes.clone()),
        );
    }

    fn contribute_unprotected_headers(
        &self,
        _headers: &mut CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        // No-op: CWT claims are always in protected headers for SCITT compliance
    }
}

