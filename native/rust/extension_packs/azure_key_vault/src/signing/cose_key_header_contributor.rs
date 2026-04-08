// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE_Key public key embedding header contributor.
//!
//! Embeds the public key as a COSE_Key structure in COSE headers,
//! defaulting to UNPROTECTED headers with label -65537.

use cose_sign1_primitives::{ArcSlice, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};
use cose_sign1_signing::{HeaderContributor, HeaderContributorContext, HeaderMergeStrategy};

/// Private-use label for embedded COSE_Key public key.
///
/// Matches V2 `PublicKeyHeaderContributor.COSE_KEY_LABEL`.
pub const COSE_KEY_LABEL: i64 = -65537;

/// Header location for COSE_Key embedding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseKeyHeaderLocation {
    /// Embed in protected headers (signed).
    Protected,
    /// Embed in unprotected headers (not signed).
    Unprotected,
}

/// Header contributor that embeds a COSE_Key public key structure.
///
/// Maps V2's `PublicKeyHeaderContributor`.
/// Stores the key as `ArcSlice` so cloning is a cheap refcount bump.
pub struct CoseKeyHeaderContributor {
    cose_key_cbor: ArcSlice,
    location: CoseKeyHeaderLocation,
}

impl CoseKeyHeaderContributor {
    /// Creates a new COSE_Key header contributor.
    ///
    /// # Arguments
    ///
    /// * `cose_key_cbor` - The CBOR-encoded COSE_Key map
    /// * `location` - Where to place the header (defaults to Unprotected)
    pub fn new(cose_key_cbor: impl Into<ArcSlice>, location: CoseKeyHeaderLocation) -> Self {
        Self {
            cose_key_cbor: cose_key_cbor.into(),
            location,
        }
    }

    /// Creates a contributor that places the key in unprotected headers.
    pub fn unprotected(cose_key_cbor: impl Into<ArcSlice>) -> Self {
        Self::new(cose_key_cbor, CoseKeyHeaderLocation::Unprotected)
    }

    /// Creates a contributor that places the key in protected headers.
    pub fn protected(cose_key_cbor: impl Into<ArcSlice>) -> Self {
        Self::new(cose_key_cbor, CoseKeyHeaderLocation::Protected)
    }
}

impl HeaderContributor for CoseKeyHeaderContributor {
    fn merge_strategy(&self) -> HeaderMergeStrategy {
        HeaderMergeStrategy::KeepExisting
    }

    fn contribute_protected_headers(
        &self,
        headers: &mut CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        if self.location == CoseKeyHeaderLocation::Protected {
            let label = CoseHeaderLabel::Int(COSE_KEY_LABEL);
            if headers.get(&label).is_none() {
                headers.insert(label, CoseHeaderValue::Bytes(self.cose_key_cbor.clone()));
            }
        }
    }

    fn contribute_unprotected_headers(
        &self,
        headers: &mut CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        if self.location == CoseKeyHeaderLocation::Unprotected {
            let label = CoseHeaderLabel::Int(COSE_KEY_LABEL);
            if headers.get(&label).is_none() {
                headers.insert(label, CoseHeaderValue::Bytes(self.cose_key_cbor.clone()));
            }
        }
    }
}
