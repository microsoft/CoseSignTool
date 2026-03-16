// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hash envelope header contributor.

use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};
use cose_sign1_signing::{HeaderContributor, HeaderContributorContext, HeaderMergeStrategy};

use super::HashAlgorithm;

/// Header contributor that adds hash envelope headers.
///
/// Maps V2 `CoseHashEnvelopeHeaderContributor`. Adds headers:
/// - 258 (PayloadHashAlg): Hash algorithm identifier
/// - 259 (PreimageContentType): Original payload content type
/// - 260 (PayloadLocation): Optional URI for original payload
pub struct HashEnvelopeHeaderContributor {
    hash_algorithm: HashAlgorithm,
    preimage_content_type: String,
    payload_location: Option<String>,
}

impl HashEnvelopeHeaderContributor {
    // COSE header labels for hash envelope
    const PAYLOAD_HASH_ALG: i64 = 258;
    const PREIMAGE_CONTENT_TYPE: i64 = 259;
    const PAYLOAD_LOCATION: i64 = 260;

    /// Creates a new hash envelope header contributor.
    pub fn new(
        hash_algorithm: HashAlgorithm,
        preimage_content_type: impl Into<String>,
        payload_location: Option<String>,
    ) -> Self {
        Self {
            hash_algorithm,
            preimage_content_type: preimage_content_type.into(),
            payload_location,
        }
    }
}

impl HeaderContributor for HashEnvelopeHeaderContributor {
    fn merge_strategy(&self) -> HeaderMergeStrategy {
        HeaderMergeStrategy::Replace
    }

    fn contribute_protected_headers(
        &self,
        headers: &mut CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        // Per RFC 9054: content_type (label 3) MUST NOT be present with hash envelope format.
        // The original content type is preserved in PreimageContentType (label 259).
        headers.remove(&CoseHeaderLabel::Int(3));

        // Add hash algorithm (label 258)
        headers.insert(
            CoseHeaderLabel::Int(Self::PAYLOAD_HASH_ALG),
            CoseHeaderValue::Int(self.hash_algorithm.cose_algorithm_id() as i64),
        );

        // Add preimage content type (label 259)
        headers.insert(
            CoseHeaderLabel::Int(Self::PREIMAGE_CONTENT_TYPE),
            CoseHeaderValue::Text(self.preimage_content_type.clone()),
        );

        // Add payload location if provided (label 260)
        if let Some(ref location) = self.payload_location {
            headers.insert(
                CoseHeaderLabel::Int(Self::PAYLOAD_LOCATION),
                CoseHeaderValue::Text(location.clone()),
            );
        }
    }

    fn contribute_unprotected_headers(
        &self,
        headers: &mut CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        // Per RFC 9054: content_type (label 3) MUST NOT be present in
        // protected or unprotected headers when using hash envelope format.
        headers.remove(&CoseHeaderLabel::Int(3));
    }
}
