// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key ID header contributor for Azure Key Vault signing.
//!
//! Adds the `kid` (label 4) header to PROTECTED headers with the full AKV key URI.

use cose_sign1_primitives::{CoseHeaderMap, CoseHeaderLabel, CoseHeaderValue};
use cose_sign1_signing::{HeaderContributor, HeaderContributorContext, HeaderMergeStrategy};

/// Header contributor that adds the AKV key identifier to protected headers.
///
/// Maps V2's kid header contribution in `AzureKeyVaultSigningService`.
pub struct KeyIdHeaderContributor {
    key_id: String,
}

impl KeyIdHeaderContributor {
    /// Creates a new key ID header contributor.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The full AKV key URI (e.g., `https://{vault}.vault.azure.net/keys/{name}/{version}`)
    pub fn new(key_id: String) -> Self {
        Self { key_id }
    }
}

impl HeaderContributor for KeyIdHeaderContributor {
    fn merge_strategy(&self) -> HeaderMergeStrategy {
        HeaderMergeStrategy::KeepExisting
    }

    fn contribute_protected_headers(
        &self,
        headers: &mut CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        let kid_label = CoseHeaderLabel::Int(4);
        if headers.get(&kid_label).is_none() {
            headers.insert(kid_label, CoseHeaderValue::Bytes(self.key_id.as_bytes().to_vec()));
        }
    }

    fn contribute_unprotected_headers(
        &self,
        _headers: &mut CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        // kid is always in protected headers
    }
}
