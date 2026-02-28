// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Content-Type header contributor.

use tracing::{debug};

use cose_sign1_primitives::{ContentType, CoseHeaderMap};
use cose_sign1_signing::{HeaderContributor, HeaderContributorContext, HeaderMergeStrategy};

/// Header contributor that adds the content type to protected headers.
///
/// Maps V2 `ContentTypeHeaderContributor`. Adds COSE header label 3 (content-type).
pub struct ContentTypeHeaderContributor {
    content_type: String,
}

impl ContentTypeHeaderContributor {
    /// Creates a new content type contributor.
    pub fn new(content_type: impl Into<String>) -> Self {
        Self {
            content_type: content_type.into(),
        }
    }
}

impl HeaderContributor for ContentTypeHeaderContributor {
    fn merge_strategy(&self) -> HeaderMergeStrategy {
        HeaderMergeStrategy::KeepExisting
    }

    fn contribute_protected_headers(
        &self,
        headers: &mut CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        // Only set if not already present
        if headers.content_type().is_none() {
            debug!(contributor = "content_type", value = %self.content_type, "Contributing header");
            headers.set_content_type(ContentType::Text(self.content_type.clone()));
        }
    }

    fn contribute_unprotected_headers(
        &self,
        _headers: &mut CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        // Content type goes in protected headers only
    }
}
