// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public-facing constants and tunables for the `cose-tp-json/v1` frontend.

/// Stable identifier embedded in user documents and emitted by [`crate::FRONTEND_ID`].
pub const FRONTEND_ID: &str = "cose-tp-json/v1";

/// Conventional file extension (`.coseTrustPolicy.json`) for documents.
pub const FILE_EXTENSION: &str = ".coseTrustPolicy.json";

/// Canonical schema URL — D7 pin-to-`main` policy (mirrors the .NET resource).
pub const SCHEMA_URL: &str =
    "https://raw.githubusercontent.com/microsoft/CoseSignTool/main/V2/schemas/cose-tp/v1.json";

/// IANA media type for canonical documents.
pub const MEDIA_TYPE_JSON: &str = "application/x-cose-trust-policy+json";

/// Alternative IANA media type for JSONC documents.
pub const MEDIA_TYPE_JSONC: &str = "application/x-cose-trust-policy+json5";

/// Default recursion depth cap (`64`) honored during translation. Bounded against
/// stack-exhaustion via deeply nested arrays / objects (§6.5.4 #6).
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// Default cache capacity (`32`) honored by [`crate::TranslatorCache`] (D9).
pub const DEFAULT_CACHE_CAPACITY: u64 = 32;

/// Configuration knobs for [`crate::CoseTpJsonFrontend`] and [`crate::TranslatorCache`].
///
/// `#[non_exhaustive]` so future tunables (e.g. document-size cap, predicate-schema strict
/// mode toggle) are non-breaking additions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CoseTpJsonOptions {
    /// Maximum depth honored when walking nested specs / JSON values during translation.
    pub max_depth: usize,
    /// Maximum number of cached translation results retained by
    /// [`crate::TranslatorCache`].
    pub cache_capacity: u64,
}

impl CoseTpJsonOptions {
    /// Construct an options bundle with all-default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder helper: override [`Self::max_depth`].
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Builder helper: override [`Self::cache_capacity`].
    pub fn with_cache_capacity(mut self, cache_capacity: u64) -> Self {
        self.cache_capacity = cache_capacity;
        self
    }
}

impl Default for CoseTpJsonOptions {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            cache_capacity: DEFAULT_CACHE_CAPACITY,
        }
    }
}
