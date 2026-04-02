// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Lazy-parsed COSE header map backed by a shared buffer.
//!
//! [`LazyHeaderMap`] stores raw CBOR bytes and defers parsing until the first
//! access.  When parsing does occur, byte-string and text-string header values
//! reference the original backing buffer via [`ArcSlice`] / [`ArcStr`] —
//! no copies are made for those value types.

use std::ops::Range;
use std::sync::{Arc, OnceLock};

use crate::error::CoseError;
use crate::headers::CoseHeaderMap;

/// A header map whose parsing is deferred until the first access.
///
/// The map holds a shared reference ([`Arc<[u8]>`]) to the parent COSE
/// message buffer and a byte range describing where the header map's CBOR
/// lives within that buffer.  On first access, the map is decoded and
/// cached in a [`OnceLock`].
///
/// # Thread safety
///
/// Parsing is performed at most once, even under concurrent access, thanks
/// to [`OnceLock`].
#[derive(Clone, Debug)]
pub struct LazyHeaderMap {
    /// Shared backing buffer (same Arc as the parent [`CoseData`]).
    raw: Arc<[u8]>,
    /// Byte range of this header map's CBOR within `raw`.
    range: Range<usize>,
    /// Parsed header entries, populated on first access.
    parsed: OnceLock<CoseHeaderMap>,
}

impl LazyHeaderMap {
    /// Creates a new lazy header map over `range` in `raw`.
    pub fn new(raw: Arc<[u8]>, range: Range<usize>) -> Self {
        Self {
            raw,
            range,
            parsed: OnceLock::new(),
        }
    }

    /// Creates a lazy header map that is already parsed.
    ///
    /// This is useful for the builder path where headers are constructed
    /// from scratch rather than decoded from a buffer.
    pub fn from_parsed(raw: Arc<[u8]>, range: Range<usize>, headers: CoseHeaderMap) -> Self {
        let lock = OnceLock::new();
        let _ = lock.set(headers);
        Self {
            raw,
            range,
            parsed: lock,
        }
    }

    /// Returns the raw CBOR bytes of this header map (for Sig_structure).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw[self.range.clone()]
    }

    /// Returns the byte range within the parent buffer.
    #[inline]
    pub fn range(&self) -> &Range<usize> {
        &self.range
    }

    /// Returns a reference to the backing Arc.
    #[inline]
    pub fn arc(&self) -> &Arc<[u8]> {
        &self.raw
    }

    /// Returns a reference to the parsed header map, parsing on first call.
    ///
    /// If the CBOR is malformed, returns an empty map (errors are silently
    /// swallowed — use [`try_headers`](Self::try_headers) to inspect errors).
    pub fn headers(&self) -> &CoseHeaderMap {
        self.parsed.get_or_init(|| {
            let bytes = &self.raw[self.range.clone()];
            if bytes.is_empty() {
                return CoseHeaderMap::new();
            }
            CoseHeaderMap::decode_shared(&self.raw, self.range.clone()).unwrap_or_default()
        })
    }

    /// Attempts to parse and return the header map, propagating errors.
    pub fn try_headers(&self) -> Result<&CoseHeaderMap, CoseError> {
        // If already parsed, return it directly.
        if let Some(h) = self.parsed.get() {
            return Ok(h);
        }
        let bytes = &self.raw[self.range.clone()];
        if bytes.is_empty() {
            return Ok(self.parsed.get_or_init(CoseHeaderMap::new));
        }
        let map = CoseHeaderMap::decode_shared(&self.raw, self.range.clone())?;
        Ok(self.parsed.get_or_init(|| map))
    }

    /// Returns `true` if the header map has already been parsed.
    pub fn is_parsed(&self) -> bool {
        self.parsed.get().is_some()
    }

    /// Returns a reference to the parsed header map for the given label.
    ///
    /// Convenience delegate to [`CoseHeaderMap::get`].
    pub fn get(
        &self,
        label: &crate::headers::CoseHeaderLabel,
    ) -> Option<&crate::headers::CoseHeaderValue> {
        self.headers().get(label)
    }

    /// Inserts a header value, replacing any previous entry for that label.
    ///
    /// Forces parsing if not yet parsed, then mutates the cached map.
    /// Note: this mutates the *parsed* representation only — the raw backing
    /// bytes are not updated. Callers that need re-serialization should
    /// rebuild the message via the builder.
    pub fn insert(
        &mut self,
        label: crate::headers::CoseHeaderLabel,
        value: crate::headers::CoseHeaderValue,
    ) {
        // Ensure the map is parsed before we take a mutable reference.
        let _ = self.headers();
        if let Some(map) = self.parsed.get_mut() {
            map.insert(label, value);
        }
    }

    /// Removes a header entry by label.
    ///
    /// Returns the removed value, or `None` if the label was not present.
    /// Same caveats as [`insert`](Self::insert) regarding raw bytes.
    pub fn remove(
        &mut self,
        label: &crate::headers::CoseHeaderLabel,
    ) -> Option<crate::headers::CoseHeaderValue> {
        let _ = self.headers();
        self.parsed.get_mut().and_then(|map| map.remove(label))
    }
}
