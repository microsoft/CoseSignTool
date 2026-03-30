// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Zero-copy shared-ownership types for COSE data.
//!
//! [`ArcSlice`] and [`ArcStr`] hold a reference-counted backing buffer and a
//! byte range into that buffer, enabling zero-copy access to decoded CBOR
//! byte/text strings while sharing the same allocation as the parent
//! [`CoseData`](crate::data::CoseData).
//!
//! When constructed from owned data (the builder path), they allocate a small
//! independent Arc. This is acceptable because builder values are typically
//! small header fields, not megabyte payloads.

use std::ops::Range;
use std::sync::Arc;

/// A zero-copy byte slice backed by a shared [`Arc`].
///
/// Provides `&[u8]` access without copying when the backing buffer is shared
/// with other structures (e.g., a parsed COSE message).
///
/// # Builder path
///
/// Use `ArcSlice::from(vec)` to create an independently-owned slice from a
/// `Vec<u8>`.  This allocates a new Arc, which is fine for small header values.
///
/// # Parse path
///
/// Use [`ArcSlice::new`] with a shared `Arc<[u8]>` and a byte range to
/// reference data inside an existing buffer with zero copies.
#[derive(Clone, Debug)]
pub struct ArcSlice {
    data: Arc<[u8]>,
    range: Range<usize>,
}

impl ArcSlice {
    /// Creates a new `ArcSlice` referencing `range` within `data`.
    ///
    /// # Panics
    ///
    /// Panics (in debug builds) if `range` is out of bounds.
    pub fn new(data: Arc<[u8]>, range: Range<usize>) -> Self {
        debug_assert!(
            range.end <= data.len(),
            "ArcSlice::new: range {}..{} out of bounds for len {}",
            range.start,
            range.end,
            data.len()
        );
        Self { data, range }
    }

    /// Returns the referenced bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[self.range.clone()]
    }

    /// Returns the length of the slice.
    #[inline]
    pub fn len(&self) -> usize {
        self.range.len()
    }

    /// Returns `true` if the slice is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }

    /// Returns the backing `Arc<[u8]>`.
    ///
    /// Use together with [`range`](Self::range) to share the buffer with
    /// other zero-copy structures (e.g., parse a receipt into a
    /// `CoseSign1Message` without copying).
    #[inline]
    pub fn arc(&self) -> &Arc<[u8]> {
        &self.data
    }

    /// Returns the byte range within the backing `Arc`.
    #[inline]
    pub fn range(&self) -> &Range<usize> {
        &self.range
    }
}

impl AsRef<[u8]> for ArcSlice {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl std::ops::Deref for ArcSlice {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl PartialEq for ArcSlice {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for ArcSlice {}

impl std::hash::Hash for ArcSlice {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl std::fmt::Display for ArcSlice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bytes({})", self.len())
    }
}

impl From<Vec<u8>> for ArcSlice {
    fn from(v: Vec<u8>) -> Self {
        let len = v.len();
        Self {
            data: Arc::from(v),
            range: 0..len,
        }
    }
}

impl From<&[u8]> for ArcSlice {
    fn from(v: &[u8]) -> Self {
        Self::from(v.to_vec())
    }
}

// ---------------------------------------------------------------------------

/// A zero-copy string slice backed by a shared [`Arc`].
///
/// Mirrors [`ArcSlice`] but guarantees UTF-8 validity (checked at construction
/// on the parse path, inherent on the builder path).
#[derive(Clone, Debug)]
pub struct ArcStr {
    data: Arc<[u8]>,
    range: Range<usize>,
}

impl ArcStr {
    /// Creates a new `ArcStr` referencing `range` within `data`.
    ///
    /// # Panics
    ///
    /// Panics if the referenced bytes are not valid UTF-8.
    pub fn new(data: Arc<[u8]>, range: Range<usize>) -> Self {
        debug_assert!(
            range.end <= data.len(),
            "ArcStr::new: range {}..{} out of bounds for len {}",
            range.start,
            range.end,
            data.len()
        );
        // Validate UTF-8 in debug builds; release builds trust the caller
        // (CBOR decoders validate UTF-8 during decode).
        debug_assert!(
            std::str::from_utf8(&data[range.clone()]).is_ok(),
            "ArcStr::new: not valid UTF-8"
        );
        Self { data, range }
    }

    /// Returns the string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        // SAFETY: validated as UTF-8 during CBOR decode or construction.
        std::str::from_utf8(&self.data[self.range.clone()]).unwrap_or("")
    }

    /// Returns the byte length of the string.
    #[inline]
    pub fn len(&self) -> usize {
        self.range.len()
    }

    /// Returns `true` if the string is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }
}

impl std::ops::Deref for ArcStr {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for ArcStr {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for ArcStr {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for ArcStr {}

impl std::hash::Hash for ArcStr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl std::fmt::Display for ArcStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<String> for ArcStr {
    fn from(s: String) -> Self {
        let bytes = s.into_bytes();
        let len = bytes.len();
        Self {
            data: Arc::from(bytes),
            range: 0..len,
        }
    }
}

impl From<&str> for ArcStr {
    fn from(s: &str) -> Self {
        Self::from(s.to_string())
    }
}
