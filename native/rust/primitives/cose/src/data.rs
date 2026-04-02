// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared ownership of raw COSE CBOR bytes.
//!
//! [`CoseData`] is the root of the zero-copy ownership model: the caller
//! passes owned bytes once, and `CoseData` wraps them in an [`Arc`] so that
//! all downstream structures (headers, payload slices, signature slices) can
//! share the same allocation without copying.
//!
//! The [`CoseData::Streamed`] variant supports large COSE files where the
//! payload should not be materialized in memory. Headers and signature are
//! buffered in a small [`Arc<[u8]>`], while the payload is accessed through
//! a seekable byte range in the underlying stream.

use std::io::{Read, Seek};
use std::ops::Range;
use std::sync::{Arc, Mutex};

use crate::error::CoseError;

/// Trait alias for `Read + Seek + Send`.
///
/// This enables type-erased seekable readers to be stored in
/// [`CoseData::Streamed`].
pub trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

/// Shared ownership of raw COSE CBOR bytes.
///
/// All COSE message types (Sign1, Sign, Encrypt, Mac) wrap this enum.
/// Cloning is cheap — only reference counts are incremented.
///
/// # Variants
///
/// - [`Buffered`](CoseData::Buffered) — the entire CBOR message lives in an
///   `Arc<[u8]>`. All byte ranges (headers, payload, signature) index into
///   this single allocation.
///
/// - [`Streamed`](CoseData::Streamed) — headers and signature are in a small
///   in-memory buffer (`header_buf`), while the payload is a seekable byte
///   range in an external source. Useful for multi-GB `.cose` files.
///
/// # Example
///
/// ```ignore
/// let data = CoseData::new(raw_cbor_bytes);
/// let header_bytes = data.slice(&(4..20));
/// let arc = data.arc().clone(); // share with sub-structures
/// ```
#[derive(Clone)]
pub enum CoseData {
    /// In-memory: COSE message bytes in a shared buffer.
    ///
    /// The `range` field defines the logical view into `raw`. For top-level
    /// messages this spans `0..raw.len()`. For sub-messages (e.g., receipts
    /// embedded in a parent's unprotected header) it is a sub-range — enabling
    /// zero-copy parsing that shares the parent's allocation.
    ///
    /// Sub-structure ranges (protected headers, payload, signature) are stored
    /// as **absolute** offsets into `raw`, so [`slice`](Self::slice) indexes
    /// directly without translation.
    Buffered {
        /// Shared backing buffer (may be the full parent message).
        raw: Arc<[u8]>,
        /// Logical byte range of *this* message within `raw`.
        range: Range<usize>,
    },
    /// Streaming: headers and signature buffered, payload accessed via seek.
    Streamed {
        /// Small buffer containing protected header, unprotected header,
        /// and signature bytes concatenated.
        header_buf: Arc<[u8]>,
        /// Protected header bytes range within `header_buf`.
        protected_range: Range<usize>,
        /// Unprotected header raw CBOR bytes range within `header_buf`.
        unprotected_range: Range<usize>,
        /// Signature bytes range within `header_buf`.
        signature_range: Range<usize>,
        /// Seekable source for payload access.
        source: Arc<Mutex<Box<dyn ReadSeek>>>,
        /// Byte offset of payload content in the source stream.
        payload_offset: u64,
        /// Byte length of payload content.
        payload_len: u64,
    },
}

impl std::fmt::Debug for CoseData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Buffered { raw, range } => f
                .debug_struct("CoseData::Buffered")
                .field("buf_len", &raw.len())
                .field("range", range)
                .finish(),
            Self::Streamed {
                header_buf,
                protected_range,
                unprotected_range,
                signature_range,
                payload_offset,
                payload_len,
                ..
            } => f
                .debug_struct("CoseData::Streamed")
                .field("header_buf_len", &header_buf.len())
                .field("protected_range", protected_range)
                .field("unprotected_range", unprotected_range)
                .field("signature_range", signature_range)
                .field("payload_offset", payload_offset)
                .field("payload_len", payload_len)
                .finish_non_exhaustive(),
        }
    }
}

impl CoseData {
    // ========================================================================
    // Buffered constructors (existing API, unchanged behavior)
    // ========================================================================

    /// Creates a new `CoseData` taking ownership of `data`.
    pub fn new(data: Vec<u8>) -> Self {
        let len = data.len();
        Self::Buffered {
            raw: Arc::from(data),
            range: 0..len,
        }
    }

    /// Creates a new `CoseData` by copying `data`.
    pub fn from_slice(data: &[u8]) -> Self {
        let len = data.len();
        Self::Buffered {
            raw: Arc::from(data),
            range: 0..len,
        }
    }

    /// Wraps an existing `Arc<[u8]>`.
    pub fn from_arc(arc: Arc<[u8]>) -> Self {
        let len = arc.len();
        Self::Buffered {
            raw: arc,
            range: 0..len,
        }
    }

    /// Wraps a sub-range of an existing `Arc<[u8]>` — **zero-copy**.
    ///
    /// The resulting `CoseData` shares the parent's allocation. All
    /// sub-structure ranges (headers, payload, signature) are expected to
    /// be **absolute** offsets into `raw` (i.e., already offset-adjusted).
    ///
    /// [`as_bytes`](Self::as_bytes) returns only the bytes within `range`.
    /// [`slice`](Self::slice) indexes directly into `raw` using absolute
    /// offsets.
    pub fn from_arc_range(arc: Arc<[u8]>, range: Range<usize>) -> Self {
        debug_assert!(
            range.end <= arc.len(),
            "CoseData::from_arc_range: range {}..{} out of bounds for len {}",
            range.start,
            range.end,
            arc.len()
        );
        Self::Buffered { raw: arc, range }
    }

    // ========================================================================
    // Streamed constructor
    // ========================================================================

    /// Parses a COSE_Sign1 message from a seekable stream.
    ///
    /// Reads headers and signature into a small in-memory buffer, and records
    /// the payload offset and length for on-demand access. The payload bytes
    /// are **not** read into memory.
    ///
    /// # COSE_Sign1 structure parsed
    ///
    /// ```text
    /// Tag(18)?  [  protected: bstr, unprotected: map, payload: bstr/nil, signature: bstr  ]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`CoseError`] if the stream does not contain a valid COSE_Sign1
    /// message or if an I/O error occurs.
    #[cfg(feature = "cbor-everparse")]
    pub fn from_stream<R: Read + Seek + Send + 'static>(reader: R) -> Result<Self, CoseError> {
        use cbor_primitives::{CborStreamDecoder, CborType};
        use cbor_primitives_everparse::EverparseStreamDecoder;

        /// CBOR tag for COSE_Sign1 (RFC 9052 §4.2).
        const COSE_SIGN1_TAG: u64 = 18;

        let mut decoder = EverparseStreamDecoder::new(reader);

        // 1. Optional tag 18
        let typ = decoder
            .peek_type()
            .map_err(|e| CoseError::CborError(e.to_string()))?;
        if typ == CborType::Tag {
            let tag = decoder
                .decode_tag()
                .map_err(|e| CoseError::CborError(e.to_string()))?;
            if tag != COSE_SIGN1_TAG {
                return Err(CoseError::InvalidMessage(format!(
                    "unexpected COSE tag: expected {}, got {}",
                    COSE_SIGN1_TAG, tag
                )));
            }
        }

        // 2. Array(4)
        let len = decoder
            .decode_array_len()
            .map_err(|e| CoseError::CborError(e.to_string()))?;
        match len {
            Some(4) => {}
            Some(n) => {
                return Err(CoseError::InvalidMessage(format!(
                    "COSE_Sign1 must have 4 elements, got {}",
                    n
                )));
            }
            None => {
                return Err(CoseError::InvalidMessage(
                    "COSE_Sign1 must be definite-length array".into(),
                ));
            }
        }

        // 3. Protected header (bstr containing a CBOR map)
        let protected_bytes: Vec<u8> = decoder
            .decode_bstr_owned()
            .map_err(|e| CoseError::CborError(e.to_string()))?;

        // 4. Unprotected header (raw CBOR map) — capture raw bytes via
        //    decode_raw_owned (skip + seek-back-read).
        let unprotected_raw: Vec<u8> = decoder
            .decode_raw_owned()
            .map_err(|e| CoseError::CborError(e.to_string()))?;

        // 5. Payload (bstr or null)
        let is_null = decoder
            .is_null()
            .map_err(|e| CoseError::CborError(e.to_string()))?;
        let (payload_offset, payload_len) = if is_null {
            decoder
                .decode_null()
                .map_err(|e| CoseError::CborError(e.to_string()))?;
            (0u64, 0u64)
        } else {
            let (offset, len) = decoder
                .decode_bstr_header_offset()
                .map_err(|e| CoseError::CborError(e.to_string()))?;
            // Skip past the payload content bytes.
            decoder
                .skip_n_bytes(len)
                .map_err(|e| CoseError::IoError(e.to_string()))?;
            (offset, len)
        };

        // 6. Signature (bstr)
        let signature_bytes: Vec<u8> = decoder
            .decode_bstr_owned()
            .map_err(|e| CoseError::CborError(e.to_string()))?;

        // Build header_buf: [ protected | unprotected_raw | signature ]
        let mut header_buf = Vec::with_capacity(
            protected_bytes.len() + unprotected_raw.len() + signature_bytes.len(),
        );

        let protected_start: usize = 0;
        header_buf.extend_from_slice(&protected_bytes);
        let protected_end: usize = header_buf.len();

        let unprotected_start: usize = header_buf.len();
        header_buf.extend_from_slice(&unprotected_raw);
        let unprotected_end: usize = header_buf.len();

        let signature_start: usize = header_buf.len();
        header_buf.extend_from_slice(&signature_bytes);
        let signature_end: usize = header_buf.len();

        // Recover the underlying reader for future payload access.
        let inner_reader = decoder.into_inner();

        Ok(CoseData::Streamed {
            header_buf: Arc::from(header_buf),
            protected_range: protected_start..protected_end,
            unprotected_range: unprotected_start..unprotected_end,
            signature_range: signature_start..signature_end,
            source: Arc::new(Mutex::new(Box::new(inner_reader))),
            payload_offset,
            payload_len,
        })
    }

    // ========================================================================
    // Accessors (work for both variants)
    // ========================================================================

    /// Returns the logical message bytes.
    ///
    /// - **Buffered**: the CBOR bytes within `range` (full buffer for
    ///   top-level messages, sub-range for zero-copy sub-messages).
    /// - **Streamed**: the `header_buf` (protected + unprotected + signature).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Buffered { raw, range } => &raw[range.clone()],
            Self::Streamed { header_buf, .. } => header_buf,
        }
    }

    /// Returns a sub-slice of the backing buffer using an **absolute** range.
    ///
    /// Sub-structure ranges (headers, payload, signature) are stored as
    /// absolute offsets into the backing `Arc`, so this method indexes
    /// directly without translation.
    #[inline]
    pub fn slice(&self, range: &Range<usize>) -> &[u8] {
        match self {
            Self::Buffered { raw, .. } => &raw[range.clone()],
            Self::Streamed { header_buf, .. } => &header_buf[range.clone()],
        }
    }

    /// Returns a shared reference to the backing [`Arc`] for sub-structures
    /// to share without cloning the bytes.
    #[inline]
    pub fn arc(&self) -> &Arc<[u8]> {
        match self {
            Self::Buffered { raw, .. } => raw,
            Self::Streamed { header_buf, .. } => header_buf,
        }
    }

    /// Returns the length of the logical message bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Returns `true` if the logical message bytes are empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    /// Returns `true` if this is a streamed (non-buffered) message.
    #[inline]
    pub fn is_streamed(&self) -> bool {
        matches!(self, Self::Streamed { .. })
    }

    // ========================================================================
    // Streamed-specific accessors
    // ========================================================================

    /// Returns the payload byte offset and length in the source stream.
    ///
    /// Returns `None` for `Buffered` data or if the payload is null/detached
    /// (both offset and length are zero).
    pub fn stream_payload_location(&self) -> Option<(u64, u64)> {
        match self {
            Self::Buffered { .. } => None,
            Self::Streamed {
                payload_offset,
                payload_len,
                ..
            } => {
                if *payload_len == 0 {
                    None
                } else {
                    Some((*payload_offset, *payload_len))
                }
            }
        }
    }

    /// Reads the payload from the stream into a `Vec<u8>`.
    ///
    /// Returns `None` for `Buffered` data (use [`slice`](Self::slice) instead)
    /// or if the streamed payload is null/detached.
    pub fn read_stream_payload(&self) -> Option<Result<Vec<u8>, CoseError>> {
        match self {
            Self::Buffered { .. } => None,
            Self::Streamed {
                source,
                payload_offset,
                payload_len,
                ..
            } => {
                if *payload_len == 0 {
                    return None;
                }
                let result = (|| {
                    let mut src = source
                        .lock()
                        .map_err(|e| CoseError::IoError(format!("mutex poisoned: {}", e)))?;
                    src.seek(std::io::SeekFrom::Start(*payload_offset))
                        .map_err(|e| CoseError::IoError(e.to_string()))?;
                    let len: usize = usize::try_from(*payload_len)
                        .map_err(|_| CoseError::IoError("payload too large for memory".into()))?;
                    let mut buf = vec![0u8; len];
                    src.read_exact(&mut buf)
                        .map_err(|e| CoseError::IoError(e.to_string()))?;
                    Ok(buf)
                })();
                Some(result)
            }
        }
    }
}
