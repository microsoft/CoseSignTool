// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CoseSign1Message parsing and verification.
//!
//! Provides the `CoseSign1Message` type for parsing and verifying
//! COSE_Sign1 messages per RFC 9052.
//!
//! All CBOR operations use the compile-time-selected provider singleton.
//! which is set once during parsing and reused for all subsequent operations.

use std::io::{Read, Seek};
use std::ops::Range;
use std::sync::Arc;

use cbor_primitives::{CborDecoder, CborEncoder, CborProvider, CborType};
use crypto_primitives::CryptoVerifier;

use crate::algorithms::COSE_SIGN1_TAG;
use crate::error::{CoseKeyError, CoseSign1Error};
use crate::headers::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};
use crate::payload::StreamingPayload;
use crate::provider::{cbor_provider, CborProviderImpl};
use crate::sig_structure::{
    build_sig_structure, build_sig_structure_prefix, SizedRead, SizedReader,
};

// Re-export the new ownership types for consumers.
pub use cose_primitives::data::CoseData;
pub use cose_primitives::lazy_headers::LazyHeaderMap;

/// A parsed COSE_Sign1 message.
///
/// COSE_Sign1 structure per RFC 9052:
///
/// ```text
/// COSE_Sign1 = [
///     protected : bstr .cbor protected-header-map,
///     unprotected : unprotected-header-map,
///     payload : bstr / nil,
///     signature : bstr
/// ]
/// ```
///
/// The message may be optionally wrapped in a CBOR tag (18).
///
/// Uses a zero-copy, single-backing-buffer architecture: the parsed message
/// owns exactly one allocation (the raw CBOR bytes via [`CoseData`]), and all
/// byte-oriented fields are represented as `Range<usize>` into that buffer.
/// Headers are lazily parsed through [`LazyHeaderMap`] — zero-copy for
/// byte/text header values via [`ArcSlice`](cose_primitives::ArcSlice) /
/// [`ArcStr`](cose_primitives::ArcStr).
///
/// Cloning is cheap: the `Arc` is reference-counted and only the header maps
/// are deep-copied (if already parsed).
#[derive(Clone)]
pub struct CoseSign1Message {
    /// Shared COSE data buffer.
    data: CoseData,
    /// Protected header bytes range + lazy parsed map.
    protected: LazyHeaderMap,
    /// Unprotected header bytes range + lazy parsed map.
    unprotected: LazyHeaderMap,
    /// Byte range of the payload within `raw` (None if detached/nil).
    payload_range: Option<Range<usize>>,
    /// Byte range of the signature within `raw`.
    signature_range: Range<usize>,
}

impl std::fmt::Debug for CoseSign1Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoseSign1Message")
            .field("protected_headers", self.protected.headers())
            .field("unprotected", self.unprotected.headers())
            .field("payload_len", &self.payload_range.as_ref().map(|r| r.len()))
            .field("signature_len", &self.signature_range.len())
            .finish()
    }
}

impl CoseSign1Message {
    /// Parses a COSE_Sign1 message from CBOR bytes.
    ///
    /// Uses a zero-copy architecture: the raw CBOR bytes are wrapped in an
    /// [`Arc`] and all fields are represented as byte ranges into that single
    /// allocation. Headers are lazily parsed through [`LazyHeaderMap`].
    ///
    /// Handles both tagged (tag 18) and untagged messages.
    /// Uses the compile-time-selected CBOR provider.
    ///
    /// **Note:** The entire `data` slice is copied into an `Arc<[u8]>`. For
    /// multi-GB payloads, prefer [`parse_stream`](Self::parse_stream) which
    /// only buffers headers and signature.
    ///
    /// # Arguments
    ///
    /// * `data` - The CBOR-encoded message bytes
    ///
    /// # Example
    ///
    /// ```ignore
    /// let msg = CoseSign1Message::parse(&bytes)?;
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, CoseSign1Error> {
        let raw: Arc<[u8]> = Arc::from(data);
        let mut decoder = crate::provider::decoder(data);

        // Check for optional tag
        let typ = decoder
            .peek_type()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        if typ == CborType::Tag {
            let tag = decoder
                .decode_tag()
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
            if tag != COSE_SIGN1_TAG {
                return Err(CoseSign1Error::InvalidMessage(format!(
                    "unexpected COSE tag: expected {}, got {}",
                    COSE_SIGN1_TAG, tag
                )));
            }
        }

        // Decode the array
        let len = decoder
            .decode_array_len()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        match len {
            Some(4) => {}
            Some(n) => {
                return Err(CoseSign1Error::InvalidMessage(format!(
                    "COSE_Sign1 must have 4 elements, got {}",
                    n
                )))
            }
            None => {
                return Err(CoseSign1Error::InvalidMessage(
                    "COSE_Sign1 must be definite-length array".to_string(),
                ))
            }
        }

        // 1. Protected header (bstr containing CBOR map)
        let protected_slice = decoder
            .decode_bstr()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
        let protected_range = slice_range_in(protected_slice, data);
        let protected = LazyHeaderMap::new(raw.clone(), protected_range);

        // 2. Unprotected header (map) — capture the byte range via decoder position.
        let unprotected_start = decoder.position();
        let pre_decoded_map = Self::decode_unprotected_header(&mut decoder)?;
        let unprotected_end = decoder.position();
        // Wrap in a LazyHeaderMap that is already parsed (avoids re-parsing).
        let unprotected_range = unprotected_start..unprotected_end;
        let unprotected =
            LazyHeaderMap::from_parsed(raw.clone(), unprotected_range, pre_decoded_map);

        // 3. Payload (bstr or null)
        let payload_range = Self::decode_payload_range(&mut decoder, data)?;

        // 4. Signature (bstr)
        let signature_slice = decoder
            .decode_bstr()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
        let signature_range = slice_range_in(signature_slice, data);

        let cose_data = CoseData::from_arc(raw);

        Ok(Self {
            data: cose_data,
            protected,
            unprotected,
            payload_range,
            signature_range,
        })
    }

    /// Parses a COSE_Sign1 message from a seekable stream.
    ///
    /// Unlike [`parse`](Self::parse), this method does **not** read the payload
    /// into memory. Headers and signature are buffered; the payload is
    /// represented as a seekable byte range in the source stream. This gives
    /// a minimal memory footprint — typically under 1 KB for headers/signature
    /// regardless of payload size.
    ///
    /// Use [`payload_reader`](Self::payload_reader) to access the payload.
    /// The [`payload`](Self::payload) method returns `None` for streamed
    /// messages.
    ///
    /// # Arguments
    ///
    /// * `reader` - A seekable byte source containing a COSE_Sign1 message
    ///
    /// # Example
    ///
    /// ```ignore
    /// let file = std::fs::File::open("large.cose")?;
    /// let msg = CoseSign1Message::parse_stream(file)?;
    /// assert!(msg.is_streamed());
    /// let alg = msg.alg();
    /// ```
    #[cfg(feature = "cbor-everparse")]
    pub fn parse_stream<R: std::io::Read + std::io::Seek + Send + 'static>(
        reader: R,
    ) -> Result<Self, CoseSign1Error> {
        let data = CoseData::from_stream(reader).map_err(CoseSign1Error::from)?;

        // Extract ranges from the Streamed variant to build LazyHeaderMaps.
        let (header_buf_arc, protected_range, unprotected_range, sig_range) = match &data {
            CoseData::Streamed {
                header_buf,
                protected_range,
                unprotected_range,
                signature_range,
                ..
            } => (
                header_buf.clone(),
                protected_range.clone(),
                unprotected_range.clone(),
                signature_range.clone(),
            ),
            _ => unreachable!("from_stream always returns Streamed"),
        };

        let protected = LazyHeaderMap::new(header_buf_arc.clone(), protected_range);
        let unprotected = LazyHeaderMap::new(header_buf_arc, unprotected_range);

        // Payload is accessed through the stream, not through a byte range.
        let payload_range: Option<Range<usize>> = None;

        Ok(Self {
            data,
            protected,
            unprotected,
            payload_range,
            signature_range: sig_range,
        })
    }

    /// Returns `true` if this message was parsed from a stream
    /// (payload not in memory).
    pub fn is_streamed(&self) -> bool {
        self.data.is_streamed()
    }

    /// Returns a boxed reader for the payload.
    ///
    /// - **Buffered messages**: wraps the in-memory payload slice in a
    ///   [`Cursor`](std::io::Cursor). Returns `None` if the payload is
    ///   detached/nil.
    /// - **Streamed messages**: seeks the source stream to the payload offset
    ///   and returns a length-limited reader. Returns `None` if the payload
    ///   is nil (zero-length).
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(reader) = msg.payload_reader() {
    ///     let mut hasher = Sha256::new();
    ///     std::io::copy(&mut reader, &mut hasher)?;
    /// }
    /// ```
    pub fn payload_reader(&self) -> Option<Box<dyn std::io::Read + '_>> {
        match &self.data {
            CoseData::Buffered { .. } => self.payload_range.as_ref().map(|r| {
                let slice: &[u8] = self.data.slice(r);
                Box::new(std::io::Cursor::new(slice)) as Box<dyn std::io::Read>
            }),
            CoseData::Streamed {
                source,
                payload_offset,
                payload_len,
                ..
            } => {
                if *payload_len == 0 {
                    return None;
                }
                let mut src = source.lock().ok()?;
                src.seek(std::io::SeekFrom::Start(*payload_offset)).ok()?;
                // Read the payload into a buffer so we can return a reader
                // without holding the mutex lock across the caller's reads.
                let len: usize = usize::try_from(*payload_len).ok()?;
                let mut buf = vec![0u8; len];
                src.read_exact(&mut buf).ok()?;
                drop(src);
                Some(Box::new(std::io::Cursor::new(buf)) as Box<dyn std::io::Read>)
            }
        }
    }

    /// Returns a reference to the compile-time-selected CBOR provider.
    ///
    /// Convenience method so consumers can access encoding/decoding
    /// without importing cbor_primitives directly.
    #[inline]
    pub fn provider(&self) -> &'static CborProviderImpl {
        cbor_provider()
    }

    /// Parse a nested COSE_Sign1 message.
    pub fn parse_inner(&self, data: &[u8]) -> Result<Self, CoseSign1Error> {
        Self::parse(data)
    }

    /// Returns the raw protected header bytes (for verification).
    pub fn protected_header_bytes(&self) -> &[u8] {
        self.protected.as_bytes()
    }

    /// Returns the algorithm from the protected header.
    pub fn alg(&self) -> Option<i64> {
        self.protected.headers().alg()
    }

    /// Returns a reference to the parsed protected headers.
    pub fn protected_headers(&self) -> &CoseHeaderMap {
        self.protected.headers()
    }

    /// Returns a reference to the unprotected headers.
    pub fn unprotected_headers(&self) -> &CoseHeaderMap {
        self.unprotected.headers()
    }

    /// Returns the protected [`LazyHeaderMap`].
    pub fn protected(&self) -> &LazyHeaderMap {
        &self.protected
    }

    /// Returns the unprotected [`LazyHeaderMap`].
    pub fn unprotected(&self) -> &LazyHeaderMap {
        &self.unprotected
    }

    /// Returns the underlying [`CoseData`] buffer.
    pub fn cose_data(&self) -> &CoseData {
        &self.data
    }

    /// Returns true if the payload is detached.
    pub fn is_detached(&self) -> bool {
        self.payload_range.is_none()
    }

    /// Returns the payload bytes, or None if detached.
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload_range.as_ref().map(|r| self.data.slice(r))
    }

    /// Returns the signature bytes.
    pub fn signature(&self) -> &[u8] {
        self.data.slice(&self.signature_range)
    }

    /// Returns the full raw CBOR bytes of the message.
    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_bytes()
    }

    /// Verifies the signature on an embedded (buffered) payload.
    ///
    /// Builds the full Sig_structure in memory and passes it to the verifier
    /// in a single call. The entire payload must be in memory.
    ///
    /// For stream-parsed messages or large payloads, use
    /// [`verify_streamed`](Self::verify_streamed) or
    /// [`verify_payload_streaming`](Self::verify_payload_streaming) instead.
    ///
    /// # Arguments
    ///
    /// * `verifier` - The verifier to use
    /// * `external_aad` - Optional external additional authenticated data
    ///
    /// # Returns
    ///
    /// `true` if verification succeeds, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns `PayloadMissing` if the payload is detached.
    pub fn verify(
        &self,
        verifier: &dyn CryptoVerifier,
        external_aad: Option<&[u8]>,
    ) -> Result<bool, CoseSign1Error> {
        let payload = self.payload().ok_or(CoseSign1Error::PayloadMissing)?;
        let sig_structure =
            build_sig_structure(self.protected_header_bytes(), external_aad, payload)?;
        verifier
            .verify(&sig_structure, self.signature())
            .map_err(CoseKeyError::from)
            .map_err(CoseSign1Error::from)
    }

    /// Verifies the signature with a detached payload (buffered).
    ///
    /// Requires the full payload in memory. Builds the complete Sig_structure
    /// and passes it to the verifier in a single call.
    ///
    /// For large detached payloads, use
    /// [`verify_payload_streaming`](Self::verify_payload_streaming) instead.
    ///
    /// # Arguments
    ///
    /// * `verifier` - The verifier to use
    /// * `payload` - The detached payload bytes (must be fully materialized)
    /// * `external_aad` - Optional external additional authenticated data
    pub fn verify_detached(
        &self,
        verifier: &dyn CryptoVerifier,
        payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<bool, CoseSign1Error> {
        let sig_structure =
            build_sig_structure(self.protected_header_bytes(), external_aad, payload)?;
        verifier
            .verify(&sig_structure, self.signature())
            .map_err(CoseKeyError::from)
            .map_err(CoseSign1Error::from)
    }

    /// Verifies the signature with a streaming detached payload.
    ///
    /// For algorithms that support streaming (ECDSA, RSA-PSS), this truly
    /// streams the payload through the verifier with ~64 KB peak memory.
    /// For algorithms that don't support streaming (Ed25519, ML-DSA), the
    /// payload is buffered into memory as a fallback.
    ///
    /// # Arguments
    ///
    /// * `verifier` - The verifier to use
    /// * `payload` - A [`SizedRead`] providing the detached payload (reader + known length)
    /// * `external_aad` - Optional external additional authenticated data
    ///
    /// # Example
    ///
    /// ```ignore
    /// // File implements SizedRead directly
    /// let mut file = std::fs::File::open("payload.bin")?;
    /// msg.verify_detached_streaming(&verifier, &mut file, None)?;
    ///
    /// // Or wrap a reader with known length
    /// let mut payload = SizedReader::new(reader, content_length);
    /// msg.verify_detached_streaming(&verifier, &mut payload, None)?;
    /// ```
    pub fn verify_detached_streaming(
        &self,
        verifier: &dyn CryptoVerifier,
        payload: &mut dyn SizedRead,
        external_aad: Option<&[u8]>,
    ) -> Result<bool, CoseSign1Error> {
        let payload_len = payload
            .len()
            .map_err(|e| CoseSign1Error::IoError(e.to_string()))?;
        self.verify_payload_streaming(verifier, payload, payload_len, external_aad)
    }

    /// Verifies the signature with a detached payload from a plain `Read`.
    ///
    /// Use this when you have a reader with unknown length. The entire
    /// payload is read into memory first to determine the length.
    ///
    /// For large payloads with known length, prefer `verify_detached_streaming` with
    /// `SizedReader::new(reader, len)` instead.
    ///
    /// # Arguments
    ///
    /// * `verifier` - The verifier to use
    /// * `payload` - A reader providing the detached payload (will be buffered into memory)
    /// * `external_aad` - Optional external additional authenticated data
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Network stream with unknown length
    /// let mut stream = get_network_stream();
    /// msg.verify_detached_read(&verifier, &mut stream, None)?;
    /// ```
    pub fn verify_detached_read(
        &self,
        verifier: &dyn CryptoVerifier,
        payload: &mut dyn std::io::Read,
        external_aad: Option<&[u8]>,
    ) -> Result<bool, CoseSign1Error> {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(payload, &mut buf)
            .map_err(|e| CoseSign1Error::IoError(e.to_string()))?;
        self.verify_detached(verifier, &buf, external_aad)
    }

    /// Verifies the signature with a streaming payload source.
    ///
    /// Opens the [`StreamingPayload`] and delegates to
    /// [`verify_payload_streaming`](Self::verify_payload_streaming) for true
    /// streaming when the verifier supports it.
    ///
    /// # Arguments
    ///
    /// * `verifier` - The verifier to use
    /// * `payload` - A streaming payload source
    /// * `external_aad` - Optional external additional authenticated data
    pub fn verify_streaming(
        &self,
        verifier: &dyn CryptoVerifier,
        payload: Arc<dyn StreamingPayload>,
        external_aad: Option<&[u8]>,
    ) -> Result<bool, CoseSign1Error> {
        let reader = payload.open().map_err(CoseSign1Error::from)?;
        let len = payload.size();
        let mut sized = SizedReader::new(reader, len);
        self.verify_detached_streaming(verifier, &mut sized, external_aad)
    }

    /// Verify signature by streaming payload through the verifier.
    ///
    /// Peak memory usage is ~64 KB (chunk buffer) regardless of payload size,
    /// provided the verifier supports streaming.
    ///
    /// For algorithms that support streaming (ECDSA, RSA-PSS):
    ///   prefix → verifier.update() → payload chunks → verifier.finalize()
    ///
    /// For algorithms that don't support streaming (Ed25519, ML-DSA):
    ///   Falls back to full materialization via [`verify_detached`](Self::verify_detached).
    ///
    /// # Arguments
    ///
    /// * `verifier` - The cryptographic verifier
    /// * `payload` - A reader providing the payload bytes
    /// * `payload_len` - The total payload length in bytes (must match actual bytes read)
    /// * `external_aad` - Optional external additional authenticated data
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut file = std::fs::File::open("large_payload.bin")?;
    /// let len = file.metadata()?.len();
    /// let valid = msg.verify_payload_streaming(&verifier, &mut file, len, None)?;
    /// ```
    pub fn verify_payload_streaming<R: Read + ?Sized>(
        &self,
        verifier: &dyn CryptoVerifier,
        payload: &mut R,
        payload_len: u64,
        external_aad: Option<&[u8]>,
    ) -> Result<bool, CoseSign1Error> {
        let protected_bytes = self.protected_header_bytes();
        let signature = self.signature();
        let aad = external_aad.unwrap_or(&[]);

        if verifier.supports_streaming() {
            // True streaming: build prefix, feed to verifier, stream payload
            let prefix = build_sig_structure_prefix(protected_bytes, Some(aad), payload_len)?;
            let mut ctx = verifier
                .verify_init(signature)
                .map_err(CoseKeyError::from)?;
            ctx.update(&prefix).map_err(CoseKeyError::from)?;

            let mut buf = vec![0u8; 65536];
            let mut total = 0u64;
            loop {
                let n = payload
                    .read(&mut buf)
                    .map_err(|e| CoseSign1Error::IoError(e.to_string()))?;
                if n == 0 {
                    break;
                }
                ctx.update(&buf[..n]).map_err(CoseKeyError::from)?;
                total += n as u64;
            }

            if total != payload_len {
                return Err(CoseSign1Error::InvalidMessage(format!(
                    "payload length mismatch: expected {}, got {}",
                    payload_len, total
                )));
            }

            Ok(ctx.finalize().map_err(CoseKeyError::from)?)
        } else {
            // Fallback: materialize payload for non-streaming verifiers (Ed25519, ML-DSA)
            let mut payload_bytes = Vec::new();
            payload
                .read_to_end(&mut payload_bytes)
                .map_err(|e| CoseSign1Error::IoError(e.to_string()))?;
            let sig_structure = build_sig_structure(protected_bytes, Some(aad), &payload_bytes)?;
            Ok(verifier
                .verify(&sig_structure, signature)
                .map_err(CoseKeyError::from)?)
        }
    }

    /// Verify a stream-parsed message without materializing the full payload.
    ///
    /// For [`Streamed`](CoseData::Streamed) messages (created via
    /// [`parse_stream`](Self::parse_stream)), this seeks to the payload in
    /// the source stream and streams it through the verifier.
    ///
    /// For [`Buffered`](CoseData::Buffered) messages, delegates to
    /// [`verify`](Self::verify).
    ///
    /// # Arguments
    ///
    /// * `verifier` - The cryptographic verifier
    /// * `external_aad` - Optional external additional authenticated data
    ///
    /// # Example
    ///
    /// ```ignore
    /// let file = std::fs::File::open("large.cose")?;
    /// let msg = CoseSign1Message::parse_stream(file)?;
    /// let valid = msg.verify_streamed(&verifier, None)?;
    /// ```
    pub fn verify_streamed(
        &self,
        verifier: &dyn CryptoVerifier,
        external_aad: Option<&[u8]>,
    ) -> Result<bool, CoseSign1Error> {
        match &self.data {
            CoseData::Streamed {
                source,
                payload_offset,
                payload_len,
                ..
            } => {
                if *payload_len == 0 {
                    return Err(CoseSign1Error::PayloadMissing);
                }
                let mut src = source
                    .lock()
                    .map_err(|_| CoseSign1Error::IoError("lock poisoned".into()))?;
                src.seek(std::io::SeekFrom::Start(*payload_offset))
                    .map_err(|e| CoseSign1Error::IoError(e.to_string()))?;
                let len = *payload_len;
                // Read through the locked source in chunks to avoid holding the
                // lock across the entire streaming verify. We use a chunked
                // approach directly on the guard.
                self.verify_payload_streaming_from_guard(verifier, &mut *src, len, external_aad)
            }
            CoseData::Buffered { .. } => match self.payload() {
                Some(p) => self.verify_detached(verifier, p, external_aad),
                None => Err(CoseSign1Error::PayloadMissing),
            },
        }
    }

    /// Internal helper: stream from an already-positioned reader (e.g., a locked Mutex guard).
    fn verify_payload_streaming_from_guard(
        &self,
        verifier: &dyn CryptoVerifier,
        reader: &mut dyn Read,
        payload_len: u64,
        external_aad: Option<&[u8]>,
    ) -> Result<bool, CoseSign1Error> {
        self.verify_payload_streaming(verifier, reader, payload_len, external_aad)
    }

    /// Returns the raw CBOR-encoded Sig_structure bytes for this message.
    ///
    /// The Sig_structure is the data that is actually signed/verified:
    ///
    /// ```text
    /// Sig_structure = [
    ///     context: "Signature1",
    ///     body_protected: bstr,  // This message's protected header bytes
    ///     external_aad: bstr,
    ///     payload: bstr
    /// ]
    /// ```
    ///
    /// # When to Use
    ///
    /// For most use cases, prefer the `verify*` methods which handle Sig_structure
    /// construction internally. This method exists for special cases where you need
    /// direct access to the Sig_structure bytes, such as:
    ///
    /// - MST receipt verification where the "payload" is a merkle accumulator
    ///   computed externally rather than the message's actual payload
    /// - Custom verification flows with non-standard key types
    /// - Debugging and testing
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload bytes to include in the Sig_structure
    /// * `external_aad` - Optional external additional authenticated data
    ///
    /// # Example
    ///
    /// ```ignore
    /// // For MST receipt verification with computed accumulator
    /// let accumulator = compute_merkle_accumulator(&proof, &leaf_hash);
    /// let sig_structure = receipt.sig_structure_bytes(&accumulator, None)?;
    /// verify_with_jwk(&sig_structure, &receipt.signature, &jwk)?;
    /// ```
    pub fn sig_structure_bytes(
        &self,
        payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CoseSign1Error> {
        crate::build_sig_structure(self.protected_header_bytes(), external_aad, payload)
    }

    /// Encodes the message to CBOR bytes using the stored provider.
    ///
    /// # Arguments
    ///
    /// * `tagged` - If true, wraps the message in CBOR tag 18
    pub fn encode(&self, tagged: bool) -> Result<Vec<u8>, CoseSign1Error> {
        let provider = cbor_provider();
        let mut encoder = provider.encoder();

        // Optional tag
        if tagged {
            encoder
                .encode_tag(COSE_SIGN1_TAG)
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
        }

        // Array of 4 elements
        encoder
            .encode_array(4)
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        // 1. Protected header bytes
        encoder
            .encode_bstr(self.protected_header_bytes())
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        // 2. Unprotected header
        let unprotected_bytes = self.unprotected.headers().encode()?;
        encoder
            .encode_raw(&unprotected_bytes)
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        // 3. Payload
        match self.payload() {
            Some(p) => encoder
                .encode_bstr(p)
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?,
            None => encoder
                .encode_null()
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?,
        }

        // 4. Signature
        encoder
            .encode_bstr(self.signature())
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        Ok(encoder.into_bytes())
    }

    fn decode_unprotected_header(
        decoder: &mut crate::provider::Decoder<'_>,
    ) -> Result<CoseHeaderMap, CoseSign1Error> {
        let len = decoder
            .decode_map_len()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        if len == Some(0) {
            return Ok(CoseHeaderMap::new());
        }

        let mut headers = CoseHeaderMap::new();

        match len {
            Some(n) => {
                for _ in 0..n {
                    let label = Self::decode_header_label(decoder)?;
                    let value = Self::decode_header_value(decoder)?;
                    headers.insert(label, value);
                }
            }
            None => {
                // Indefinite length
                loop {
                    if decoder
                        .is_break()
                        .map_err(|e| CoseSign1Error::CborError(e.to_string()))?
                    {
                        decoder
                            .decode_break()
                            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                        break;
                    }
                    let label = Self::decode_header_label(decoder)?;
                    let value = Self::decode_header_value(decoder)?;
                    headers.insert(label, value);
                }
            }
        }

        Ok(headers)
    }

    fn decode_header_label(
        decoder: &mut crate::provider::Decoder<'_>,
    ) -> Result<CoseHeaderLabel, CoseSign1Error> {
        let typ = decoder
            .peek_type()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        match typ {
            CborType::UnsignedInt | CborType::NegativeInt => {
                let v = decoder
                    .decode_i64()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderLabel::Int(v))
            }
            CborType::TextString => {
                let v = decoder
                    .decode_tstr_owned()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderLabel::Text(v))
            }
            _ => Err(CoseSign1Error::InvalidMessage(format!(
                "invalid header label type: {:?}",
                typ
            ))),
        }
    }

    fn decode_header_value(
        decoder: &mut crate::provider::Decoder<'_>,
    ) -> Result<CoseHeaderValue, CoseSign1Error> {
        let typ = decoder
            .peek_type()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        match typ {
            CborType::UnsignedInt => {
                let v = decoder
                    .decode_u64()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                if v <= i64::MAX as u64 {
                    Ok(CoseHeaderValue::Int(v as i64))
                } else {
                    Ok(CoseHeaderValue::Uint(v))
                }
            }
            CborType::NegativeInt => {
                let v = decoder
                    .decode_i64()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Int(v))
            }
            CborType::ByteString => {
                let v = decoder
                    .decode_bstr_owned()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Bytes(v.into()))
            }
            CborType::TextString => {
                let v = decoder
                    .decode_tstr_owned()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Text(v.into()))
            }
            CborType::Array => {
                let len = decoder
                    .decode_array_len()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

                let mut arr = Vec::new();
                match len {
                    Some(n) => {
                        for _ in 0..n {
                            arr.push(Self::decode_header_value(decoder)?);
                        }
                    }
                    None => loop {
                        if decoder
                            .is_break()
                            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?
                        {
                            decoder
                                .decode_break()
                                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                            break;
                        }
                        arr.push(Self::decode_header_value(decoder)?);
                    },
                }
                Ok(CoseHeaderValue::Array(arr))
            }
            CborType::Map => {
                let len = decoder
                    .decode_map_len()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

                let mut pairs = Vec::new();
                match len {
                    Some(n) => {
                        for _ in 0..n {
                            let k = Self::decode_header_label(decoder)?;
                            let v = Self::decode_header_value(decoder)?;
                            pairs.push((k, v));
                        }
                    }
                    None => loop {
                        if decoder
                            .is_break()
                            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?
                        {
                            decoder
                                .decode_break()
                                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                            break;
                        }
                        let k = Self::decode_header_label(decoder)?;
                        let v = Self::decode_header_value(decoder)?;
                        pairs.push((k, v));
                    },
                }
                Ok(CoseHeaderValue::Map(pairs))
            }
            CborType::Tag => {
                let tag = decoder
                    .decode_tag()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                let inner = Self::decode_header_value(decoder)?;
                Ok(CoseHeaderValue::Tagged(tag, Box::new(inner)))
            }
            CborType::Bool => {
                let v = decoder
                    .decode_bool()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Bool(v))
            }
            CborType::Null => {
                decoder
                    .decode_null()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Null)
            }
            CborType::Undefined => {
                decoder
                    .decode_undefined()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Undefined)
            }
            CborType::Float16 | CborType::Float32 | CborType::Float64 => {
                let v = decoder
                    .decode_f64()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Float(v))
            }
            _ => {
                // Skip unknown types
                decoder
                    .skip()
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                Ok(CoseHeaderValue::Null)
            }
        }
    }

    fn decode_payload_range(
        decoder: &mut crate::provider::Decoder<'_>,
        data: &[u8],
    ) -> Result<Option<Range<usize>>, CoseSign1Error> {
        if decoder
            .is_null()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?
        {
            decoder
                .decode_null()
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
            return Ok(None);
        }

        let payload_slice = decoder
            .decode_bstr()
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
        Ok(Some(slice_range_in(payload_slice, data)))
    }
}

/// Computes the byte range of `slice` within `parent` using pointer arithmetic.
///
/// # Panics
///
/// Panics if `slice` is not a sub-slice of `parent`.
fn slice_range_in(slice: &[u8], parent: &[u8]) -> Range<usize> {
    let start = slice.as_ptr() as usize - parent.as_ptr() as usize;
    let end = start + slice.len();
    debug_assert!(
        end <= parent.len(),
        "slice_range_in: sub-slice is not within parent"
    );
    start..end
}
