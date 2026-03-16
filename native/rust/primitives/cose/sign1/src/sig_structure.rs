// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Sig_structure construction per RFC 9052.
//!
//! The Sig_structure is the data that is actually signed and verified
//! in COSE_Sign1 messages.
//!
//! # Streaming Support
//!
//! For large payloads, use [`SizedRead`] to enable true chunked streaming:
//!
//! ```ignore
//! use std::fs::File;
//! use cose_sign1_primitives::{SizedRead, hash_sig_structure_streaming};
//!
//! // File implements SizedRead automatically
//! let file = File::open("large_payload.bin")?;
//! let hash = hash_sig_structure_streaming(
//!     &provider,
//!     Sha256::new(),
//!     protected_bytes,
//!     None,
//!     file,
//! )?;
//! ```

use std::io::{Read, Write};

use cbor_primitives::CborEncoder;

use crate::error::CoseSign1Error;

/// Signature1 context string per RFC 9052.
pub const SIG_STRUCTURE_CONTEXT: &str = "Signature1";

/// Builds the Sig_structure for COSE_Sign1 signing/verification (RFC 9052 Section 4.4).
///
/// The Sig_structure is the "To-Be-Signed" (TBS) data that is hashed and signed:
///
/// ```text
/// Sig_structure = [
///     context: "Signature1",
///     body_protected: bstr,  (CBOR-encoded protected headers)
///     external_aad: bstr,    (empty bstr if None)
///     payload: bstr
/// ]
/// ```
///
/// # Arguments
///
/// * `provider` - CBOR provider for encoding
/// * `protected_header_bytes` - The CBOR-encoded protected header bytes
/// * `external_aad` - Optional external additional authenticated data
/// * `payload` - The payload bytes
///
/// # Returns
///
/// The CBOR-encoded Sig_structure bytes.
pub fn build_sig_structure(
    protected_header_bytes: &[u8],
    external_aad: Option<&[u8]>,
    payload: &[u8],
) -> Result<Vec<u8>, CoseSign1Error> {
    let external = external_aad.unwrap_or(&[]);

    let mut encoder = crate::provider::encoder();

    // Array with 4 items
    encoder
        .encode_array(4)
        .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

    // 1. Context string
    encoder
        .encode_tstr(SIG_STRUCTURE_CONTEXT)
        .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

    // 2. Protected header bytes (as bstr)
    encoder
        .encode_bstr(protected_header_bytes)
        .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

    // 3. External AAD (as bstr)
    encoder
        .encode_bstr(external)
        .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

    // 4. Payload (as bstr)
    encoder
        .encode_bstr(payload)
        .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

    Ok(encoder.into_bytes())
}

/// Builds a Sig_structure prefix for streaming (without final payload bytes).
///
/// Returns CBOR bytes up to and including the payload bstr length prefix.
/// The caller then streams the payload bytes directly after this prefix.
///
/// This enables true streaming for large payloads - the hash can be computed
/// incrementally without loading the entire payload into memory.
///
/// # Arguments
///
/// * `provider` - CBOR provider for encoding
/// * `protected_header_bytes` - The CBOR-encoded protected header bytes
/// * `external_aad` - Optional external additional authenticated data
/// * `payload_len` - The total length of the payload in bytes
///
/// # Returns
///
/// CBOR bytes that should be followed by exactly `payload_len` bytes of payload data.
///
/// # Example
///
/// ```ignore
/// // Build the prefix
/// let prefix = build_sig_structure_prefix(&provider, protected_bytes, None, payload_len)?;
///
/// // Create a hasher and feed it the prefix
/// let mut hasher = Sha256::new();
/// hasher.update(&prefix);
///
/// // Stream the payload through the hasher
/// let mut buffer = [0u8; 8192];
/// loop {
///     let n = payload_reader.read(&mut buffer)?;
///     if n == 0 { break; }
///     hasher.update(&buffer[..n]);
/// }
///
/// // Get the final hash and sign it
/// let hash = hasher.finalize();
/// ```
pub fn build_sig_structure_prefix(
    protected_header_bytes: &[u8],
    external_aad: Option<&[u8]>,
    payload_len: u64,
) -> Result<Vec<u8>, CoseSign1Error> {
    let external = external_aad.unwrap_or(&[]);

    let mut encoder = crate::provider::encoder();

    // Array header (4 items)
    encoder
        .encode_array(4)
        .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

    // 1. Context string
    encoder
        .encode_tstr(SIG_STRUCTURE_CONTEXT)
        .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

    // 2. Protected header bytes (as bstr)
    encoder
        .encode_bstr(protected_header_bytes)
        .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

    // 3. External AAD (as bstr)
    encoder
        .encode_bstr(external)
        .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

    // 4. Payload bstr header only (no content)
    encoder
        .encode_bstr_header(payload_len)
        .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

    Ok(encoder.into_bytes())
}

/// Helper for streaming Sig_structure hashing.
///
/// This is a streaming hasher that:
/// 1. Writes the Sig_structure prefix (using build_sig_structure_prefix)
/// 2. Streams payload chunks directly to the hasher
/// 3. Produces the final hash for signing/verification
///
/// The hasher `H` should be a crypto hash that implements Write (e.g., sha2::Sha256).
///
/// # Example
///
/// ```ignore
/// use sha2::{Sha256, Digest};
///
/// let mut hasher = SigStructureHasher::new(Sha256::new());
/// hasher.init(&provider, protected_bytes, external_aad, payload_len)?;
///
/// // Stream payload in chunks
/// for chunk in payload_chunks {
///     hasher.update(chunk)?;
/// }
///
/// let hash = hasher.finalize();
/// ```
pub struct SigStructureHasher<H> {
    hasher: H,
    initialized: bool,
}

impl<H: Write> SigStructureHasher<H> {
    /// Create a new streaming hasher.
    pub fn new(hasher: H) -> Self {
        Self {
            hasher,
            initialized: false,
        }
    }

    /// Initialize with Sig_structure prefix.
    ///
    /// Must be called before update(). Writes the CBOR prefix:
    /// `array(4) + "Signature1" + bstr(protected) + bstr(external_aad) + bstr_header(payload_len)`
    pub fn init(
        &mut self,
        protected_header_bytes: &[u8],
        external_aad: Option<&[u8]>,
        payload_len: u64,
    ) -> Result<(), CoseSign1Error> {
        if self.initialized {
            return Err(CoseSign1Error::InvalidMessage(
                "SigStructureHasher already initialized".to_string(),
            ));
        }

        let prefix = build_sig_structure_prefix(
            protected_header_bytes,
            external_aad,
            payload_len,
        )?;

        self.hasher
            .write_all(&prefix)
            .map_err(|e| CoseSign1Error::CborError(format!("hash write failed: {}", e)))?;

        self.initialized = true;
        Ok(())
    }

    /// Stream payload chunks to the hasher.
    ///
    /// Call this repeatedly with payload data. Total bytes must equal payload_len from init().
    pub fn update(&mut self, chunk: &[u8]) -> Result<(), CoseSign1Error> {
        if !self.initialized {
            return Err(CoseSign1Error::InvalidMessage(
                "SigStructureHasher not initialized - call init() first".to_string(),
            ));
        }

        self.hasher
            .write_all(chunk)
            .map_err(|e| CoseSign1Error::CborError(format!("hash write failed: {}", e)))?;

        Ok(())
    }

    /// Consume the hasher and return the inner hasher for finalization.
    ///
    /// The caller is responsible for calling the appropriate finalize method
    /// on the returned hasher (e.g., `hasher.finalize()` for sha2 Digest types).
    pub fn into_inner(self) -> H {
        self.hasher
    }
}

/// Convenience method for hashers that implement Clone.
impl<H: Write + Clone> SigStructureHasher<H> {
    /// Get a clone of the current hasher state.
    pub fn clone_hasher(&self) -> H {
        self.hasher.clone()
    }
}
// ============================================================================
// Streaming Payload Abstraction
// ============================================================================

/// A readable stream with a known length.
///
/// This trait enables true streaming for Sig_structure hashing without loading
/// the entire payload into memory. The length is required upfront because CBOR
/// byte string encoding needs the length in the header before the content.
///
/// # Automatic Implementations
///
/// This trait is automatically implemented for:
/// - `std::fs::File` (via Seek)
/// - `std::io::Cursor<T>` where T: AsRef<[u8]>
/// - Any `&[u8]` slice
///
/// # Example
///
/// ```ignore
/// use std::fs::File;
/// use cose_sign1_primitives::SizedRead;
///
/// let file = File::open("payload.bin")?;
/// assert!(file.len().is_ok()); // SizedRead is implemented for File
/// ```
pub trait SizedRead: Read {
    /// Returns the total number of bytes in this stream.
    ///
    /// This must be accurate - the CBOR bstr header is encoded using this value.
    fn len(&self) -> Result<u64, std::io::Error>;

    /// Returns true if the stream has zero bytes.
    fn is_empty(&self) -> Result<bool, std::io::Error> {
        Ok(self.len()? == 0)
    }
}

/// A wrapper that adds a known length to any Read.
///
/// Use this when you know the payload length but your reader doesn't implement Seek.
///
/// # Example
///
/// ```ignore
/// use cose_sign1_primitives::SizedReader;
///
/// let reader = get_network_stream();
/// let payload_len = response.content_length().unwrap();
/// let sized = SizedReader::new(reader, payload_len);
/// ```
#[derive(Debug)]
pub struct SizedReader<R> {
    inner: R,
    len: u64,
}

impl<R> SizedReader<R> {
    /// Create a new SizedReader with a known length.
    pub fn new(reader: R, len: u64) -> Self {
        Self { inner: reader, len }
    }

    /// Consume this wrapper and return the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for SizedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read> SizedRead for SizedReader<R> {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.len)
    }
}

/// SizedRead for byte slices (already know the length).
impl SizedRead for &[u8] {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok((*self).len() as u64)
    }
}

/// SizedRead for std::fs::File (uses metadata).
impl SizedRead for std::fs::File {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.metadata()?.len())
    }
}

/// SizedRead for Cursor over byte containers.
impl<T: AsRef<[u8]>> SizedRead for std::io::Cursor<T> {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.get_ref().as_ref().len() as u64)
    }
}

// ============================================================================
// Converting Read to SizedRead
// ============================================================================

/// A wrapper that adds length to any `Read + Seek` by seeking.
///
/// This is more efficient than buffering because it doesn't need to
/// load the entire stream into memory - it just seeks to the end
/// to determine the length, then seeks back.
///
/// # Example
///
/// ```ignore
/// use std::fs::File;
/// use cose_sign1_primitives::SizedSeekReader;
///
/// // For seekable streams where you don't want to use File directly
/// let file = File::open("payload.bin")?;
/// let mut sized = SizedSeekReader::new(file)?;
/// key.sign_streaming(protected, &mut sized, None)?;
/// ```
#[derive(Debug)]
pub struct SizedSeekReader<R> {
    inner: R,
    len: u64,
}

impl<R: Read + std::io::Seek> SizedSeekReader<R> {
    /// Create a new SizedSeekReader by seeking to determine length.
    ///
    /// This seeks to the end to get the length, then seeks back to the
    /// current position.
    pub fn new(mut reader: R) -> std::io::Result<Self> {
        use std::io::SeekFrom;
        
        let current = reader.stream_position()?;
        let end = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(current))?;
        
        Ok(Self {
            inner: reader,
            len: end - current,
        })
    }

    /// Consume this wrapper and return the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for SizedSeekReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read> SizedRead for SizedSeekReader<R> {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.len)
    }
}

/// Buffer an entire `Read` stream into memory to create a `SizedRead`.
///
/// Use this as a fallback when you have a reader with unknown length
/// (e.g., network streams without Content-Length, pipes, compressed data).
///
/// **Warning:** This reads the entire stream into memory. For large payloads,
/// prefer using `SizedSeekReader` if the stream is seekable, or pass the
/// length directly with `SizedReader::new()` if you know it.
///
/// # Example
///
/// ```ignore
/// use cose_sign1_primitives::sized_from_read_buffered;
///
/// // Network stream with unknown length
/// let response_body = get_network_stream();
/// let mut payload = sized_from_read_buffered(response_body)?;
/// key.sign_streaming(protected, &mut payload, None)?;
/// ```
pub fn sized_from_read_buffered<R: Read>(mut reader: R) -> std::io::Result<std::io::Cursor<Vec<u8>>> {
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    Ok(std::io::Cursor::new(buffer))
}

/// Create a `SizedRead` from a seekable reader.
///
/// This is a convenience function that wraps a `Read + Seek` in a
/// `SizedSeekReader`, determining the length by seeking.
///
/// # Example
///
/// ```ignore
/// use cose_sign1_primitives::sized_from_seekable;
///
/// let file = std::fs::File::open("payload.bin")?;
/// let mut payload = sized_from_seekable(file)?;
/// ```
pub fn sized_from_seekable<R: Read + std::io::Seek>(reader: R) -> std::io::Result<SizedSeekReader<R>> {
    SizedSeekReader::new(reader)
}

// ============================================================================
// Ergonomic Constructors
// ============================================================================

/// Extension trait for converting common types into `SizedRead`.
///
/// This provides a fluent `.into_sized()` method for types where
/// the length can be determined automatically.
///
/// # Why This Exists
///
/// Rust's `Read` trait intentionally doesn't include length because many
/// streams have unknown length (network sockets, pipes, compressed data).
/// However, CBOR requires knowing the byte string length upfront for the
/// header encoding. This trait bridges that gap for common cases.
///
/// # Automatic Implementations
///
/// - `std::fs::File` - length from `metadata()`
/// - `std::io::Cursor<T>` - length from inner buffer
/// - `&[u8]` - length is trivial
/// - `Vec<u8>` - converts to Cursor
///
/// # Example
///
/// ```ignore
/// use std::fs::File;
/// use cose_sign1_primitives::IntoSizedRead;
///
/// let file = File::open("payload.bin")?;
/// let sized = file.into_sized()?;  // SizedRead with length from metadata
/// ```
pub trait IntoSizedRead {
    /// The resulting SizedRead type.
    type Output: SizedRead;
    /// The error type if length cannot be determined.
    type Error;

    /// Convert this into a SizedRead.
    fn into_sized(self) -> Result<Self::Output, Self::Error>;
}

/// Files can be converted to SizedRead (they implement SizedRead directly).
impl IntoSizedRead for std::fs::File {
    type Output = std::fs::File;
    type Error = std::convert::Infallible;

    fn into_sized(self) -> Result<Self::Output, Self::Error> {
        Ok(self)
    }
}

/// Cursors over byte containers implement SizedRead directly.
impl<T: AsRef<[u8]>> IntoSizedRead for std::io::Cursor<T> {
    type Output = std::io::Cursor<T>;
    type Error = std::convert::Infallible;

    fn into_sized(self) -> Result<Self::Output, Self::Error> {
        Ok(self)
    }
}

/// Vec<u8> converts to a Cursor for SizedRead.
impl IntoSizedRead for Vec<u8> {
    type Output = std::io::Cursor<Vec<u8>>;
    type Error = std::convert::Infallible;

    fn into_sized(self) -> Result<Self::Output, Self::Error> {
        Ok(std::io::Cursor::new(self))
    }
}

/// Box<[u8]> converts to a Cursor for SizedRead.
impl IntoSizedRead for Box<[u8]> {
    type Output = std::io::Cursor<Box<[u8]>>;
    type Error = std::convert::Infallible;

    fn into_sized(self) -> Result<Self::Output, Self::Error> {
        Ok(std::io::Cursor::new(self))
    }
}

/// Open a file as a SizedRead.
///
/// This is a convenience function that opens a file and wraps it
/// for use with streaming Sig_structure operations.
///
/// # Example
///
/// ```ignore
/// use cose_sign1_primitives::open_sized_file;
///
/// let payload = open_sized_file("large_payload.bin")?;
/// let hash = hash_sig_structure_streaming(&provider, hasher, protected, None, payload)?;
/// ```
pub fn open_sized_file<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Create a SizedRead from bytes with a known length.
///
/// This is useful when you have a reader and separately know the length
/// (e.g., from an HTTP Content-Length header).
///
/// # Example
///
/// ```ignore
/// use cose_sign1_primitives::sized_from_reader;
///
/// // HTTP response with known Content-Length
/// let body = response.into_reader();
/// let content_length = response.content_length().unwrap();
/// let payload = sized_from_reader(body, content_length);
/// ```
pub fn sized_from_reader<R: Read>(reader: R, len: u64) -> SizedReader<R> {
    SizedReader::new(reader, len)
}

/// Create a SizedRead from in-memory bytes.
///
/// # Example
///
/// ```ignore
/// use cose_sign1_primitives::sized_from_bytes;
///
/// let payload = sized_from_bytes(my_bytes);
/// ```
pub fn sized_from_bytes<T: AsRef<[u8]>>(bytes: T) -> std::io::Cursor<T> {
    std::io::Cursor::new(bytes)
}

/// Default chunk size for streaming operations (64 KB).
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Hash a Sig_structure with streaming payload, automatically chunking.
///
/// This is the ergonomic way to hash a COSE Sig_structure for large payloads
/// without loading them entirely into memory.
///
/// # How It Works
///
/// 1. Encodes the Sig_structure prefix with the bstr header sized for `payload.len()`
/// 2. Writes the prefix to the hasher
/// 3. Reads the payload in chunks and feeds each chunk to the hasher
/// 4. Returns the hasher for finalization
///
/// # Example
///
/// ```ignore
/// use sha2::{Sha256, Digest};
/// use cose_sign1_primitives::{hash_sig_structure_streaming, SizedReader};
///
/// let file = std::fs::File::open("large_payload.bin")?;
/// let file_len = file.metadata()?.len();
/// let payload = SizedReader::new(file, file_len);
///
/// let hasher = hash_sig_structure_streaming(
///     &provider,
///     Sha256::new(),
///     protected_header_bytes,
///     None, // external_aad
///     payload,
/// )?;
///
/// let hash: [u8; 32] = hasher.finalize().into();
/// ```
pub fn hash_sig_structure_streaming<H, R>(
    mut hasher: H,
    protected_header_bytes: &[u8],
    external_aad: Option<&[u8]>,
    mut payload: R,
) -> Result<H, CoseSign1Error>
where
    H: Write,
    R: SizedRead,
{
    hash_sig_structure_streaming_chunked(
        &mut hasher,
        protected_header_bytes,
        external_aad,
        &mut payload,
        DEFAULT_CHUNK_SIZE,
    )?;
    Ok(hasher)
}

/// Hash a Sig_structure with streaming payload and custom chunk size.
///
/// Same as [`hash_sig_structure_streaming`] but with configurable chunk size.
/// This variant takes mutable references, allowing you to reuse buffers.
pub fn hash_sig_structure_streaming_chunked<H, R>(
    hasher: &mut H,
    protected_header_bytes: &[u8],
    external_aad: Option<&[u8]>,
    payload: &mut R,
    chunk_size: usize,
) -> Result<u64, CoseSign1Error>
where
    H: Write,
    R: SizedRead,
{
    let payload_len = payload
        .len()
        .map_err(|e| CoseSign1Error::IoError(format!("failed to get payload length: {}", e)))?;

    // Build and write the prefix (includes bstr header for payload_len)
    let prefix = build_sig_structure_prefix(protected_header_bytes, external_aad, payload_len)?;
    hasher
        .write_all(&prefix)
        .map_err(|e| CoseSign1Error::IoError(format!("hash write failed: {}", e)))?;

    // Stream payload in chunks
    let mut buffer = vec![0u8; chunk_size];
    let mut total_read = 0u64;

    loop {
        let n = payload
            .read(&mut buffer)
            .map_err(|e| CoseSign1Error::IoError(format!("payload read failed: {}", e)))?;

        if n == 0 {
            break;
        }

        hasher
            .write_all(&buffer[..n])
            .map_err(|e| CoseSign1Error::IoError(format!("hash write failed: {}", e)))?;

        total_read += n as u64;
    }

    // Verify we read the expected amount
    if total_read != payload_len {
        return Err(CoseSign1Error::PayloadError(crate::PayloadError::LengthMismatch {
            expected: payload_len,
            actual: total_read,
        }));
    }

    Ok(total_read)
}

/// Stream a Sig_structure directly to a writer (for signature verification).
///
/// This writes the complete CBOR Sig_structure to the provided writer,
/// streaming the payload in chunks. Useful when verification requires
/// the full Sig_structure as a stream (e.g., for ring's signature verification).
///
/// # Example
///
/// ```ignore
/// use cose_sign1_primitives::{stream_sig_structure, SizedReader};
///
/// let mut sig_structure_bytes = Vec::new();
/// let payload = SizedReader::new(payload_reader, payload_len);
///
/// stream_sig_structure(
///     &provider,
///     &mut sig_structure_bytes,
///     protected_header_bytes,
///     None,
///     payload,
/// )?;
/// ```
pub fn stream_sig_structure<W, R>(
    writer: &mut W,
    protected_header_bytes: &[u8],
    external_aad: Option<&[u8]>,
    mut payload: R,
) -> Result<u64, CoseSign1Error>
where
    W: Write,
    R: SizedRead,
{
    stream_sig_structure_chunked(
        writer,
        protected_header_bytes,
        external_aad,
        &mut payload,
        DEFAULT_CHUNK_SIZE,
    )
}

/// Stream a Sig_structure with custom chunk size.
pub fn stream_sig_structure_chunked<W, R>(
    writer: &mut W,
    protected_header_bytes: &[u8],
    external_aad: Option<&[u8]>,
    payload: &mut R,
    chunk_size: usize,
) -> Result<u64, CoseSign1Error>
where
    W: Write,
    R: SizedRead,
{
    let payload_len = payload
        .len()
        .map_err(|e| CoseSign1Error::IoError(format!("failed to get payload length: {}", e)))?;

    // Build and write the prefix
    let prefix = build_sig_structure_prefix(protected_header_bytes, external_aad, payload_len)?;
    writer
        .write_all(&prefix)
        .map_err(|e| CoseSign1Error::IoError(format!("write failed: {}", e)))?;

    // Stream payload in chunks
    let mut buffer = vec![0u8; chunk_size];
    let mut total_read = 0u64;

    loop {
        let n = payload
            .read(&mut buffer)
            .map_err(|e| CoseSign1Error::IoError(format!("payload read failed: {}", e)))?;

        if n == 0 {
            break;
        }

        writer
            .write_all(&buffer[..n])
            .map_err(|e| CoseSign1Error::IoError(format!("write failed: {}", e)))?;

        total_read += n as u64;
    }

    // Verify we read the expected amount
    if total_read != payload_len {
        return Err(CoseSign1Error::PayloadError(crate::PayloadError::LengthMismatch {
            expected: payload_len,
            actual: total_read,
        }));
    }

    Ok(total_read)
}
