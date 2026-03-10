// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Payload types for CoseSign1 messages.
//!
//! Provides abstractions for both in-memory and streaming payloads.
//!
//! [`StreamingPayload`] is a factory that produces readers implementing [`SizedRead`],
//! allowing payloads to be read multiple times (e.g., once for signing, once for verification)
//! while carrying size information.

use crate::error::PayloadError;
use crate::sig_structure::SizedRead;

/// A payload that supports streaming access.
///
/// This trait allows for efficient handling of large payloads without
/// loading the entire content into memory. The returned reader implements
/// [`SizedRead`], providing both streaming access and size information.
pub trait StreamingPayload: Send + Sync {
    /// Returns the total size of the payload in bytes.
    ///
    /// This is a convenience method - the same value is available via
    /// [`SizedRead::len()`] on the reader returned by [`open()`](Self::open).
    fn size(&self) -> u64;

    /// Opens the payload for reading.
    ///
    /// Each call should return a new reader starting from the beginning
    /// of the payload. This allows the payload to be read multiple times
    /// (e.g., once for signing, once for verification).
    ///
    /// The returned reader implements [`SizedRead`], so callers can use
    /// [`SizedRead::len()`] to get the payload size.
    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError>;
}

/// A file-based streaming payload.
///
/// Reads payload data from a file on disk.
#[derive(Clone, Debug)]
pub struct FilePayload {
    path: std::path::PathBuf,
    size: u64,
}

impl FilePayload {
    /// Creates a new file payload from the given path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file doesn't exist or can't be accessed.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Result<Self, PayloadError> {
        let path = path.into();
        let metadata = std::fs::metadata(&path)
            .map_err(|e| PayloadError::OpenFailed(format!("{}: {}", path.display(), e)))?;
        Ok(Self {
            path,
            size: metadata.len(),
        })
    }

    /// Returns the path to the payload file.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl StreamingPayload for FilePayload {
    fn size(&self) -> u64 {
        self.size
    }

    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
        let file = std::fs::File::open(&self.path)
            .map_err(|e| PayloadError::OpenFailed(format!("{}: {}", self.path.display(), e)))?;
        Ok(Box::new(file))
    }
}

/// An in-memory payload.
///
/// Stores the entire payload in memory. Suitable for small payloads.
#[derive(Clone, Debug)]
pub struct MemoryPayload {
    data: Vec<u8>,
}

impl MemoryPayload {
    /// Creates a new in-memory payload.
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self { data: data.into() }
    }

    /// Returns a reference to the payload data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the payload and returns the underlying data.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

impl StreamingPayload for MemoryPayload {
    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
        Ok(Box::new(std::io::Cursor::new(self.data.clone())))
    }
}

impl From<Vec<u8>> for MemoryPayload {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for MemoryPayload {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

/// Payload source for signing/verification.
///
/// This enum allows callers to provide either in-memory bytes or
/// a streaming payload source.
pub enum Payload {
    /// In-memory payload bytes.
    Bytes(Vec<u8>),
    /// Streaming payload source.
    Streaming(Box<dyn StreamingPayload>),
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes(data) => f
                .debug_tuple("Bytes")
                .field(&format_args!("{} bytes", data.len()))
                .finish(),
            Self::Streaming(_) => f
                .debug_tuple("Streaming")
                .field(&format_args!("<dyn StreamingPayload>"))
                .finish(),
        }
    }
}

impl Payload {
    /// Returns the size of the payload.
    pub fn size(&self) -> u64 {
        match self {
            Self::Bytes(data) => data.len() as u64,
            Self::Streaming(stream) => stream.size(),
        }
    }

    /// Returns true if this is a streaming payload.
    pub fn is_streaming(&self) -> bool {
        matches!(self, Self::Streaming(_))
    }

    /// Returns the payload bytes if this is an in-memory payload.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(data) => Some(data),
            Self::Streaming(_) => None,
        }
    }
}

impl From<Vec<u8>> for Payload {
    fn from(data: Vec<u8>) -> Self {
        Self::Bytes(data)
    }
}

impl From<&[u8]> for Payload {
    fn from(data: &[u8]) -> Self {
        Self::Bytes(data.to_vec())
    }
}
