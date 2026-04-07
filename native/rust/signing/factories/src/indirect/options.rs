// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Options for indirect signature factory.

use crate::direct::DirectSignatureOptions;

/// Hash algorithm for payload hashing.
///
/// Maps subset of COSE hash algorithms used in indirect signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashAlgorithm {
    /// SHA-256 (COSE algorithm -16)
    #[default]
    Sha256,
    /// SHA-384 (COSE algorithm -43)
    Sha384,
    /// SHA-512 (COSE algorithm -44)
    Sha512,
}

impl HashAlgorithm {
    /// Returns the COSE algorithm identifier.
    pub fn cose_algorithm_id(&self) -> i32 {
        match self {
            HashAlgorithm::Sha256 => -16,
            HashAlgorithm::Sha384 => -43,
            HashAlgorithm::Sha512 => -44,
        }
    }

    /// Returns the algorithm name.
    pub fn name(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha-256",
            HashAlgorithm::Sha384 => "sha-384",
            HashAlgorithm::Sha512 => "sha-512",
        }
    }
}

/// Options for creating indirect signatures.
///
/// Maps V2 `IndirectSignatureOptions`.
#[must_use = "builders do nothing unless consumed"]
#[derive(Default, Debug)]
pub struct IndirectSignatureOptions {
    /// Base options for the underlying direct signature.
    pub base: DirectSignatureOptions,

    /// Hash algorithm for payload hashing.
    ///
    /// Default is SHA-256.
    pub payload_hash_algorithm: HashAlgorithm,

    /// Optional URI indicating the location of the original payload.
    ///
    /// This is added to COSE header 260 (PayloadLocation).
    pub payload_location: Option<String>,
}

impl IndirectSignatureOptions {
    /// Creates new options with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the hash algorithm.
    pub fn with_hash_algorithm(mut self, alg: HashAlgorithm) -> Self {
        self.payload_hash_algorithm = alg;
        self
    }

    /// Sets the payload location.
    pub fn with_payload_location(mut self, location: impl Into<String>) -> Self {
        self.payload_location = Some(location.into());
        self
    }

    /// Sets the base direct signature options.
    pub fn with_base_options(mut self, base: DirectSignatureOptions) -> Self {
        self.base = base;
        self
    }
}
