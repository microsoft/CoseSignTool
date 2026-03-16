// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key algorithm types and defaults.

/// Cryptographic algorithm to use for key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// RSA algorithm. Default key size is 2048 bits.
    Rsa,
    /// Elliptic Curve Digital Signature Algorithm. Default key size is 256 bits (P-256 curve).
    Ecdsa,
    /// Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
    /// Post-quantum cryptographic algorithm. Default parameter set is 65.
    #[cfg(feature = "pqc")]
    MlDsa,
}

impl KeyAlgorithm {
    /// Returns the default key size for this algorithm.
    ///
    /// - RSA: 2048 bits
    /// - ECDSA: 256 bits (P-256 curve)
    /// - ML-DSA: 65 (parameter set)
    pub fn default_key_size(&self) -> u32 {
        match self {
            Self::Rsa => 2048,
            Self::Ecdsa => 256,
            #[cfg(feature = "pqc")]
            Self::MlDsa => 65,
        }
    }
}

impl Default for KeyAlgorithm {
    fn default() -> Self {
        Self::Ecdsa
    }
}
