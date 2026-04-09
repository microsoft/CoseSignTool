// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key algorithm types and defaults.

/// Cryptographic algorithm to use for key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyAlgorithm {
    /// RSA algorithm. Default key size is 2048 bits.
    Rsa,
    /// Elliptic Curve Digital Signature Algorithm. Default key size is 256 bits (P-256 curve).
    #[default]
    Ecdsa,
    /// Edwards-curve Digital Signature Algorithm (Ed25519 / Ed448).
    /// Pure signature scheme — no external digest. Key size 255 → Ed25519, 448 → Ed448.
    EdDsa,
    /// Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
    /// Post-quantum cryptographic algorithm. Default parameter set is 65.
    #[cfg(feature = "pqc")]
    MlDsa,
    /// IETF composite: ML-DSA + ECDSA dual key/signature.
    ///
    /// Produces X.509 certificates with composite public keys and composite
    /// signatures per the IETF draft-ietf-lamps-pq-composite-sigs spec.
    /// The key_size selects the ML-DSA parameter set (44/65/87) and the
    /// classical algorithm is auto-selected:
    /// - 44 → ML-DSA-44 + ECDSA-P256-SHA256
    /// - 65 → ML-DSA-65 + ECDSA-P384-SHA384
    /// - 87 → ML-DSA-87 + ECDSA-P384-SHA384
    ///
    /// Requires OpenSSL 3.5+ with the composite provider.
    #[cfg(feature = "composite")]
    Composite,
}

impl KeyAlgorithm {
    /// Returns the default key size for this algorithm.
    ///
    /// - RSA: 2048 bits
    /// - ECDSA: 256 bits (P-256 curve)
    /// - EdDSA: 255 (Ed25519)
    /// - ML-DSA: 65 (parameter set)
    pub fn default_key_size(&self) -> u32 {
        match self {
            Self::Rsa => 2048,
            Self::Ecdsa => 256,
            Self::EdDsa => 255,
            #[cfg(feature = "pqc")]
            Self::MlDsa => 65,
            #[cfg(feature = "composite")]
            Self::Composite => 65,
        }
    }

    /// Returns true if this algorithm is a pure signature scheme (no external digest).
    pub fn is_pure_signature(&self) -> bool {
        match self {
            Self::EdDsa => true,
            #[cfg(feature = "pqc")]
            Self::MlDsa => true,
            #[cfg(feature = "composite")]
            Self::Composite => true,
            _ => false,
        }
    }
}
