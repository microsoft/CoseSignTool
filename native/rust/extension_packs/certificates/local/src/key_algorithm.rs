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
    /// **EXPERIMENTAL** — Hybrid PQC: classical ECDSA + ML-DSA dual key/signature.
    ///
    /// ⚠️ This feature is experimental. The IETF composite signature spec
    /// (draft-ietf-lamps-pq-composite-sigs) is still evolving, and the
    /// required OpenSSL OQS provider has unstable algorithm naming.
    /// Pure ML-DSA (`KeyAlgorithm::MlDsa`) is the recommended PQC path today.
    ///
    /// The key_size selects the ML-DSA parameter set and paired classical algorithm:
    /// - 44 → p256_mldsa44 (ECDSA-P256 + ML-DSA-44)
    /// - 65 → p384_mldsa65 (ECDSA-P384 + ML-DSA-65) [default]
    /// - 87 → p384_mldsa87 (ECDSA-P384 + ML-DSA-87)
    ///
    /// Requires OpenSSL 3.5+ with the OQS provider installed.
    /// See `native/scripts/setup-oqs-provider.ps1` for setup instructions.
    #[cfg(feature = "composite")]
    #[deprecated(note = "Experimental: IETF composite spec is in flux. Use MlDsa for stable PQC.")]
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
