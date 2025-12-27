// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Supported COSE algorithms (IANA COSE Algorithms registry).
///
/// Note: this enum includes provisional algorithm IDs used by this repo for ML-DSA.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(i64)]
pub enum CoseAlgorithm {
    /// ECDSA w/ SHA-256 over P-256.
    ES256 = -7,
    /// ECDSA w/ SHA-384 over P-384.
    ES384 = -35,
    /// ECDSA w/ SHA-512 over P-521.
    ES512 = -36,
    // Provisional COSE algorithm IDs used by this repo for ML-DSA (post-quantum).
    /// ML-DSA-44 (provisional COSE alg id used by this repo).
    MLDsa44 = -48,
    /// ML-DSA-65 (provisional COSE alg id used by this repo).
    MLDsa65 = -49,
    /// ML-DSA-87 (provisional COSE alg id used by this repo).
    MLDsa87 = -50,
    /// RSASSA-PSS w/ SHA-256.
    PS256 = -37,
    /// RSASSA-PKCS1v1.5 w/ SHA-256.
    RS256 = -257,
}

/// Supported hash algorithms for COSE Hash Envelope (IANA COSE Algorithms registry).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CoseHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}
