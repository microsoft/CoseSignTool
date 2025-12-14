// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Specifies the cryptographic algorithm to use for key generation.
/// </summary>
public enum KeyAlgorithm
{
    /// <summary>
    /// RSA algorithm. Default key size is 2048 bits.
    /// Recommended for broad compatibility.
    /// </summary>
    RSA,

    /// <summary>
    /// Elliptic Curve Digital Signature Algorithm.
    /// Default key size is 256 bits (P-256 curve).
    /// More efficient than RSA with equivalent security.
    /// </summary>
    ECDSA,

    /// <summary>
    /// Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
    /// Post-quantum cryptographic algorithm standardized by NIST.
    /// Requires .NET 10 or later.
    /// Parameter sets: 44, 65, 87 (use keySize parameter).
    /// </summary>
    MLDSA
}