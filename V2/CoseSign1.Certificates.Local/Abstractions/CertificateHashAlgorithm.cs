// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Specifies the hash algorithm to use for certificate signing.
/// </summary>
public enum CertificateHashAlgorithm
{
    /// <summary>
    /// SHA-256 hash algorithm. Recommended for most use cases.
    /// </summary>
    SHA256,

    /// <summary>
    /// SHA-384 hash algorithm. Higher security level.
    /// </summary>
    SHA384,

    /// <summary>
    /// SHA-512 hash algorithm. Highest security level.
    /// </summary>
    SHA512
}