// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Models;

using System;

/// <summary>
/// Represents certificate fingerprints (base64url-encoded hashes) for different hash algorithms.
/// </summary>
public sealed class CertificateFingerprints
{
    /// <summary>
    /// Gets the SHA-256 fingerprint (base64url-encoded).
    /// </summary>
    public string Sha256 { get; }

    /// <summary>
    /// Gets the SHA-384 fingerprint (base64url-encoded), if available.
    /// </summary>
    public string? Sha384 { get; }

    /// <summary>
    /// Gets the SHA-512 fingerprint (base64url-encoded), if available.
    /// </summary>
    public string? Sha512 { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateFingerprints"/> class.
    /// </summary>
    public CertificateFingerprints(string sha256, string? sha384 = null, string? sha512 = null)
    {
        Sha256 = sha256 ?? throw new ArgumentNullException(nameof(sha256));
        Sha384 = sha384;
        Sha512 = sha512;
    }

    /// <summary>
    /// Gets a fingerprint by algorithm name.
    /// </summary>
    public string? GetFingerprint(string algorithm)
    {
        return algorithm?.ToLowerInvariant() switch
        {
            DidX509Constants.HashAlgorithmSha256 => Sha256,
            DidX509Constants.HashAlgorithmSha384 => Sha384,
            DidX509Constants.HashAlgorithmSha512 => Sha512,
            _ => null
        };
    }

    /// <summary>
    /// Checks if a fingerprint matches for the specified algorithm.
    /// </summary>
    public bool Matches(string algorithm, string fingerprint)
    {
        var actual = GetFingerprint(algorithm);
        return actual != null && string.Equals(actual, fingerprint, StringComparison.Ordinal);
    }
}
