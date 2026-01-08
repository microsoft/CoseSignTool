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
    /// <param name="sha256">The SHA-256 fingerprint.</param>
    /// <param name="sha384">The SHA-384 fingerprint.</param>
    /// <param name="sha512">The SHA-512 fingerprint.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="sha256"/> is <see langword="null"/>.</exception>
    public CertificateFingerprints(string sha256, string? sha384 = null, string? sha512 = null)
    {
        Sha256 = sha256 ?? throw new ArgumentNullException(nameof(sha256));
        Sha384 = sha384;
        Sha512 = sha512;
    }

    /// <summary>
    /// Gets a fingerprint by algorithm name.
    /// </summary>
    /// <param name="algorithm">The hash algorithm.</param>
    /// <returns>The fingerprint for the specified algorithm, or <see langword="null"/> if it is not available.</returns>
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
    /// <param name="algorithm">The hash algorithm.</param>
    /// <param name="fingerprint">The fingerprint to compare against.</param>
    /// <returns><see langword="true"/> if the fingerprint matches; otherwise, <see langword="false"/>.</returns>
    public bool Matches(string algorithm, string fingerprint)
    {
        var actual = GetFingerprint(algorithm);
        return actual != null && string.Equals(actual, fingerprint, StringComparison.Ordinal);
    }
}