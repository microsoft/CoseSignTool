// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust;

/// <summary>
/// Builder for configuring certificate identity pinning strategies.
/// </summary>
public sealed class CertificateIdentityPinningBuilder
{
    private readonly CertificateTrustBuilder.CertificateTrustOptions _options;

    internal CertificateIdentityPinningBuilder(CertificateTrustBuilder.CertificateTrustOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Adds an allowed signing certificate thumbprint (hex string).
    /// </summary>
    /// <param name="thumbprint">The thumbprint to allow.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="thumbprint"/> is null.</exception>
    public CertificateIdentityPinningBuilder AllowThumbprint(string thumbprint)
    {
        if (thumbprint == null)
        {
            throw new ArgumentNullException(nameof(thumbprint));
        }

        _options.AllowedThumbprints.Add(thumbprint);
        return this;
    }

    /// <summary>
    /// Adds an allowed subject/issuer pattern.
    /// </summary>
    /// <param name="subject">The subject string to match.</param>
    /// <param name="issuer">Optional issuer string to match.</param>
    /// <param name="matchKind">The match mode.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="subject"/> is null.</exception>
    public CertificateIdentityPinningBuilder AllowSubjectIssuerPattern(
        string subject,
        string? issuer = null,
        CertificateIdentityMatchKind matchKind = CertificateIdentityMatchKind.Exact)
    {
        if (subject == null)
        {
            throw new ArgumentNullException(nameof(subject));
        }

        _options.AllowedSubjectIssuerPatterns.Add(new CertificateIdentityPattern(subject, issuer, matchKind));
        return this;
    }
}
