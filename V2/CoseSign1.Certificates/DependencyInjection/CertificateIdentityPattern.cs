// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust;

/// <summary>
/// Represents an allow-list pattern for certificate identity matching.
/// </summary>
public sealed class CertificateIdentityPattern
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateIdentityPattern"/> class.
    /// </summary>
    /// <param name="subject">The subject string to match.</param>
    /// <param name="issuer">Optional issuer string to match.</param>
    /// <param name="matchKind">The match mode.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="subject"/> is null.</exception>
    public CertificateIdentityPattern(string subject, string? issuer, CertificateIdentityMatchKind matchKind)
    {
        Subject = subject ?? throw new ArgumentNullException(nameof(subject));
        Issuer = issuer;
        MatchKind = matchKind;
    }

    /// <summary>
    /// Gets the subject pattern string.
    /// </summary>
    public string Subject { get; }

    /// <summary>
    /// Gets the issuer pattern string (optional).
    /// </summary>
    public string? Issuer { get; }

    /// <summary>
    /// Gets the match mode.
    /// </summary>
    public CertificateIdentityMatchKind MatchKind { get; }
}
