// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust.Facts;

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Fact summarizing certificate identity and trust evaluation for a message's signing key.
/// </summary>
public sealed class CertificateSigningKeyTrustFact : ISigningKeyFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.SigningKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSigningKeyTrustFact"/> class.
    /// </summary>
    /// <param name="thumbprint">Certificate thumbprint.</param>
    /// <param name="subject">Certificate subject.</param>
    /// <param name="issuer">Certificate issuer.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="thumbprint"/>, <paramref name="subject"/>, or <paramref name="issuer"/> is null.</exception>
    /// <param name="chainBuilt">True if a chain was built; otherwise, false.</param>
    /// <param name="chainTrusted">True if chain validation succeeded; otherwise, false.</param>
    /// <param name="chainStatusFlags">Combined chain status flags.</param>
    /// <param name="chainStatusSummary">Optional summary of chain status flags.</param>
    public CertificateSigningKeyTrustFact(
        string thumbprint,
        string subject,
        string issuer,
        bool chainBuilt,
        bool chainTrusted,
        X509ChainStatusFlags chainStatusFlags,
        string? chainStatusSummary)
    {
        Thumbprint = thumbprint ?? throw new ArgumentNullException(nameof(thumbprint));
        Subject = subject ?? throw new ArgumentNullException(nameof(subject));
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        ChainBuilt = chainBuilt;
        ChainTrusted = chainTrusted;
        ChainStatusFlags = chainStatusFlags;
        ChainStatusSummary = chainStatusSummary;
    }

    /// <summary>
    /// Gets the certificate thumbprint.
    /// </summary>
    public string Thumbprint { get; }

    /// <summary>
    /// Gets the certificate subject.
    /// </summary>
    public string Subject { get; }

    /// <summary>
    /// Gets the certificate issuer.
    /// </summary>
    public string Issuer { get; }

    /// <summary>
    /// Gets a value indicating whether a chain was built.
    /// </summary>
    public bool ChainBuilt { get; }

    /// <summary>
    /// Gets a value indicating whether chain validation succeeded.
    /// </summary>
    public bool ChainTrusted { get; }

    /// <summary>
    /// Gets combined chain status flags.
    /// </summary>
    public X509ChainStatusFlags ChainStatusFlags { get; }

    /// <summary>
    /// Gets a human-readable status summary (optional).
    /// </summary>
    public string? ChainStatusSummary { get; }
}
