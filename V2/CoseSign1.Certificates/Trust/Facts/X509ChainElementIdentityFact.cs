// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust.Facts;

using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Fact describing an X.509 certificate identity at a specific depth in the signing certificate chain.
/// </summary>
/// <remarks>
/// Depth 0 is the leaf (signing) certificate. Depth increases toward the root.
/// </remarks>
public sealed class X509ChainElementIdentityFact : ISigningKeyFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.SigningKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="X509ChainElementIdentityFact"/> class.
    /// </summary>
    /// <param name="depth">The element depth. 0 is the leaf.</param>
    /// <param name="chainLength">The total chain length.</param>
    /// <param name="certificateThumbprint">Certificate thumbprint (hex string).</param>
    /// <param name="subject">Certificate subject.</param>
    /// <param name="issuer">Certificate issuer.</param>
    /// <param name="serialNumber">Certificate serial number (hex string).</param>
    /// <param name="notBefore">Certificate not-before timestamp.</param>
    /// <param name="notAfter">Certificate not-after timestamp.</param>
    /// <exception cref="ArgumentNullException">Thrown when a required string parameter is null.</exception>
    public X509ChainElementIdentityFact(
        int depth,
        int chainLength,
        string certificateThumbprint,
        string subject,
        string issuer,
        string serialNumber,
        DateTime notBefore,
        DateTime notAfter)
    {
        Depth = depth;
        ChainLength = chainLength;
        CertificateThumbprint = certificateThumbprint ?? throw new ArgumentNullException(nameof(certificateThumbprint));
        Subject = subject ?? throw new ArgumentNullException(nameof(subject));
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        SerialNumber = serialNumber ?? throw new ArgumentNullException(nameof(serialNumber));
        NotBeforeUtc = notBefore.ToUniversalTime();
        NotAfterUtc = notAfter.ToUniversalTime();
    }

    /// <summary>
    /// Gets the chain depth. 0 is leaf.
    /// </summary>
    public int Depth { get; }

    /// <summary>
    /// Gets the total chain length.
    /// </summary>
    public int ChainLength { get; }

    /// <summary>
    /// Gets a value indicating whether this element represents the root (last element).
    /// </summary>
    public bool IsRoot => ChainLength > 0 && Depth == ChainLength - 1;

    /// <summary>
    /// Gets the certificate thumbprint (hex string).
    /// </summary>
    public string CertificateThumbprint { get; }

    /// <summary>
    /// Gets the certificate subject.
    /// </summary>
    public string Subject { get; }

    /// <summary>
    /// Gets the certificate issuer.
    /// </summary>
    public string Issuer { get; }

    /// <summary>
    /// Gets the certificate serial number (hex string).
    /// </summary>
    public string SerialNumber { get; }

    /// <summary>
    /// Gets the certificate not-before timestamp (UTC).
    /// </summary>
    public DateTime NotBeforeUtc { get; }

    /// <summary>
    /// Gets the certificate not-after timestamp (UTC).
    /// </summary>
    public DateTime NotAfterUtc { get; }
}
