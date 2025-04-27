// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.AzureTrustedSigning;

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Azure.Developer.TrustedSigning.CryptoProvider;
using CoseSign1.Certificates.Local;
using System.Linq;

/// <summary>
/// Provides an implementation of the <see cref="CertificateCoseSigningKeyProvider"/> class
/// for Azure Trusted Signing. This class integrates with the Azure Trusted Signing service
/// to provide signing certificates, certificate chains, and cryptographic keys.
/// </summary>
public class AzureTrustedSigningCoseSigningKeyProvider : CertificateCoseSigningKeyProvider
{
    private readonly AzSignContext SignContext;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureTrustedSigningCoseSigningKeyProvider"/> class.
    /// </summary>
    /// <param name="signContext">The <see cref="AzSignContext"/> used to interact with Azure Trusted Signing.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="signContext"/> is null.</exception>
    public AzureTrustedSigningCoseSigningKeyProvider(AzSignContext signContext)
    {
        SignContext = signContext ?? throw new ArgumentNullException(nameof(signContext));
    }

    private readonly object CertificateChainLock = new object();
    private IReadOnlyList<X509Certificate2>? CertificateChain;

    /// <summary>
    /// Retrieves the certificate chain from the Azure Trusted Signing service.
    /// </summary>
    /// <param name="sortOrder">The desired sort order of the certificate chain (root-first or leaf-first).</param>
    /// <returns>An enumerable collection of <see cref="X509Certificate2"/> objects representing the certificate chain.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if the certificate chain is not available or is empty.
    /// </exception>
    protected override IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder)
    {
        lock (CertificateChainLock)
        {
            CertificateChain ??= SignContext.GetCertChain()
                ?? throw new InvalidOperationException("Certificate chain is not available. Please check the Azure Trusted Signing configuration.");
        }

        X509Certificate2 firstCert = CertificateChain.FirstOrDefault()
            ?? throw new InvalidOperationException("Certificate chain is empty. Please check the Azure Trusted Signing configuration.");

        // Determine if the certificate chain order needs to be reversed.
        bool needsRevers = sortOrder == (firstCert.Issuer == firstCert.Subject ? X509ChainSortOrder.RootFirst : X509ChainSortOrder.LeafFirst);

        // Return the certificates in the specified order.
        foreach (X509Certificate2 cert in needsRevers ? CertificateChain.Reverse() : CertificateChain)
        {
            yield return cert;
        }
    }

    private X509Certificate2? SigningCertificate;

    /// <summary>
    /// Retrieves the signing certificate from the Azure Trusted Signing service.
    /// </summary>
    /// <returns>The <see cref="X509Certificate2"/> object representing the signing certificate.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if the signing certificate is not available.
    /// </exception>
    protected override X509Certificate2 GetSigningCertificate()
    {
        SigningCertificate ??= SignContext.GetSigningCertificate()
            ?? throw new InvalidOperationException("Signing certificate is not available. Please check the Azure Trusted Signing configuration.");
        return SigningCertificate;
    }

    /// <summary>
    /// Provides an ECDsa key for signing or verification operations.
    /// </summary>
    /// <param name="publicKey">True to return the public key; false to return the private key (default).</param>
    /// <returns>Always throws a <see cref="NotSupportedException"/> as ECDsa is not supported.</returns>
    /// <exception cref="NotSupportedException">Thrown because ECDsa is not supported for Azure Trusted Signing.</exception>
    protected override ECDsa? ProvideECDsaKey(bool publicKey = false)
        => throw new NotSupportedException("ECDsa is not supported for Azure Trusted Signing CryptoProvider.");

    private RSAAzSign? RsaAzSignInstance;

    /// <summary>
    /// Provides an RSA key for signing or verification operations.
    /// </summary>
    /// <param name="publicKey">True to return the public key; false to return the private key (default).</param>
    /// <returns>An <see cref="RSA"/> object representing the RSA key.</returns>
    protected override RSA? ProvideRSAKey(bool publicKey = false)
        => RsaAzSignInstance ??= new RSAAzSign(SignContext);
}
