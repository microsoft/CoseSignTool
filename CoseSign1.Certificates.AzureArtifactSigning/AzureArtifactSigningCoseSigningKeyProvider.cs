// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.AzureArtifactSigning;

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Azure.Developer.ArtifactSigning.CryptoProvider;
using Azure.Developer.ArtifactSigning.CryptoProvider.Interfaces;
using CoseSign1.Certificates.Local;
using System.Linq;

/// <summary>
/// Provides an implementation of the <see cref="CertificateCoseSigningKeyProvider"/> class
/// for Azure Artifact Signing. This class integrates with the Azure Artifact Signing service
/// to provide signing certificates, certificate chains, and cryptographic keys.
/// </summary>
public class AzureArtifactSigningCoseSigningKeyProvider : CertificateCoseSigningKeyProvider
{
    private readonly ISignContext SignContext;
    private static readonly AzureArtifactSigningDidX509Generator AzureDidGenerator = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureArtifactSigningCoseSigningKeyProvider"/> class.
    /// </summary>
    /// <param name="signContext">The <see cref="ISignContext"/> used to interact with Azure Artifact Signing.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="signContext"/> is null.</exception>
    public AzureArtifactSigningCoseSigningKeyProvider(ISignContext signContext)
    {
        SignContext = signContext ?? throw new ArgumentNullException(nameof(ISignContext));
    }

    /// <summary>
    /// Gets the issuer value for CWT Claims, using Azure Artifact Signing specific DID:X509:0 format.
    /// If non-standard EKUs are present, returns DID:X509:0 with EKU suffix, otherwise uses parent class behavior.
    /// </summary>
    /// <remarks>
    /// For Azure Artifact Signing certificates with non-standard EKUs, the format is:
    /// did:x509:0:sha256:{rootHash}::eku:{deepestGreatestEku}
    /// Otherwise, delegates to the base class implementation.
    /// </remarks>
    public override string? Issuer
    {
        get
        {
            try
            {
                // Get the certificate chain in leaf-first order
                IEnumerable<X509Certificate2> certChain = GetCertificateChain(X509ChainSortOrder.LeafFirst);

                // Generate DID:X509:0 identifier from the chain using Azure-specific generator
                return AzureDidGenerator.GenerateFromChain(certChain);
            }
            catch (Exception)
            {
                // If chain building or DID generation fails, fall back to base implementation
                return base.Issuer;
            }
        }
    }

    private readonly object CertificateChainLock = new object();
    private IReadOnlyList<X509Certificate2>? CertificateChain;

    /// <summary>
    /// Retrieves the certificate chain from the Azure Artifact Signing service.
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
                ?? throw new InvalidOperationException("Certificate chain is not available. Please check the Azure Artifact Signing configuration.");
        }

        if (CertificateChain.Count == 0)
        {
            throw new InvalidOperationException("Certificate chain is empty. Please check the Azure Artifact Signing configuration.");
        }

        // Build a properly ordered chain: leaf-first, walking from signing cert to root.
        X509Certificate2 signingCert = GetSigningCertificate();
        List<X509Certificate2> ordered = new() { signingCert };
        HashSet<string> used = new() { signingCert.Thumbprint };

        // Walk up the chain: find the issuer of the current cert
        X509Certificate2? current = signingCert;
        while (current != null && current.Issuer != current.Subject)
        {
            X509Certificate2? issuer = CertificateChain
                .FirstOrDefault(c => !used.Contains(c.Thumbprint) && c.Subject == current.Issuer);
            if (issuer is null)
            {
                break;
            }
            ordered.Add(issuer);
            used.Add(issuer.Thumbprint);
            current = issuer;
        }

        // Add any remaining certs not yet included (defensive)
        foreach (X509Certificate2 cert in CertificateChain.Where(c => !used.Contains(c.Thumbprint)))
        {
            ordered.Add(cert);
            used.Add(cert.Thumbprint);
        }

        // ordered is now leaf-first; reverse if root-first was requested
        if (sortOrder == X509ChainSortOrder.RootFirst)
        {
            ordered.Reverse();
        }

        return ordered;
    }

    private X509Certificate2? SigningCertificate;

    /// <summary>
    /// Retrieves the signing certificate from the Azure Artifact Signing service.
    /// </summary>
    /// <returns>The <see cref="X509Certificate2"/> object representing the signing certificate.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if the signing certificate is not available.
    /// </exception>
    protected override X509Certificate2 GetSigningCertificate()
    {
        SigningCertificate ??= SignContext.GetSigningCertificate()
            ?? throw new InvalidOperationException("Signing certificate is not available. Please check the Azure Artifact Signing configuration.");
        return SigningCertificate;
    }

    /// <summary>
    /// Provides an ECDsa key for signing or verification operations.
    /// </summary>
    /// <param name="publicKey">True to return the public key; false to return the private key (default).</param>
    /// <returns>Always throws a <see cref="NotSupportedException"/> as ECDsa is not supported.</returns>
    /// <exception cref="NotSupportedException">Thrown because ECDsa is not supported for Azure Artifact Signing.</exception>
    protected override ECDsa? ProvideECDsaKey(bool publicKey = false)
        => throw new NotSupportedException("ECDsa is not supported for Azure Artifact Signing CryptoProvider.");

    private RSAAzSign? RsaAzSignInstance;

    /// <summary>
    /// Provides an RSA key for signing or verification operations.
    /// </summary>
    /// <param name="publicKey">True to return the public key; false to return the private key (default).</param>
    /// <returns>An <see cref="RSA"/> object representing the RSA key.</returns>
    protected override RSA? ProvideRSAKey(bool publicKey = false)
        => RsaAzSignInstance ??= new RSAAzSign(SignContext);
}
