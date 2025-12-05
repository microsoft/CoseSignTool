// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Signing implementation which uses <see cref="X509Certificate2"/> objects with direct private key access for signing operations.
/// </summary>
public class X509Certificate2CoseSigningKeyProvider : CertificateCoseSigningKeyProvider
{
    private readonly X509Certificate2 SigningCertificate;

    /// <summary>
    /// Creates a new <see cref="X509Certificate2CoseSigningKeyProvider"/> with a given <see cref="ICertificateChainBuilder"/> and
    /// <see cref="X509Certificate2"/> certificate.
    /// </summary>
    /// <param name="certificateChainBuilder">The <see cref="ICertificateChainBuilder"/> builder used to build the chain for
    /// <paramref name="signingCertificate"/>.</param>
    /// <param name="signingCertificate">The <see cref="X509Certificate2"/> certificate used to perform signing operations with.</param>
    /// <param name="rootCertificates">Optional root certificates to chain the signing certificate to.</param>
    /// <param name="enableScittCompliance">Optional. If true (default), automatically adds SCITT-compliant CWT claims (issuer and subject) to the signature.</param>
    public X509Certificate2CoseSigningKeyProvider(
        ICertificateChainBuilder? certificateChainBuilder,
        X509Certificate2 signingCertificate,
        List<X509Certificate2>? rootCertificates = null,
        bool enableScittCompliance = true)
        : base (
              certificateChainBuilder ?? new X509ChainBuilder() { ChainPolicy = CreateChainPolicyForSigning(rootCertificates) },
              hashAlgorithm: null,
              rootCertificates)
    {
        SigningCertificate = signingCertificate ?? throw new ArgumentNullException(nameof(signingCertificate));
        EnableScittCompliance = enableScittCompliance;
    }

    /// <summary>
    /// Constructor to initialize the SigningCertificate.
    /// </summary>
    /// <param name="signingCertificate">Signing Cert of type X509Certificate2.</param>
    /// <param name="hashAlgorithm">Hash Algorithm From Base Clas.s</param>
    /// <param name="rootCertificates">Optional root certificates to chain the signing certificate to.</param>
    /// <param name="enableScittCompliance">Optional. If true (default), automatically adds SCITT-compliant CWT claims (issuer and subject) to the signature.</param>
    /// <exception cref="ArgumentNullException">Throws Exception if SigningCertificate is null.</exception>
    public X509Certificate2CoseSigningKeyProvider(X509Certificate2 signingCertificate,
        HashAlgorithmName? hashAlgorithm = null,
        List<X509Certificate2>? rootCertificates = null,
        bool enableScittCompliance = true)
        : base(
              new X509ChainBuilder() { ChainPolicy = CreateChainPolicyForSigning(rootCertificates) },
              hashAlgorithm,
              rootCertificates)
    {
        SigningCertificate = signingCertificate ?? throw new ArgumentNullException(nameof(signingCertificate));
        EnableScittCompliance = enableScittCompliance;
    }

    protected static X509ChainPolicy CreateChainPolicyForSigning(List<X509Certificate2>? roots = null)
    {
        // Make the most permissive policy possible because we don't want actual validation here.
        X509ChainPolicy policy = new()
        {
            VerificationFlags = X509VerificationFlags.AllFlags,
            RevocationMode = X509RevocationMode.NoCheck
        };

        // Add roots if any.
        roots?.ForEach(cert => policy.ExtraStore.Add(cert));

        return policy;
    }

    /// <inheritdoc/>
    protected override X509Certificate2 GetSigningCertificate() => SigningCertificate;

    /// <inheritdoc/>
    protected override IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder)
    {
        if (SigningCertificate.Subject.Equals(SigningCertificate.Issuer))
        {
            // special self signed case where there is no chain to build in order to determine the certificate chain.
            return new List<X509Certificate2> { SigningCertificate };
        }

        if (ChainBuilder is null)
        {
            // This shouldn't happen except in tests or new extensions.
            throw new ArgumentNullException(nameof(ChainBuilder), "Could not get certificate chain because no ChainBuilder was defined.");
        }
        else
        {
            if (ChainBuilder.Build(SigningCertificate))
            {
                // Build was successful. Return the sorted chain.
                X509Certificate2Collection certificateChain = new(ChainBuilder.ChainElements?.ToArray() ?? []);
                return EnsureSortedProperty(certificateChain, sortOrder);
            }
            else
            {
                // Build failed, so throw.
                throw new CoseSign1CertificateException($"{ChainBuilder.GetType().FullName}::Build " +
                    $"is not successful for the provided SigningCertificate: " +
                    $"{SigningCertificate.Subject} [{SigningCertificate.Thumbprint}]\r\n" +
                    $"{string.Join("\r\n", ChainBuilder.ChainStatus.Select(s => s.StatusInformation))}");
            }
        }
    }

    /// <inheritdoc/>
    protected override ECDsa? ProvideECDsaKey(bool publicKey = false) => publicKey
        ? SigningCertificate.GetECDsaPublicKey()
        : SigningCertificate.GetECDsaPrivateKey();

    /// <inheritdoc/>
    protected override RSA? ProvideRSAKey(bool publicKey = false) => publicKey
        ? SigningCertificate.GetRSAPublicKey()
        : SigningCertificate.GetRSAPrivateKey();

    /// <summary>
    /// Ensures the <see cref="X509Certificate2Collection"/> is returned in proper <see cref="X509ChainSortOrder"/> sort order.
    /// </summary>
    /// <param name="inputCollection">The input collection to evaluate.</param>
    /// <param name="sortOrder">The order to evaluate against.</param>
    /// <returns>X509Certificate2Collection</returns>
    private static IEnumerable<X509Certificate2> EnsureSortedProperty(X509Certificate2Collection inputCollection, X509ChainSortOrder sortOrder)
    {
        if (inputCollection.Count == 0)
        {
            yield break;
        }

        X509Certificate2 cert = inputCollection[0];
        if (cert.Issuer.Equals(cert.Subject, StringComparison.InvariantCulture))
        {
            // self-signed, so the first element is the root.
            if (sortOrder != X509ChainSortOrder.RootFirst)
            {
                // need to reverse the order
                for (int i = inputCollection.Count - 1; i >= 0; i--)
                {
                    yield return inputCollection[i];
                }
                yield break;
            }
        }

        // collection was in correct sort order.
        for (int i = 0; i < inputCollection.Count; ++i)
        {
            yield return inputCollection[i];
        }
    }
}

