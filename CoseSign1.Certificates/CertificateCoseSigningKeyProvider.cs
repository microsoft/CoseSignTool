﻿// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates;

/// <summary>
/// Abstract class which contains common logic needed for all certificate based <see cref="ICoseSigningKeyProvider"/> implementations.
/// </summary>
public abstract class CertificateCoseSigningKeyProvider : ICoseSigningKeyProvider
{
    /// <inheritdoc/>
    public HashAlgorithmName HashAlgorithm { get; } = HashAlgorithmName.SHA256;

    /// <inheritdoc/>
    public bool IsRSA => GetRSAKey(true) != null;

    /// <summary>
    /// An X509ChainBuilder instance to build the certificate chain. 
    /// </summary>
    public ICertificateChainBuilder? ChainBuilder { get; }

    /// <summary>
    /// Abstraction to Get the Signing Certificate from the Derived Class Instance
    /// </summary>
    /// <returns>X509Certificate2 instance</returns>
    protected abstract X509Certificate2 GetSigningCertificate();

    /// <summary>
    /// Gets the Certificate Chain from the Derived Class Instance
    /// </summary>
    /// <returns>X509Certificate2 instance</returns>
    protected abstract IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder);

    /// <summary>
    /// Abstraction to Get the ECDsa Key from the Derived Class Instance
    /// </summary>
    /// <param name="publicKey">True if the public key is to be returned, false for the private key (default).</param>
    /// <returns>ECDsa Key</returns>
    protected abstract ECDsa? ProvideECDsaKey(bool publicKey = false);

    /// <summary>
    /// Abstraction to Get the RSA Key from the Derived Class Instance
    /// </summary>
    /// <param name="publicKey">True if the public key is to be returned, false for the private key (default).</param>
    /// <returns>RSA Key</returns>
    protected abstract RSA? ProvideRSAKey(bool publicKey = false);

    /// <summary>
    /// Virtual Method for UnProtectedHeaders so that it could be Overridden By Derived Class Instance
    /// </summary>
    protected virtual CoseHeaderMap? GetUnProtectedHeadersImplementation() => null;

    /// <summary>
    /// To be used for mocking
    /// </summary>
    [ExcludeFromCodeCoverage]
    protected CertificateCoseSigningKeyProvider() { }

    /// <summary>
    /// Default constructor to instantiate hashalgorithm
    /// </summary>
    /// <param name="hashAlgorithm">The <see cref="HashAlgorithmName"/> used for the signing operation.</param>
    public CertificateCoseSigningKeyProvider(HashAlgorithmName? hashAlgorithm = null)
    {
        HashAlgorithm = hashAlgorithm ?? HashAlgorithm;
    }

    /// <summary>
    /// Default constructor to instantiate chain builder and HashAlgorithm
    /// </summary>
    /// <param name="certificateChainBuilder">The <see cref="ICertificateChainBuilder"/> builder used to build the chain for <paramref name="signingCertificate"/>.</param>
    /// <param name="hashAlgorithm">The <see cref="HashAlgorithmName"/> used for the signing operation.</param>
    /// <param name="rootCertificates">Optional root certificates to chain the signing certificate to.</param>
    public CertificateCoseSigningKeyProvider(ICertificateChainBuilder? certificateChainBuilder, HashAlgorithmName? hashAlgorithm = null, List<X509Certificate2>? rootCertificates = null)
    {
        ChainBuilder = certificateChainBuilder ?? new X509ChainBuilder();
        HashAlgorithm = hashAlgorithm ?? HashAlgorithm;
        if (rootCertificates?.Count > 0 is true)
        {
            ChainBuilder.ChainPolicy.ExtraStore.Clear();
            rootCertificates.ForEach(c => ChainBuilder.ChainPolicy.ExtraStore.Add(c));
        }
    }

    /// <inheritdoc/>
    /// <exception cref="CoseSign1CertificateException">Thrown if the signing certificate thumbprint does not match the first element in the certificate chain returned by <see cref="GetCertificateChain(X509ChainSortOrder)"/>.</exception>
    public CoseHeaderMap GetProtectedHeaders()
    {
        CoseHeaderMap protectedHeaders = new();
        CborWriter cborWriter = new();
        X509Certificate2 signingCertificate = GetSigningCertificate();

        // Encode signing cert
        CoseX509Thumprint thumbprint =
        signingCertificate is null
            ? throw new CoseSign1CertificateException("Signing Certificate Is Not Provided")
            : new(signingCertificate);

        byte[] encodedBytes = thumbprint.Serialize(cborWriter);
        CoseHeaderValue value = CoseHeaderValue.FromEncodedValue(encodedBytes);
        protectedHeaders.Add(CertificateCoseHeaderLabels.X5T, value);

        //X509ChainSortOrder is based on x5Chain elements order suggested here <see cref="https://datatracker.ietf.org/doc/rfc9360/"/>.
        IEnumerable<X509Certificate2> chain = GetCertificateChain(X509ChainSortOrder.LeafFirst);

        // ensure the first chain element thumbprint matches the signing certificate otherwise this message will not be processable.
        if (!signingCertificate.Thumbprint.Equals(chain.FirstOrDefault()?.Thumbprint ?? string.Empty))
        {
            throw new CoseSign1CertificateException($"The signing certificate thumprint: \"{signingCertificate.Thumbprint}\" must match the first item in the signing certificate chain list, which is found to be: \"{chain.FirstOrDefault()?.Thumbprint}\".");
        }

        // Encode signing cert chain
        cborWriter.EncodeCertList(chain);
        value = CoseHeaderValue.FromEncodedValue(cborWriter.Encode());
        protectedHeaders.Add(CertificateCoseHeaderLabels.X5Chain, value);

        return protectedHeaders;
    }

    /// <inheritdoc/>
    public CoseHeaderMap? GetUnProtectedHeaders() => GetUnProtectedHeadersImplementation();

    /// <inheritdoc/>
    public RSA? GetRSAKey(bool publicKey = false) => ProvideRSAKey(publicKey);

    /// <inheritdoc/>
    public ECDsa? GetECDsaKey(bool publicKey = false) => ProvideECDsaKey(publicKey);

    /// <summary>
    /// Makes the supplied root and intermediate certificates available for the signing certificate to chain to.
    /// </summary>
    /// <param name="roots">The certificates to include.</param>
    /// <param name="append">True to append to an existing set of non-default roots.</param>
    public void AddRoots(List<X509Certificate2> roots, bool append = false)
    {
        X509Certificate2Collection store = ChainBuilder?.ChainPolicy.ExtraStore ?? throw new ArgumentException(nameof(ChainBuilder));

        if (!append)
        {
            store.Clear();
        }

        roots.ForEach(c => store.Add(c));
    }
}

