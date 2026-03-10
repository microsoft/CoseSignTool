// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Fluent builder extensions for <see cref="CertificateChainOptions"/>.
/// </summary>
public static class CertificateChainOptionsExtensions
{
    /// <summary>
    /// Sets the root CA subject name.
    /// </summary>
    /// <param name="options">The certificate chain options to configure.</param>
    /// <param name="name">The root CA subject name.</param>
    /// <returns>The same options instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="name"/> is <see langword="null"/>.</exception>
    public static CertificateChainOptions WithRootName(this CertificateChainOptions options, string name)
    {
        options.RootName = name ?? throw new ArgumentNullException(nameof(name));
        return options;
    }

    /// <summary>
    /// Sets the intermediate CA subject name, or null for 2-tier chain.
    /// </summary>
    /// <param name="options">The certificate chain options to configure.</param>
    /// <param name="name">The intermediate CA subject name, or <see langword="null"/> to omit the intermediate certificate.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateChainOptions WithIntermediateName(this CertificateChainOptions options, string? name)
    {
        options.IntermediateName = name;
        return options;
    }

    /// <summary>
    /// Creates a 2-tier chain (root + leaf, no intermediate).
    /// </summary>
    /// <param name="options">The certificate chain options to configure.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateChainOptions WithoutIntermediate(this CertificateChainOptions options)
    {
        options.IntermediateName = null;
        return options;
    }

    /// <summary>
    /// Sets the leaf certificate subject name.
    /// </summary>
    /// <param name="options">The certificate chain options to configure.</param>
    /// <param name="name">The leaf certificate subject name.</param>
    /// <returns>The same options instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="name"/> is <see langword="null"/>.</exception>
    public static CertificateChainOptions WithLeafName(this CertificateChainOptions options, string name)
    {
        options.LeafName = name ?? throw new ArgumentNullException(nameof(name));
        return options;
    }

    /// <summary>
    /// Sets the cryptographic algorithm for all certificates.
    /// </summary>
    /// <param name="options">The certificate chain options to configure.</param>
    /// <param name="algorithm">The key algorithm for all certificates in the chain.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateChainOptions WithKeyAlgorithm(this CertificateChainOptions options, KeyAlgorithm algorithm)
    {
        options.KeyAlgorithm = algorithm;
        return options;
    }

    /// <summary>
    /// Sets the key size for all certificates.
    /// </summary>
    /// <param name="options">The certificate chain options to configure.</param>
    /// <param name="keySize">The key size in bits.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateChainOptions WithKeySize(this CertificateChainOptions options, int keySize)
    {
        options.KeySize = keySize;
        return options;
    }

    /// <summary>
    /// Sets validity durations for all certificates.
    /// </summary>
    /// <param name="options">The certificate chain options to configure.</param>
    /// <param name="rootValidity">The validity period for the root certificate.</param>
    /// <param name="intermediateValidity">The validity period for the intermediate certificate.</param>
    /// <param name="leafValidity">The validity period for the leaf certificate.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateChainOptions WithValidity(
        this CertificateChainOptions options,
        TimeSpan rootValidity,
        TimeSpan intermediateValidity,
        TimeSpan leafValidity)
    {
        options.RootValidity = rootValidity;
        options.IntermediateValidity = intermediateValidity;
        options.LeafValidity = leafValidity;
        return options;
    }

    /// <summary>
    /// Configures chain for PFX export (only leaf has private key).
    /// </summary>
    /// <param name="options">The certificate chain options to configure.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateChainOptions ForPfxExport(this CertificateChainOptions options)
    {
        options.LeafOnlyPrivateKey = true;
        return options;
    }

    /// <summary>
    /// Returns certificates in leaf-first order.
    /// </summary>
    /// <param name="options">The certificate chain options to configure.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateChainOptions LeafFirstOrder(this CertificateChainOptions options)
    {
        options.LeafFirst = true;
        return options;
    }

    /// <summary>
    /// Sets the Enhanced Key Usage OIDs for the leaf certificate.
    /// </summary>
    /// <param name="options">The certificate chain options to configure.</param>
    /// <param name="ekuOids">The EKU OIDs to configure for the leaf certificate.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateChainOptions WithLeafEkus(this CertificateChainOptions options, params string[] ekuOids)
    {
        options.LeafEnhancedKeyUsages = ekuOids.ToList();
        return options;
    }
}