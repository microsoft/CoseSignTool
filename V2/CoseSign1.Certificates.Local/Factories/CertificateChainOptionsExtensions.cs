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
    public static CertificateChainOptions WithRootName(this CertificateChainOptions options, string name)
    {
        options.RootName = name ?? throw new ArgumentNullException(nameof(name));
        return options;
    }

    /// <summary>
    /// Sets the intermediate CA subject name, or null for 2-tier chain.
    /// </summary>
    public static CertificateChainOptions WithIntermediateName(this CertificateChainOptions options, string? name)
    {
        options.IntermediateName = name;
        return options;
    }

    /// <summary>
    /// Creates a 2-tier chain (root + leaf, no intermediate).
    /// </summary>
    public static CertificateChainOptions WithoutIntermediate(this CertificateChainOptions options)
    {
        options.IntermediateName = null;
        return options;
    }

    /// <summary>
    /// Sets the leaf certificate subject name.
    /// </summary>
    public static CertificateChainOptions WithLeafName(this CertificateChainOptions options, string name)
    {
        options.LeafName = name ?? throw new ArgumentNullException(nameof(name));
        return options;
    }

    /// <summary>
    /// Sets the cryptographic algorithm for all certificates.
    /// </summary>
    public static CertificateChainOptions WithKeyAlgorithm(this CertificateChainOptions options, KeyAlgorithm algorithm)
    {
        options.KeyAlgorithm = algorithm;
        return options;
    }

    /// <summary>
    /// Sets the key size for all certificates.
    /// </summary>
    public static CertificateChainOptions WithKeySize(this CertificateChainOptions options, int keySize)
    {
        options.KeySize = keySize;
        return options;
    }

    /// <summary>
    /// Sets validity durations for all certificates.
    /// </summary>
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
    public static CertificateChainOptions ForPfxExport(this CertificateChainOptions options)
    {
        options.LeafOnlyPrivateKey = true;
        return options;
    }

    /// <summary>
    /// Returns certificates in leaf-first order.
    /// </summary>
    public static CertificateChainOptions LeafFirstOrder(this CertificateChainOptions options)
    {
        options.LeafFirst = true;
        return options;
    }

    /// <summary>
    /// Sets the Enhanced Key Usage OIDs for the leaf certificate.
    /// </summary>
    public static CertificateChainOptions WithLeafEkus(this CertificateChainOptions options, params string[] ekuOids)
    {
        options.LeafEnhancedKeyUsages = ekuOids.ToList();
        return options;
    }
}