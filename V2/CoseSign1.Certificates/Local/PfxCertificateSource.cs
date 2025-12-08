// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Certificate source that loads from a PFX/PKCS#12 file.
/// Supports loading with password protection and extracting the full certificate chain.
/// </summary>
public class PfxCertificateSource : CertificateSourceBase
{
    private readonly X509Certificate2 _certificate;

    /// <summary>
    /// Initializes a new instance of PfxCertificateSource from a file path.
    /// </summary>
    /// <param name="pfxFilePath">Path to the PFX file</param>
    /// <param name="password">Password for the PFX file (null for unprotected files)</param>
    /// <param name="keyStorageFlags">Flags controlling how the private key is stored</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, creates ExplicitCertificateChainBuilder with all certificates from the PFX.</param>
    public PfxCertificateSource(
        string pfxFilePath,
        string? password = null,
#if NET5_0_OR_GREATER
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.EphemeralKeySet,
#else
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.MachineKeySet,
#endif
        ICertificateChainBuilder? chainBuilder = null)
        : this(LoadFromFile(pfxFilePath, password, keyStorageFlags), chainBuilder)
    {
    }

    /// <summary>
    /// Initializes a new instance of PfxCertificateSource from byte array.
    /// </summary>
    /// <param name="pfxData">PFX file data</param>
    /// <param name="password">Password for the PFX file (null for unprotected data)</param>
    /// <param name="keyStorageFlags">Flags controlling how the private key is stored</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, creates ExplicitCertificateChainBuilder with all certificates from the PFX.</param>
    public PfxCertificateSource(
        byte[] pfxData,
        string? password = null,
#if NET5_0_OR_GREATER
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.EphemeralKeySet,
#else
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.MachineKeySet,
#endif
        ICertificateChainBuilder? chainBuilder = null)
        : this(LoadFromBytes(pfxData, password, keyStorageFlags), chainBuilder)
    {
    }

    /// <summary>
    /// Private constructor that accepts the loaded certificate and chain.
    /// </summary>
    private PfxCertificateSource((X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain) loaded, ICertificateChainBuilder? chainBuilder)
        : base(loaded.chain, chainBuilder)
    {
        _certificate = loaded.certificate;
    }

    /// <inheritdoc/>
    public override X509Certificate2 GetSigningCertificate() => _certificate;

    /// <inheritdoc/>
    public override bool HasPrivateKey => _certificate.HasPrivateKey;

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _certificate?.Dispose();
        }
        base.Dispose(disposing);
    }

    private static (X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain) LoadFromFile(
        string pfxFilePath,
        string? password,
        X509KeyStorageFlags keyStorageFlags)
    {
#if NET5_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(pfxFilePath);
#else
        if (string.IsNullOrWhiteSpace(pfxFilePath)) { throw new ArgumentException("Value cannot be null or whitespace.", nameof(pfxFilePath)); }
#endif

        if (!File.Exists(pfxFilePath))
        {
            throw new FileNotFoundException($"PFX file not found: {pfxFilePath}", pfxFilePath);
        }

#if NET5_0_OR_GREATER
        var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(pfxFilePath, password, keyStorageFlags);
#else
        var collection = new X509Certificate2Collection();
        collection.Import(pfxFilePath, password, keyStorageFlags);
#endif
        return ExtractCertificateAndChain(collection, $"PFX file: {pfxFilePath}");
    }

    private static (X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain) LoadFromBytes(
        byte[] pfxData,
        string? password,
        X509KeyStorageFlags keyStorageFlags)
    {
#if NET5_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(pfxData);
#else
        if (pfxData == null) { throw new ArgumentNullException(nameof(pfxData)); }
#endif

#if NET5_0_OR_GREATER
        var collection = X509CertificateLoader.LoadPkcs12Collection(pfxData, password, keyStorageFlags);
#else
        var collection = new X509Certificate2Collection();
        collection.Import(pfxData, password, keyStorageFlags);
#endif
        return ExtractCertificateAndChain(collection, "PFX data");
    }

    private static (X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain) ExtractCertificateAndChain(
        X509Certificate2Collection collection,
        string source)
    {
        var certificate = collection
            .Cast<X509Certificate2>()
            .FirstOrDefault(c => c.HasPrivateKey)
            ?? throw new InvalidOperationException($"No certificate with private key found in {source}");

        var chain = collection.Cast<X509Certificate2>().ToList();
        return (certificate, chain);
    }
}
