// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Logging;
using Microsoft.Extensions.Logging;

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Certificate source that loads from a PFX/PKCS#12 file.
/// Supports loading with password protection and extracting the full certificate chain.
/// </summary>
public class PfxCertificateSource : CertificateSourceBase
{
    private readonly X509Certificate2 Certificate;

    /// <summary>
    /// Initializes a new instance of PfxCertificateSource from a file path.
    /// </summary>
    /// <param name="pfxFilePath">Path to the PFX file</param>
    /// <param name="password">Password for the PFX file (null for unprotected files)</param>
    /// <param name="keyStorageFlags">Flags controlling how the private key is stored</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, creates ExplicitCertificateChainBuilder with all certificates from the PFX.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public PfxCertificateSource(
        string pfxFilePath,
        string? password = null,
#if NET5_0_OR_GREATER
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.EphemeralKeySet,
#else
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.MachineKeySet,
#endif
        ICertificateChainBuilder? chainBuilder = null,
        ILogger<PfxCertificateSource>? logger = null)
        : this(LoadFromFile(pfxFilePath, password, keyStorageFlags, logger), chainBuilder, logger)
    {
        Logger.LogTrace(
            new EventId(LogEvents.CertificateLoaded, nameof(LogEvents.CertificateLoaded)),
            "PfxCertificateSource initialized from file. FilePath: {FilePath}, Subject: {Subject}, Thumbprint: {Thumbprint}, HasPrivateKey: {HasPrivateKey}",
            pfxFilePath,
            Certificate.Subject,
            Certificate.Thumbprint,
            Certificate.HasPrivateKey);
    }

    /// <summary>
    /// Initializes a new instance of PfxCertificateSource from byte array.
    /// </summary>
    /// <param name="pfxData">PFX file data</param>
    /// <param name="password">Password for the PFX file (null for unprotected data)</param>
    /// <param name="keyStorageFlags">Flags controlling how the private key is stored</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, creates ExplicitCertificateChainBuilder with all certificates from the PFX.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public PfxCertificateSource(
        byte[] pfxData,
        string? password = null,
#if NET5_0_OR_GREATER
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.EphemeralKeySet,
#else
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.MachineKeySet,
#endif
        ICertificateChainBuilder? chainBuilder = null,
        ILogger<PfxCertificateSource>? logger = null)
        : this(LoadFromBytes(pfxData, password, keyStorageFlags, logger), chainBuilder, logger)
    {
        Logger.LogTrace(
            new EventId(LogEvents.CertificateLoaded, nameof(LogEvents.CertificateLoaded)),
            "PfxCertificateSource initialized from bytes. Subject: {Subject}, Thumbprint: {Thumbprint}, HasPrivateKey: {HasPrivateKey}",
            Certificate.Subject,
            Certificate.Thumbprint,
            Certificate.HasPrivateKey);
    }

    /// <summary>
    /// Private constructor that accepts the loaded certificate and chain.
    /// </summary>
    private PfxCertificateSource(
        (X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain) loaded,
        ICertificateChainBuilder? chainBuilder,
        ILogger<PfxCertificateSource>? logger)
        : base(loaded.chain, chainBuilder, logger)
    {
        Certificate = loaded.certificate;
    }

    /// <inheritdoc/>
    public override X509Certificate2 GetSigningCertificate() => Certificate;

    /// <inheritdoc/>
    public override bool HasPrivateKey => Certificate.HasPrivateKey;

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Certificate?.Dispose();
        }
        base.Dispose(disposing);
    }

    private static (X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain) LoadFromFile(
        string pfxFilePath,
        string? password,
        X509KeyStorageFlags keyStorageFlags,
        ILogger? logger)
    {
#if NET5_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(pfxFilePath);
#else
        if (string.IsNullOrWhiteSpace(pfxFilePath)) { throw new ArgumentException("Value cannot be null or whitespace.", nameof(pfxFilePath)); }
#endif

        logger?.LogTrace(
            new EventId(LogEvents.CertificateLoaded, nameof(LogEvents.CertificateLoaded)),
            "Loading PFX from file. FilePath: {FilePath}, KeyStorageFlags: {KeyStorageFlags}",
            pfxFilePath,
            keyStorageFlags);

        if (!File.Exists(pfxFilePath))
        {
            logger?.LogTrace(
                new EventId(LogEvents.CertificateLoadFailed, nameof(LogEvents.CertificateLoadFailed)),
                "PFX file not found. FilePath: {FilePath}",
                pfxFilePath);
            throw new FileNotFoundException($"PFX file not found: {pfxFilePath}", pfxFilePath);
        }

#if NET5_0_OR_GREATER
        var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(pfxFilePath, password, keyStorageFlags);
#else
        var collection = new X509Certificate2Collection();
        collection.Import(pfxFilePath, password, keyStorageFlags);
#endif
        return ExtractCertificateAndChain(collection, $"PFX file: {pfxFilePath}", logger);
    }

    private static (X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain) LoadFromBytes(
        byte[] pfxData,
        string? password,
        X509KeyStorageFlags keyStorageFlags,
        ILogger? logger)
    {
#if NET5_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(pfxData);
#else
        if (pfxData == null) { throw new ArgumentNullException(nameof(pfxData)); }
#endif

        logger?.LogTrace(
            new EventId(LogEvents.CertificateLoaded, nameof(LogEvents.CertificateLoaded)),
            "Loading PFX from bytes. DataLength: {DataLength}, KeyStorageFlags: {KeyStorageFlags}",
            pfxData.Length,
            keyStorageFlags);

#if NET5_0_OR_GREATER
        var collection = X509CertificateLoader.LoadPkcs12Collection(pfxData, password, keyStorageFlags);
#else
        var collection = new X509Certificate2Collection();
        collection.Import(pfxData, password, keyStorageFlags);
#endif
        return ExtractCertificateAndChain(collection, "PFX data", logger);
    }

    private static (X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain) ExtractCertificateAndChain(
        X509Certificate2Collection collection,
        string source,
        ILogger? logger)
    {
        logger?.LogTrace(
            new EventId(LogEvents.CertificateLoaded, nameof(LogEvents.CertificateLoaded)),
            "Extracting certificate and chain from {Source}. CertificateCount: {Count}",
            source,
            collection.Count);

        var certificate = collection
            .Cast<X509Certificate2>()
            .FirstOrDefault(c => c.HasPrivateKey)
            ?? throw new InvalidOperationException($"No certificate with private key found in {source}");

        var chain = collection.Cast<X509Certificate2>().ToList();

        logger?.LogTrace(
            new EventId(LogEvents.CertificateLoaded, nameof(LogEvents.CertificateLoaded)),
            "Extracted signing certificate. Subject: {Subject}, ChainCertificateCount: {ChainCount}",
            certificate.Subject,
            chain.Count);

        return (certificate, chain);
    }
}