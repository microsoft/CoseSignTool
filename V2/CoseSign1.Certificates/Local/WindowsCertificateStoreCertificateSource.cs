// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Logging;
using Microsoft.Extensions.Logging;

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Certificate source that retrieves certificates from Windows certificate stores.
/// Supports finding certificates by thumbprint, subject name, or custom predicate.
/// Uses X509ChainBuilder for automatic chain building from system trust stores.
/// This class is intended for use on Windows systems.
/// </summary>
/// <remarks>
/// On non-Windows systems, the Windows certificate store is not available.
/// </remarks>
public class WindowsCertificateStoreCertificateSource : CertificateSourceBase
{
    private readonly X509Certificate2 Certificate;
    private readonly X509Store? Store;

    /// <summary>
    /// Initializes a new instance by finding a certificate by thumbprint.
    /// </summary>
    /// <param name="thumbprint">Certificate thumbprint (hex string)</param>
    /// <param name="storeName">Certificate store name</param>
    /// <param name="storeLocation">Certificate store location</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder for automatic chain building.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public WindowsCertificateStoreCertificateSource(
        string thumbprint,
        StoreName storeName = StoreName.My,
        StoreLocation storeLocation = StoreLocation.CurrentUser,
        ICertificateChainBuilder? chainBuilder = null,
        ILogger<WindowsCertificateStoreCertificateSource>? logger = null)
        : this(
            (store, log) => FindCertificateByThumbprint(store, thumbprint, log)
                ?? throw new InvalidOperationException($"Certificate with thumbprint '{thumbprint}' not found in {storeLocation}\\{storeName}"),
            storeName,
            storeLocation,
            chainBuilder,
            logger)
    {
        Logger.LogTrace(
            new EventId(LogEvents.CertificateLoaded, nameof(LogEvents.CertificateLoaded)),
            "WindowsCertificateStoreCertificateSource initialized by thumbprint. Thumbprint: {Thumbprint}, Store: {StoreLocation}\\{StoreName}, Subject: {Subject}",
            thumbprint,
            storeLocation,
            storeName,
            Certificate.Subject);
    }

    /// <summary>
    /// Initializes a new instance by finding a certificate by subject name.
    /// </summary>
    /// <param name="subjectName">Certificate subject name (or part of it)</param>
    /// <param name="storeName">Certificate store name</param>
    /// <param name="storeLocation">Certificate store location</param>
    /// <param name="validOnly">If true, only returns valid certificates</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder for automatic chain building.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public WindowsCertificateStoreCertificateSource(
        string subjectName,
        StoreName storeName,
        StoreLocation storeLocation,
        bool validOnly,
        ICertificateChainBuilder? chainBuilder = null,
        ILogger<WindowsCertificateStoreCertificateSource>? logger = null)
        : this(
            (store, log) => FindCertificateBySubjectName(store, subjectName, validOnly, log)
                ?? throw new InvalidOperationException($"Certificate with subject name containing '{subjectName}' not found in {storeLocation}\\{storeName}"),
            storeName,
            storeLocation,
            chainBuilder,
            logger)
    {
        Logger.LogTrace(
            new EventId(LogEvents.CertificateLoaded, nameof(LogEvents.CertificateLoaded)),
            "WindowsCertificateStoreCertificateSource initialized by subject name. SubjectName: {SubjectName}, Store: {StoreLocation}\\{StoreName}, ValidOnly: {ValidOnly}, FoundSubject: {Subject}",
            subjectName,
            storeLocation,
            storeName,
            validOnly,
            Certificate.Subject);
    }

    /// <summary>
    /// Initializes a new instance with a custom certificate finder predicate.
    /// </summary>
    /// <param name="predicate">Predicate to find the desired certificate</param>
    /// <param name="storeName">Certificate store name</param>
    /// <param name="storeLocation">Certificate store location</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder for automatic chain building.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public WindowsCertificateStoreCertificateSource(
        Func<X509Certificate2, bool> predicate,
        StoreName storeName = StoreName.My,
        StoreLocation storeLocation = StoreLocation.CurrentUser,
        ICertificateChainBuilder? chainBuilder = null,
        ILogger<WindowsCertificateStoreCertificateSource>? logger = null)
        : this(
            (store, log) =>
            {
                log?.LogTrace(
                    new EventId(LogEvents.CertificateStoreAccess, nameof(LogEvents.CertificateStoreAccess)),
                    "Searching for certificate by predicate in {StoreLocation}\\{StoreName}",
                    storeLocation,
                    storeName);
                return store.Certificates.Cast<X509Certificate2>().FirstOrDefault(predicate)
                    ?? throw new InvalidOperationException($"No certificate matching the predicate found in {storeLocation}\\{storeName}");
            },
            storeName,
            storeLocation,
            chainBuilder,
            logger)
    {
        Logger.LogTrace(
            new EventId(LogEvents.CertificateLoaded, nameof(LogEvents.CertificateLoaded)),
            "WindowsCertificateStoreCertificateSource initialized by predicate. Store: {StoreLocation}\\{StoreName}, Subject: {Subject}",
            storeLocation,
            storeName,
            Certificate.Subject);
    }

    /// <summary>
    /// Private constructor that performs the actual store access and certificate retrieval.
    /// </summary>
    private WindowsCertificateStoreCertificateSource(
        Func<X509Store, ILogger?, X509Certificate2> certificateFinder,
        StoreName storeName,
        StoreLocation storeLocation,
        ICertificateChainBuilder? chainBuilder,
        ILogger<WindowsCertificateStoreCertificateSource>? logger)
        : base(chainBuilder ?? new X509ChainBuilder(), logger)
    {
        Logger.LogTrace(
            new EventId(LogEvents.CertificateStoreAccess, nameof(LogEvents.CertificateStoreAccess)),
            "Opening certificate store. Store: {StoreLocation}\\{StoreName}",
            storeLocation,
            storeName);

        Store = new X509Store(storeName, storeLocation);
        Store.Open(OpenFlags.ReadOnly);

        Logger.LogTrace(
            new EventId(LogEvents.CertificateStoreAccess, nameof(LogEvents.CertificateStoreAccess)),
            "Certificate store opened. CertificateCount: {CertificateCount}",
            Store.Certificates.Count);

        Certificate = certificateFinder(Store, logger);
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
            Store?.Dispose();
            // Don't dispose Certificate - it's owned by the store
        }
        base.Dispose(disposing);
    }

    private static X509Certificate2? FindCertificateByThumbprint(X509Store store, string thumbprint, ILogger? logger)
    {
#if NET5_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint);
#else
        if (string.IsNullOrWhiteSpace(thumbprint)) { throw new ArgumentException("Value cannot be null or whitespace.", nameof(thumbprint)); }
#endif

        // Normalize thumbprint (remove spaces, colons, make uppercase)
        var normalizedThumbprint = thumbprint
            .Replace(" ", "")
            .Replace(":", "")
            .ToUpperInvariant();

        logger?.LogTrace(
            new EventId(LogEvents.CertificateStoreAccess, nameof(LogEvents.CertificateStoreAccess)),
            "Searching for certificate by thumbprint. NormalizedThumbprint: {Thumbprint}",
            normalizedThumbprint);

        var cert = store.Certificates
            .Cast<X509Certificate2>()
            .FirstOrDefault(c => c.Thumbprint.Equals(normalizedThumbprint, StringComparison.OrdinalIgnoreCase));

        if (cert == null)
        {
            logger?.LogTrace(
                new EventId(LogEvents.CertificateLoadFailed, nameof(LogEvents.CertificateLoadFailed)),
                "Certificate with thumbprint {Thumbprint} not found",
                normalizedThumbprint);
        }

        return cert;
    }

    private static X509Certificate2? FindCertificateBySubjectName(
        X509Store store,
        string subjectName,
        bool validOnly,
        ILogger? logger)
    {
#if NET5_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectName);
#else
        if (string.IsNullOrWhiteSpace(subjectName)) { throw new ArgumentException("Value cannot be null or whitespace.", nameof(subjectName)); }
#endif

        logger?.LogTrace(
            new EventId(LogEvents.CertificateStoreAccess, nameof(LogEvents.CertificateStoreAccess)),
            "Searching for certificate by subject name. SubjectName: {SubjectName}, ValidOnly: {ValidOnly}",
            subjectName,
            validOnly);

        var candidates = store.Certificates
            .Cast<X509Certificate2>()
            .Where(c => c.Subject.Contains(subjectName, StringComparison.OrdinalIgnoreCase));

        if (validOnly)
        {
            var now = DateTime.Now;
            candidates = candidates.Where(c => c.NotBefore <= now && c.NotAfter >= now);
        }

        // Prefer certificates with private keys
        var cert = candidates.FirstOrDefault(c => c.HasPrivateKey)
            ?? candidates.FirstOrDefault();

        if (cert == null)
        {
            logger?.LogTrace(
                new EventId(LogEvents.CertificateLoadFailed, nameof(LogEvents.CertificateLoadFailed)),
                "Certificate with subject name containing '{SubjectName}' not found",
                subjectName);
        }
        else
        {
            logger?.LogTrace(
                new EventId(LogEvents.CertificateLoaded, nameof(LogEvents.CertificateLoaded)),
                "Found certificate by subject name. Subject: {Subject}, HasPrivateKey: {HasPrivateKey}",
                cert.Subject,
                cert.HasPrivateKey);
        }

        return cert;
    }
}