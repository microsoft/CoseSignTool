// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Certificates.ChainBuilders;

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
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ErrorValueCannotBeNullOrWhiteSpace = "Value cannot be null or whitespace.";
        public static readonly string ErrorCertificateByThumbprintNotFoundFormat = "Certificate with thumbprint '{0}' not found in {1}\\{2}";
        public static readonly string ErrorCertificateBySubjectNameNotFoundFormat = "Certificate with subject name containing '{0}' not found in {1}\\{2}";
        public static readonly string ErrorNoCertificateMatchingPredicateFoundFormat = "No certificate matching the predicate found in {0}\\{1}";

        public static readonly string LogInitByThumbprint = "WindowsCertificateStoreCertificateSource initialized by thumbprint. Thumbprint: {Thumbprint}, Store: {StoreLocation}\\{StoreName}, Subject: {Subject}";
        public static readonly string LogInitBySubjectName = "WindowsCertificateStoreCertificateSource initialized by subject name. SubjectName: {SubjectName}, Store: {StoreLocation}\\{StoreName}, ValidOnly: {ValidOnly}, FoundSubject: {Subject}";
        public static readonly string LogSearchingByPredicate = "Searching for certificate by predicate in {StoreLocation}\\{StoreName}";
        public static readonly string LogInitByPredicate = "WindowsCertificateStoreCertificateSource initialized by predicate. Store: {StoreLocation}\\{StoreName}, Subject: {Subject}";
        public static readonly string LogOpeningStore = "Opening certificate store. Store: {StoreLocation}\\{StoreName}";
        public static readonly string LogStoreOpened = "Certificate store opened. CertificateCount: {CertificateCount}";
        public static readonly string LogSearchingByThumbprint = "Searching for certificate by thumbprint. NormalizedThumbprint: {Thumbprint}";
        public static readonly string LogCertificateByThumbprintNotFound = "Certificate with thumbprint {Thumbprint} not found";
        public static readonly string LogSearchingBySubjectName = "Searching for certificate by subject name. SubjectName: {SubjectName}, ValidOnly: {ValidOnly}";
        public static readonly string LogCertificateBySubjectNameNotFound = "Certificate with subject name containing '{SubjectName}' not found";
        public static readonly string LogFoundBySubjectName = "Found certificate by subject name. Subject: {Subject}, HasPrivateKey: {HasPrivateKey}";

        public static readonly string ReplaceSpace = " ";
        public static readonly string ReplaceColon = ":";
    }

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
    /// <exception cref="ArgumentException">Thrown when <paramref name="thumbprint"/> is null or whitespace.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the certificate cannot be found.</exception>
    public WindowsCertificateStoreCertificateSource(
        string thumbprint,
        StoreName storeName = StoreName.My,
        StoreLocation storeLocation = StoreLocation.CurrentUser,
        ICertificateChainBuilder? chainBuilder = null,
        ILogger<WindowsCertificateStoreCertificateSource>? logger = null)
        : this(
            (store, log) => FindCertificateByThumbprint(store, thumbprint, log)
                ?? throw new InvalidOperationException(string.Format(ClassStrings.ErrorCertificateByThumbprintNotFoundFormat, thumbprint, storeLocation, storeName)),
            storeName,
            storeLocation,
            chainBuilder,
            logger)
    {
        Logger.LogTrace(
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogInitByThumbprint,
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
    /// <exception cref="ArgumentException">Thrown when <paramref name="subjectName"/> is null or whitespace.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the certificate cannot be found.</exception>
    public WindowsCertificateStoreCertificateSource(
        string subjectName,
        StoreName storeName,
        StoreLocation storeLocation,
        bool validOnly,
        ICertificateChainBuilder? chainBuilder = null,
        ILogger<WindowsCertificateStoreCertificateSource>? logger = null)
        : this(
            (store, log) => FindCertificateBySubjectName(store, subjectName, validOnly, log)
                ?? throw new InvalidOperationException(string.Format(ClassStrings.ErrorCertificateBySubjectNameNotFoundFormat, subjectName, storeLocation, storeName)),
            storeName,
            storeLocation,
            chainBuilder,
            logger)
    {
        Logger.LogTrace(
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogInitBySubjectName,
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
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="predicate"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the certificate cannot be found.</exception>
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
                    LogEvents.CertificateStoreAccessEvent,
                    ClassStrings.LogSearchingByPredicate,
                    storeLocation,
                    storeName);
                return store.Certificates.Cast<X509Certificate2>().FirstOrDefault(predicate)
                    ?? throw new InvalidOperationException(string.Format(ClassStrings.ErrorNoCertificateMatchingPredicateFoundFormat, storeLocation, storeName));
            },
            storeName,
            storeLocation,
            chainBuilder,
            logger)
    {
        Logger.LogTrace(
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogInitByPredicate,
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
            LogEvents.CertificateStoreAccessEvent,
            ClassStrings.LogOpeningStore,
            storeLocation,
            storeName);

        Store = new X509Store(storeName, storeLocation);
        Store.Open(OpenFlags.ReadOnly);

        Logger.LogTrace(
            LogEvents.CertificateStoreAccessEvent,
            ClassStrings.LogStoreOpened,
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
        Guard.ThrowIfNullOrWhiteSpace(thumbprint);

        // Normalize thumbprint (remove spaces, colons, make uppercase)
        var normalizedThumbprint = thumbprint
            .Replace(ClassStrings.ReplaceSpace, string.Empty)
            .Replace(ClassStrings.ReplaceColon, string.Empty)
            .ToUpperInvariant();

        logger?.LogTrace(
            LogEvents.CertificateStoreAccessEvent,
            ClassStrings.LogSearchingByThumbprint,
            normalizedThumbprint);

        var cert = store.Certificates
            .Cast<X509Certificate2>()
            .FirstOrDefault(c => c.Thumbprint.Equals(normalizedThumbprint, StringComparison.OrdinalIgnoreCase));

        if (cert == null)
        {
            logger?.LogTrace(
                LogEvents.CertificateLoadFailedEvent,
                ClassStrings.LogCertificateByThumbprintNotFound,
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
        Guard.ThrowIfNullOrWhiteSpace(subjectName);

        logger?.LogTrace(
            LogEvents.CertificateStoreAccessEvent,
            ClassStrings.LogSearchingBySubjectName,
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
                LogEvents.CertificateLoadFailedEvent,
                ClassStrings.LogCertificateBySubjectNameNotFound,
                subjectName);
        }
        else
        {
            logger?.LogTrace(
                LogEvents.CertificateLoadedEvent,
                ClassStrings.LogFoundBySubjectName,
                cert.Subject,
                cert.HasPrivateKey);
        }

        return cert;
    }
}