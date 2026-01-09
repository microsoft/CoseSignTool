// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Certificates.ChainBuilders;

/// <summary>
/// Certificate source that retrieves certificates from Linux/OpenSSL certificate stores.
/// Supports PEM format files and common Linux certificate store locations.
/// This class is intended for use on Linux, FreeBSD, and macOS systems.
/// </summary>
/// <remarks>
/// On non-Unix systems, some file system operations may not work as expected.
/// </remarks>
public class LinuxCertificateStoreCertificateSource : CertificateSourceBase
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string LogInitByThumbprint = "LinuxCertificateStoreCertificateSource initialized by thumbprint. Thumbprint: {Thumbprint}, Subject: {Subject}";
        public static readonly string LogInitBySubjectName = "LinuxCertificateStoreCertificateSource initialized by subject name. SubjectName: {SubjectName}, ValidOnly: {ValidOnly}, Subject: {Subject}";
        public static readonly string LogInitByPredicate = "LinuxCertificateStoreCertificateSource initialized by predicate. Subject: {Subject}";
        public static readonly string LogSearchingStorePaths = "Searching for certificate in {StorePathCount} store paths";
        public static readonly string LogSearchingPath = "Searching for certificate in path: {Path}";
        public static readonly string LogPathNotDirectory = "Skipping non-directory path: {Path}";
        public static readonly string LogFoundCertificate = "Found matching certificate. Thumbprint: {Thumbprint}, Subject: {Subject}";
        public static readonly string LogSearchingThumbprint = "Searching for certificate by thumbprint {Thumbprint} in {StorePathCount} store paths";
        public static readonly string LogFoundByThumbprint = "Found certificate by thumbprint. Thumbprint: {Thumbprint}, Subject: {Subject}";
        public static readonly string LogCertificateNotFound = "Certificate with thumbprint {Thumbprint} not found";
        public static readonly string LogSearchingSubjectName = "Searching for certificate by subject name {SubjectName} (validOnly: {ValidOnly}) in {StorePathCount} store paths";
        public static readonly string LogFoundBySubjectName = "Found certificate by subject name. SubjectName: {SubjectName}, Subject: {Subject}";

        public static readonly string ErrorCertificateBySubjectNameNotFoundInAnyStoreFormat = "Certificate with subject name containing '{0}' not found in any certificate store";
        public static readonly string ErrorCertificateByThumbprintNotFoundInAnyStoreFormat = "Certificate with thumbprint '{0}' not found in any certificate store";
        public static readonly string ErrorNoCertificateMatchingPredicateFoundInAnyStore = "No certificate matching the predicate found in any certificate store";

        public static readonly string LogSearchingCertificateStorePaths = "Searching certificate store paths. Paths: {Paths}";
        public static readonly string StorePathsSeparator = ", ";

        public static readonly string LogCertificateFileNotFound = "Certificate file not found. Path: {Path}";
        public static readonly string ErrorCertificateFileNotFoundFormat = "Certificate file not found: {0}";

        public static readonly string LogPrivateKeyFileNotFound = "Private key file not found. Path: {Path}";
        public static readonly string ErrorPrivateKeyFileNotFoundFormat = "Private key file not found: {0}";

        public static readonly string LogCertificateLoadedWithRsaPrivateKey = "Certificate loaded with RSA private key. Subject: {Subject}";
        public static readonly string LogCertificateLoadedWithEcdsaPrivateKey = "Certificate loaded with ECDSA private key. Subject: {Subject}";

        public static readonly string LogUnableToImportPrivateKey = "Unable to import private key. Path: {Path}";
        public static readonly string ErrorUnableToImportPrivateKeyFormat = "Unable to import private key from {0}. The key format is not supported or the key is invalid.";

        public static readonly string LogNoCertificateMatchingPredicateFound = "No certificate matching predicate found";

        public static readonly string LogLoadingCertificateFromFiles = "Loading certificate from files. CertificateFile: {CertFile}, PrivateKeyFile: {KeyFile}";

        public static readonly string ReplaceSpace = " ";
        public static readonly string ReplaceColon = ":";

        public static readonly string LogSearchingByThumbprintNormalized = "Searching for certificate by thumbprint. NormalizedThumbprint: {Thumbprint}";
        public static readonly string LogSearchingDirectory = "Searching directory. Path: {Path}";
        public static readonly string LogFoundByThumbprintFromFile = "Found certificate by thumbprint. File: {File}, Subject: {Subject}";
        public static readonly string LogSearchingBySubjectNameSimple = "Searching for certificate by subject name. SubjectName: {SubjectName}, ValidOnly: {ValidOnly}";
        public static readonly string LogSubjectNameCandidatesFound = "Found {Count} candidate certificates matching subject name";
        public static readonly string LogSubjectNameCandidatesAfterValidityFilter = "{Count} certificates remaining after validity filter";
        public static readonly string LogSelectedCertificate = "Selected certificate. Subject: {Subject}, HasPrivateKey: {HasPrivateKey}";
        public static readonly string LogSubjectNameNotFound = "Certificate with subject name containing '{SubjectName}' not found";
        public static readonly string LogSearchingByPredicate = "Searching for certificate by predicate";
        public static readonly string LogFoundByPredicate = "Found certificate matching predicate. File: {File}, Subject: {Subject}";

        public static readonly string FileSearchPatternFormat = "*{0}";
        public static readonly string PemExtension = ".pem";
        public static readonly string CrtExtension = ".crt";
        public static readonly string CerExtension = ".cer";

        public static readonly string[] CertificateFileExtensions = new[] { PemExtension, CrtExtension, CerExtension };

        public static readonly string StorePathEtcSslCerts = "/etc/ssl/certs";
        public static readonly string StorePathEtcPkiTlsCerts = "/etc/pki/tls/certs";
        public static readonly string StorePathEtcSsl = "/etc/ssl";
        public static readonly string StorePathEtcPkiCaTrustExtractedPem = "/etc/pki/ca-trust/extracted/pem";
        public static readonly string StorePathUsrLocalShareCaCertificates = "/usr/local/share/ca-certificates";
        public static readonly string StorePathVarLibCaCertificates = "/var/lib/ca-certificates";

        public static readonly string[] DefaultCertificateStorePaths = new[]
        {
            StorePathEtcSslCerts,
            StorePathEtcPkiTlsCerts,
            StorePathEtcSsl,
            StorePathEtcPkiCaTrustExtractedPem,
            StorePathUsrLocalShareCaCertificates,
            StorePathVarLibCaCertificates
        };
    }

    private readonly X509Certificate2 Certificate;

    /// <summary>
    /// Common OpenSSL and Linux certificate store paths.
    /// </summary>
    public static readonly string[] DefaultCertificateStorePaths = ClassStrings.DefaultCertificateStorePaths;

    /// <summary>
    /// Initializes a new instance by finding a certificate by thumbprint in default store paths.
    /// </summary>
    /// <param name="thumbprint">Certificate thumbprint (hex string)</param>
    /// <param name="storePaths">Optional custom certificate store paths. If null, uses DefaultCertificateStorePaths.</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder for automatic chain building.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="thumbprint"/> is null or whitespace.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the certificate cannot be found.</exception>
    public LinuxCertificateStoreCertificateSource(
        string thumbprint,
        IEnumerable<string>? storePaths = null,
        ICertificateChainBuilder? chainBuilder = null,
        ILogger<LinuxCertificateStoreCertificateSource>? logger = null)
        : this(
            (paths, log) => FindCertificateByThumbprint(paths, thumbprint, log)
                ?? throw new InvalidOperationException(string.Format(ClassStrings.ErrorCertificateByThumbprintNotFoundInAnyStoreFormat, thumbprint)),
            storePaths,
            chainBuilder,
            logger)
    {
        Logger.LogTrace(
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogInitByThumbprint,
            thumbprint,
            Certificate.Subject);
    }

    /// <summary>
    /// Initializes a new instance by finding a certificate by subject name in default store paths.
    /// </summary>
    /// <param name="subjectName">Certificate subject name (or part of it)</param>
    /// <param name="storePaths">Optional custom certificate store paths. If null, uses DefaultCertificateStorePaths.</param>
    /// <param name="validOnly">If true, only returns valid certificates</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder for automatic chain building.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="subjectName"/> is null or whitespace.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the certificate cannot be found.</exception>
    public LinuxCertificateStoreCertificateSource(
        string subjectName,
        IEnumerable<string>? storePaths,
        bool validOnly,
        ICertificateChainBuilder? chainBuilder = null,
        ILogger<LinuxCertificateStoreCertificateSource>? logger = null)
        : this(
            (paths, log) => FindCertificateBySubjectName(paths, subjectName, validOnly, log)
                ?? throw new InvalidOperationException(string.Format(ClassStrings.ErrorCertificateBySubjectNameNotFoundInAnyStoreFormat, subjectName)),
            storePaths,
            chainBuilder,
            logger)
    {
        Logger.LogTrace(
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogInitBySubjectName,
            subjectName,
            validOnly,
            Certificate.Subject);
    }

    /// <summary>
    /// Initializes a new instance with a custom certificate finder predicate.
    /// </summary>
    /// <param name="predicate">Predicate to find the desired certificate</param>
    /// <param name="storePaths">Optional custom certificate store paths. If null, uses DefaultCertificateStorePaths.</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder for automatic chain building.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="predicate"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the certificate cannot be found.</exception>
    public LinuxCertificateStoreCertificateSource(
        Func<X509Certificate2, bool> predicate,
        IEnumerable<string>? storePaths = null,
        ICertificateChainBuilder? chainBuilder = null,
        ILogger<LinuxCertificateStoreCertificateSource>? logger = null)
        : this(
            (paths, log) => FindCertificateByPredicate(paths, predicate, log)
                ?? throw new InvalidOperationException(ClassStrings.ErrorNoCertificateMatchingPredicateFoundInAnyStore),
            storePaths,
            chainBuilder,
            logger)
    {
        Logger.LogTrace(
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogInitByPredicate,
            Certificate.Subject);
    }

    /// <summary>
    /// Initializes a new instance from separate certificate and private key files (common Linux pattern).
    /// </summary>
    /// <param name="certificateFilePath">Path to the certificate file (.pem, .crt)</param>
    /// <param name="privateKeyFilePath">Path to the private key file (.key, .pem)</param>
    /// <param name="keyStorageFlags">Flags controlling how the private key is stored</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder for automatic chain building.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="certificateFilePath"/> or <paramref name="privateKeyFilePath"/> is null or whitespace.</exception>
    /// <exception cref="FileNotFoundException">Thrown when <paramref name="certificateFilePath"/> or <paramref name="privateKeyFilePath"/> does not exist.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the private key cannot be imported.</exception>
    public LinuxCertificateStoreCertificateSource(
        string certificateFilePath,
        string privateKeyFilePath,
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.MachineKeySet,
        ICertificateChainBuilder? chainBuilder = null,
        ILogger<LinuxCertificateStoreCertificateSource>? logger = null)
        : base(chainBuilder ?? new X509ChainBuilder(), logger)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateFilePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyFilePath);

        Logger.LogTrace(
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogLoadingCertificateFromFiles,
            certificateFilePath,
            privateKeyFilePath);

        if (!File.Exists(certificateFilePath))
        {
            Logger.LogTrace(
                LogEvents.CertificateLoadFailedEvent,
                ClassStrings.LogCertificateFileNotFound,
                certificateFilePath);
            throw new FileNotFoundException(string.Format(ClassStrings.ErrorCertificateFileNotFoundFormat, certificateFilePath), certificateFilePath);
        }

        if (!File.Exists(privateKeyFilePath))
        {
            Logger.LogTrace(
                LogEvents.CertificateLoadFailedEvent,
                ClassStrings.LogPrivateKeyFileNotFound,
                privateKeyFilePath);
            throw new FileNotFoundException(string.Format(ClassStrings.ErrorPrivateKeyFileNotFoundFormat, privateKeyFilePath), privateKeyFilePath);
        }

        // Load certificate and private key separately, then combine them
        var cert = X509CertificateLoader.LoadCertificateFromFile(certificateFilePath);
        var keyPem = File.ReadAllText(privateKeyFilePath);

        // Try to parse as RSA key first, then EC if that fails
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(keyPem);
            Certificate = cert.CopyWithPrivateKey(rsa);
            Logger.LogTrace(
                LogEvents.CertificateLoadedEvent,
                ClassStrings.LogCertificateLoadedWithRsaPrivateKey,
                Certificate.Subject);
        }
        catch (CryptographicException)
        {
            try
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(keyPem);
                Certificate = cert.CopyWithPrivateKey(ecdsa);
                Logger.LogTrace(
                    LogEvents.CertificateLoadedEvent,
                    ClassStrings.LogCertificateLoadedWithEcdsaPrivateKey,
                    Certificate.Subject);
            }
            catch (CryptographicException ex)
            {
                cert.Dispose();
                Logger.LogTrace(
                    LogEvents.CertificateLoadFailedEvent,
                    ClassStrings.LogUnableToImportPrivateKey,
                    privateKeyFilePath);
                throw new InvalidOperationException(string.Format(ClassStrings.ErrorUnableToImportPrivateKeyFormat, privateKeyFilePath), ex);
            }
        }

        // Dispose the certificate without private key since we created a new one with the key
        cert.Dispose();
    }

    /// <summary>
    /// Private constructor that performs the actual certificate retrieval from store paths.
    /// </summary>
    private LinuxCertificateStoreCertificateSource(
        Func<IEnumerable<string>, ILogger?, X509Certificate2> certificateFinder,
        IEnumerable<string>? storePaths,
        ICertificateChainBuilder? chainBuilder,
        ILogger<LinuxCertificateStoreCertificateSource>? logger)
        : base(chainBuilder ?? new X509ChainBuilder(), logger)
    {
        var paths = storePaths ?? DefaultCertificateStorePaths.Where(Directory.Exists);
        Logger.LogTrace(
            LogEvents.CertificateStoreAccessEvent,
            ClassStrings.LogSearchingCertificateStorePaths,
            string.Join(ClassStrings.StorePathsSeparator, paths));
        Certificate = certificateFinder(paths, logger);
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

    /// <summary>
    /// Finds a certificate by thumbprint in the specified store paths.
    /// </summary>
    private static X509Certificate2? FindCertificateByThumbprint(IEnumerable<string> storePaths, string thumbprint, ILogger? logger)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint);

        // Normalize thumbprint: remove whitespace and convert to uppercase
        string normalizedThumbprint = thumbprint
            .Replace(ClassStrings.ReplaceSpace, string.Empty)
            .Replace(ClassStrings.ReplaceColon, string.Empty)
            .ToUpperInvariant();

        logger?.LogTrace(
            LogEvents.CertificateStoreAccessEvent,
            ClassStrings.LogSearchingByThumbprintNormalized,
            normalizedThumbprint);

        foreach (var path in storePaths)
        {
            if (!Directory.Exists(path))
            {
                continue;
            }

            logger?.LogTrace(
                LogEvents.CertificateStoreAccessEvent,
                ClassStrings.LogSearchingDirectory,
                path);

            foreach (var certFile in EnumerateCertificateFiles(path))
            {
                try
                {
                    var cert = X509CertificateLoader.LoadCertificateFromFile(certFile);
                    if (cert.Thumbprint.Equals(normalizedThumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        logger?.LogTrace(
                            LogEvents.CertificateLoadedEvent,
                            ClassStrings.LogFoundByThumbprintFromFile,
                            certFile,
                            cert.Subject);
                        return cert;
                    }
                    cert.Dispose();
                }
                catch (CryptographicException)
                {
                    // Skip files that can't be parsed as valid certificates
                }
                catch (IOException)
                {
                    // Skip files that can't be read
                }
            }
        }

        logger?.LogTrace(
            LogEvents.CertificateLoadFailedEvent,
            ClassStrings.LogCertificateNotFound,
            normalizedThumbprint);

        return null;
    }

    /// <summary>
    /// Finds a certificate by subject name in the specified store paths.
    /// </summary>
    private static X509Certificate2? FindCertificateBySubjectName(IEnumerable<string> storePaths, string subjectName, bool validOnly, ILogger? logger)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectName);

        logger?.LogTrace(
            LogEvents.CertificateStoreAccessEvent,
            ClassStrings.LogSearchingBySubjectNameSimple,
            subjectName,
            validOnly);

        var candidates = new List<X509Certificate2>();

        foreach (var path in storePaths)
        {
            if (!Directory.Exists(path))
            {
                continue;
            }

            foreach (var certFile in EnumerateCertificateFiles(path))
            {
                try
                {
                    var cert = X509CertificateLoader.LoadCertificateFromFile(certFile);
                    if (cert.Subject.Contains(subjectName, StringComparison.OrdinalIgnoreCase))
                    {
                        candidates.Add(cert);
                    }
                    else
                    {
                        cert.Dispose();
                    }
                }
                catch (CryptographicException)
                {
                    // Skip files that can't be parsed as valid certificates
                }
                catch (IOException)
                {
                    // Skip files that can't be read
                }
            }
        }

        logger?.LogTrace(
            LogEvents.CertificateStoreAccessEvent,
            ClassStrings.LogSubjectNameCandidatesFound,
            candidates.Count);

        if (validOnly)
        {
            var now = DateTime.Now;
            var validCandidates = candidates.Where(c => c.NotBefore <= now && c.NotAfter >= now).ToList();

            // Dispose invalid candidates
            foreach (var invalid in candidates.Except(validCandidates))
            {
                invalid.Dispose();
            }

            candidates = validCandidates;
            logger?.LogTrace(
                LogEvents.CertificateStoreAccessEvent,
                ClassStrings.LogSubjectNameCandidatesAfterValidityFilter,
                candidates.Count);
        }

        // Prefer certificates with private keys
        var result = candidates.FirstOrDefault(c => c.HasPrivateKey) ?? candidates.FirstOrDefault();

        // Dispose the ones we're not using
        foreach (var cert in candidates.Where(c => c != result))
        {
            cert.Dispose();
        }

        if (result != null)
        {
            logger?.LogTrace(
                LogEvents.CertificateLoadedEvent,
                ClassStrings.LogSelectedCertificate,
                result.Subject,
                result.HasPrivateKey);
        }
        else
        {
            logger?.LogTrace(
                LogEvents.CertificateLoadFailedEvent,
                ClassStrings.LogSubjectNameNotFound,
                subjectName);
        }

        return result;
    }

    /// <summary>
    /// Finds a certificate using a predicate in the specified store paths.
    /// </summary>
    private static X509Certificate2? FindCertificateByPredicate(IEnumerable<string> storePaths, Func<X509Certificate2, bool> predicate, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(predicate);

        logger?.LogTrace(
            LogEvents.CertificateStoreAccessEvent,
            ClassStrings.LogSearchingByPredicate);

        foreach (var path in storePaths)
        {
            if (!Directory.Exists(path))
            {
                continue;
            }

            foreach (var certFile in EnumerateCertificateFiles(path))
            {
                try
                {
                    var cert = X509CertificateLoader.LoadCertificateFromFile(certFile);
                    if (predicate(cert))
                    {
                        logger?.LogTrace(
                            LogEvents.CertificateLoadedEvent,
                            ClassStrings.LogFoundByPredicate,
                            certFile,
                            cert.Subject);
                        return cert;
                    }
                    cert.Dispose();
                }
                catch (CryptographicException)
                {
                    // Skip files that can't be parsed as valid certificates
                }
                catch (IOException)
                {
                    // Skip files that can't be read
                }
            }
        }

        logger?.LogTrace(
            LogEvents.CertificateLoadFailedEvent,
            ClassStrings.LogNoCertificateMatchingPredicateFound);

        return null;
    }

    /// <summary>
    /// Enumerates certificate files in the specified directory.
    /// Supports .pem, .crt, .cer extensions.
    /// </summary>
    private static IEnumerable<string> EnumerateCertificateFiles(string directory)
    {
        var extensions = ClassStrings.CertificateFileExtensions;

        foreach (var ext in extensions)
        {
            foreach (var file in Directory.EnumerateFiles(
                directory,
                string.Format(ClassStrings.FileSearchPatternFormat, ext),
                SearchOption.TopDirectoryOnly))
            {
                yield return file;
            }
        }
    }
}