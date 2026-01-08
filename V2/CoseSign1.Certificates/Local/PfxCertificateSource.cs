// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security;

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Certificate source that loads from a PFX/PKCS#12 file.
/// Supports loading with password protection and extracting the full certificate chain.
/// </summary>
/// <remarks>
/// <para>
/// <b>Security Best Practice:</b> Use the <see cref="SecureString"/> overloads when possible
/// to avoid password strings lingering in memory. Regular strings are immutable in .NET and
/// cannot be reliably cleared from memory.
/// </para>
/// </remarks>
public class PfxCertificateSource : CertificateSourceBase
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Log message templates
        public static readonly string LogInitializedFromFileSecure = "PfxCertificateSource initialized from file (SecureString). FilePath: {FilePath}, Subject: {Subject}, Thumbprint: {Thumbprint}, HasPrivateKey: {HasPrivateKey}";
        public static readonly string LogInitializedFromFile = "PfxCertificateSource initialized from file. FilePath: {FilePath}, Subject: {Subject}, Thumbprint: {Thumbprint}, HasPrivateKey: {HasPrivateKey}";
        public static readonly string LogInitializedFromBytesSecure = "PfxCertificateSource initialized from bytes (SecureString). Subject: {Subject}, Thumbprint: {Thumbprint}, HasPrivateKey: {HasPrivateKey}";
        public static readonly string LogInitializedFromBytes = "PfxCertificateSource initialized from bytes. Subject: {Subject}, Thumbprint: {Thumbprint}, HasPrivateKey: {HasPrivateKey}";
        public static readonly string LogLoadingFromFileSecure = "Loading PFX from file (SecureString). FilePath: {FilePath}, KeyStorageFlags: {KeyStorageFlags}";
        public static readonly string LogLoadingFromFile = "Loading PFX from file. FilePath: {FilePath}, KeyStorageFlags: {KeyStorageFlags}";
        public static readonly string LogFileNotFound = "PFX file not found. FilePath: {FilePath}";
        public static readonly string LogLoadingFromBytesSecure = "Loading PFX from bytes (SecureString). DataLength: {DataLength}, KeyStorageFlags: {KeyStorageFlags}";
        public static readonly string LogLoadingFromBytes = "Loading PFX from bytes. DataLength: {DataLength}, KeyStorageFlags: {KeyStorageFlags}";
        public static readonly string LogExtractingChain = "Extracting certificate and chain from {Source}. CertificateCount: {Count}";
        public static readonly string LogExtractedCertificate = "Extracted signing certificate. Subject: {Subject}, ChainCertificateCount: {ChainCount}";

        public static readonly string ErrorPfxFileNotFoundFormat = "PFX file not found: {0}";
        public static readonly string ErrorNoCertificateWithPrivateKeyFoundFormat = "No certificate with private key found in {0}";

        public static readonly string ErrorValueCannotBeNullOrWhiteSpace = "Value cannot be null or whitespace.";

        public static readonly string SourcePfxData = "PFX data";
        public static readonly string SourcePfxFileFormat = "PFX file: {0}";
    }

    private readonly X509Certificate2 Certificate;

    /// <summary>
    /// Initializes a new instance of PfxCertificateSource from a file path with a SecureString password.
    /// </summary>
    /// <param name="pfxFilePath">Path to the PFX file</param>
    /// <param name="password">SecureString password for the PFX file (null for unprotected files)</param>
    /// <param name="keyStorageFlags">Flags controlling how the private key is stored</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, creates ExplicitCertificateChainBuilder with all certificates from the PFX.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <remarks>
    /// This overload is recommended for security-sensitive scenarios as it keeps the password
    /// in encrypted memory until needed.
    /// </remarks>
    public PfxCertificateSource(
        string pfxFilePath,
        SecureString? password,
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
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogInitializedFromFileSecure,
            pfxFilePath,
            Certificate.Subject,
            Certificate.Thumbprint,
            Certificate.HasPrivateKey);
    }

    /// <summary>
    /// Initializes a new instance of PfxCertificateSource from a file path.
    /// </summary>
    /// <param name="pfxFilePath">Path to the PFX file</param>
    /// <param name="password">Password for the PFX file (null for unprotected files)</param>
    /// <param name="keyStorageFlags">Flags controlling how the private key is stored</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, creates ExplicitCertificateChainBuilder with all certificates from the PFX.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <remarks>
    /// Consider using the <see cref="SecureString"/> overload for improved security.
    /// </remarks>
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
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogInitializedFromFile,
            pfxFilePath,
            Certificate.Subject,
            Certificate.Thumbprint,
            Certificate.HasPrivateKey);
    }

    /// <summary>
    /// Initializes a new instance of PfxCertificateSource from byte array with a SecureString password.
    /// </summary>
    /// <param name="pfxData">PFX file data</param>
    /// <param name="password">SecureString password for the PFX file (null for unprotected data)</param>
    /// <param name="keyStorageFlags">Flags controlling how the private key is stored</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, creates ExplicitCertificateChainBuilder with all certificates from the PFX.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <remarks>
    /// This overload is recommended for security-sensitive scenarios as it keeps the password
    /// in encrypted memory until needed.
    /// </remarks>
    public PfxCertificateSource(
        byte[] pfxData,
        SecureString? password,
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
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogInitializedFromBytesSecure,
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
    /// <remarks>
    /// Consider using the <see cref="SecureString"/> overload for improved security.
    /// </remarks>
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
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogInitializedFromBytes,
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
        SecureString? password,
        X509KeyStorageFlags keyStorageFlags,
        ILogger? logger)
    {
#if NET5_0_OR_GREATER
        ArgumentException.ThrowIfNullOrWhiteSpace(pfxFilePath);
#else
    if (string.IsNullOrWhiteSpace(pfxFilePath)) { throw new ArgumentException(ClassStrings.ErrorValueCannotBeNullOrWhiteSpace, nameof(pfxFilePath)); }
#endif

        logger?.LogTrace(
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogLoadingFromFileSecure,
            pfxFilePath,
            keyStorageFlags);

        if (!File.Exists(pfxFilePath))
        {
            logger?.LogTrace(
                LogEvents.CertificateLoadFailedEvent,
                ClassStrings.LogFileNotFound,
                pfxFilePath);
            throw new FileNotFoundException(string.Format(ClassStrings.ErrorPfxFileNotFoundFormat, pfxFilePath), pfxFilePath);
        }

        // Convert SecureString to plain string only at the moment of use
        string? plainPassword = ConvertSecureStringToPlain(password);
        try
        {
#if NET5_0_OR_GREATER
            var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(pfxFilePath, plainPassword, keyStorageFlags);
#else
            var collection = new X509Certificate2Collection();
            collection.Import(pfxFilePath, plainPassword, keyStorageFlags);
#endif
            return ExtractCertificateAndChain(collection, string.Format(ClassStrings.SourcePfxFileFormat, pfxFilePath), logger);
        }
        finally
        {
            // Help GC clean up the plain password string
            plainPassword = null;
        }
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
    if (string.IsNullOrWhiteSpace(pfxFilePath)) { throw new ArgumentException(ClassStrings.ErrorValueCannotBeNullOrWhiteSpace, nameof(pfxFilePath)); }
#endif

        logger?.LogTrace(
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogLoadingFromFile,
            pfxFilePath,
            keyStorageFlags);

        if (!File.Exists(pfxFilePath))
        {
            logger?.LogTrace(
                LogEvents.CertificateLoadFailedEvent,
                ClassStrings.LogFileNotFound,
                pfxFilePath);
            throw new FileNotFoundException(string.Format(ClassStrings.ErrorPfxFileNotFoundFormat, pfxFilePath), pfxFilePath);
        }

#if NET5_0_OR_GREATER
        var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(pfxFilePath, password, keyStorageFlags);
#else
        var collection = new X509Certificate2Collection();
        collection.Import(pfxFilePath, password, keyStorageFlags);
#endif
        return ExtractCertificateAndChain(collection, string.Format(ClassStrings.SourcePfxFileFormat, pfxFilePath), logger);
    }

    private static (X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain) LoadFromBytes(
        byte[] pfxData,
        SecureString? password,
        X509KeyStorageFlags keyStorageFlags,
        ILogger? logger)
    {
#if NET5_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(pfxData);
#else
        if (pfxData == null) { throw new ArgumentNullException(nameof(pfxData)); }
#endif

        logger?.LogTrace(
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogLoadingFromBytesSecure,
            pfxData.Length,
            keyStorageFlags);

        // Convert SecureString to plain string only at the moment of use
        string? plainPassword = ConvertSecureStringToPlain(password);
        try
        {
#if NET5_0_OR_GREATER
            var collection = X509CertificateLoader.LoadPkcs12Collection(pfxData, plainPassword, keyStorageFlags);
#else
            var collection = new X509Certificate2Collection();
            collection.Import(pfxData, plainPassword, keyStorageFlags);
#endif
            return ExtractCertificateAndChain(collection, ClassStrings.SourcePfxData, logger);
        }
        finally
        {
            // Help GC clean up the plain password string
            plainPassword = null;
        }
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
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogLoadingFromBytes,
            pfxData.Length,
            keyStorageFlags);

#if NET5_0_OR_GREATER
        var collection = X509CertificateLoader.LoadPkcs12Collection(pfxData, password, keyStorageFlags);
#else
        var collection = new X509Certificate2Collection();
        collection.Import(pfxData, password, keyStorageFlags);
#endif
        return ExtractCertificateAndChain(collection, ClassStrings.SourcePfxData, logger);
    }

    /// <summary>
    /// Converts a SecureString to a plain string for use with APIs that don't support SecureString.
    /// </summary>
    private static string? ConvertSecureStringToPlain(SecureString? secureString)
    {
        if (secureString == null || secureString.Length == 0)
        {
            return null;
        }

        IntPtr ptr = IntPtr.Zero;
        try
        {
            ptr = Marshal.SecureStringToBSTR(secureString);
            return Marshal.PtrToStringBSTR(ptr);
        }
        finally
        {
            if (ptr != IntPtr.Zero)
            {
                Marshal.ZeroFreeBSTR(ptr);
            }
        }
    }

    private static (X509Certificate2 certificate, IReadOnlyList<X509Certificate2> chain) ExtractCertificateAndChain(
        X509Certificate2Collection collection,
        string source,
        ILogger? logger)
    {
        logger?.LogTrace(
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogExtractingChain,
            source,
            collection.Count);

        var certificate = collection
            .Cast<X509Certificate2>()
            .FirstOrDefault(c => c.HasPrivateKey)
            ?? throw new InvalidOperationException(string.Format(ClassStrings.ErrorNoCertificateWithPrivateKeyFoundFormat, source));

        var chain = collection.Cast<X509Certificate2>().ToList();

        logger?.LogTrace(
            LogEvents.CertificateLoadedEvent,
            ClassStrings.LogExtractedCertificate,
            certificate.Subject,
            chain.Count);

        return (certificate, chain);
    }
}