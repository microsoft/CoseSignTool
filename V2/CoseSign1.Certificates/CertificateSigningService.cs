// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Logging;
using CoseSign1.Certificates.Remote;
using CoseSign1.Headers;
using DIDx509;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSign1.Certificates;

/// <summary>
/// Certificate-based signing service that works with any <see cref="ICertificateSigningKey"/>.
/// Provides a unified signing experience for both local and remote certificate scenarios.
/// Thread-safe: All operations are stateless or use proper locking.
/// </summary>
/// <remarks>
/// <para>
/// Use the static factory methods for common scenarios:
/// <list type="bullet">
/// <item><description><see cref="Create(X509Certificate2, ICertificateChainBuilder, ILogger?)"/> - Local certificate with chain builder</description></item>
/// <item><description><see cref="Create(X509Certificate2, IReadOnlyList{X509Certificate2}, ILogger?)"/> - Local certificate with explicit chain</description></item>
/// <item><description><see cref="Create(RemoteCertificateSource, ILogger?)"/> - Remote certificate source</description></item>
/// </list>
/// </para>
/// <para>
/// Example usage:
/// <code>
/// // For local certificates with chain builder
/// using var service = CertificateSigningService.Create(certificate, chainBuilder);
/// 
/// // For local certificates with explicit chain
/// using var service = CertificateSigningService.Create(certificate, certificateChain);
/// 
/// // For remote certificates (Azure Key Vault, etc.)
/// var source = new AzureKeyVaultCertificateSource(factory, certName);
/// await source.InitializeAsync();
/// using var service = CertificateSigningService.Create(source);
/// </code>
/// </para>
/// </remarks>
public class CertificateSigningService : ISigningService<CertificateSigningOptions>
{
    private static readonly CertificateHeaderContributor CertificateContributor = new();
    private bool Disposed;
    private readonly SigningServiceMetadata ServiceMetadataField;
    private readonly bool IsRemoteField;

    /// <summary>
    /// The certificate signing key when provided directly or via factory methods.
    /// </summary>
    private ICertificateSigningKey? SigningKeyField;

    /// <summary>
    /// The logger for this service instance.
    /// </summary>
    protected readonly ILogger Logger;

    #region Factory Methods

    /// <summary>
    /// Creates a signing service for a local certificate with a chain builder.
    /// </summary>
    /// <param name="certificate">Certificate with private key for signing.</param>
    /// <param name="chainBuilder">Chain builder to construct the certificate chain.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <returns>A signing service configured for local certificate signing.</returns>
    /// <exception cref="ArgumentNullException">Thrown when certificate or chainBuilder is null.</exception>
    /// <exception cref="ArgumentException">Thrown when certificate does not have a private key.</exception>
    public static CertificateSigningService Create(
        X509Certificate2 certificate,
        ICertificateChainBuilder chainBuilder,
        ILogger? logger = null)
    {
#if NET5_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(chainBuilder);
#else
        if (certificate == null) { throw new ArgumentNullException(nameof(certificate)); }
        if (chainBuilder == null) { throw new ArgumentNullException(nameof(chainBuilder)); }
#endif

        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException(
                "Certificate must have a private key for local signing.",
                nameof(certificate));
        }

        var service = new CertificateSigningService(isRemote: false, logger: logger);
        var certificateSource = new DirectCertificateSource(certificate, chainBuilder);
        var signingKeyProvider = new DirectSigningKeyProvider(certificate);
        service.SigningKeyField = new CertificateSigningKey(certificateSource, signingKeyProvider, service);

        logger?.LogDebug(
            LogEvents.CertificateLoadedEvent,
            "Creating local signing service for certificate. Subject: {Subject}, Thumbprint: {Thumbprint}",
            certificate.Subject,
            certificate.Thumbprint);

        return service;
    }

    /// <summary>
    /// Creates a signing service for a local certificate with an explicit certificate chain.
    /// </summary>
    /// <param name="certificate">Certificate with private key for signing.</param>
    /// <param name="certificateChain">The complete certificate chain including the signing certificate.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <returns>A signing service configured for local certificate signing.</returns>
    /// <exception cref="ArgumentNullException">Thrown when certificate or certificateChain is null.</exception>
    /// <exception cref="ArgumentException">Thrown when certificate does not have a private key.</exception>
    public static CertificateSigningService Create(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> certificateChain,
        ILogger? logger = null)
    {
#if NET5_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(certificateChain);
#else
        if (certificate == null) { throw new ArgumentNullException(nameof(certificate)); }
        if (certificateChain == null) { throw new ArgumentNullException(nameof(certificateChain)); }
#endif

        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException(
                "Certificate must have a private key for local signing.",
                nameof(certificate));
        }

        var service = new CertificateSigningService(isRemote: false, logger: logger);
        var certificateSource = new DirectCertificateSource(certificate, certificateChain);
        var signingKeyProvider = new DirectSigningKeyProvider(certificate);
        service.SigningKeyField = new CertificateSigningKey(certificateSource, signingKeyProvider, service);

        logger?.LogDebug(
            LogEvents.CertificateLoadedEvent,
            "Creating local signing service with explicit chain. Subject: {Subject}, ChainLength: {ChainLength}",
            certificate.Subject,
            certificateChain.Count);

        return service;
    }

    /// <summary>
    /// Creates a signing service for a remote certificate source.
    /// </summary>
    /// <param name="source">The remote certificate source (e.g., Azure Key Vault, Azure Trusted Signing).</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <returns>A signing service configured for remote certificate signing.</returns>
    /// <exception cref="ArgumentNullException">Thrown when source is null.</exception>
    public static CertificateSigningService Create(
        RemoteCertificateSource source,
        ILogger? logger = null)
    {
#if NET5_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(source);
#else
        if (source == null) { throw new ArgumentNullException(nameof(source)); }
#endif

        var service = new CertificateSigningService(isRemote: true, logger: logger);
        service.SigningKeyField = new RemoteCertificateSigningKey(source, service);

        logger?.LogDebug(
            LogEvents.CertificateLoadedEvent,
            "Creating remote signing service for certificate source");

        return service;
    }

    #endregion

    #region Constructors

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSigningService"/> class with a certificate signing key.
    /// </summary>
    /// <param name="signingKey">The certificate signing key to use.</param>
    /// <param name="logger">Optional logger for diagnostic output. If null, logging is disabled.</param>
    public CertificateSigningService(ICertificateSigningKey signingKey, ILogger? logger = null)
        : this(signingKey?.Metadata.IsRemote ?? false,
               new SigningServiceMetadata(
                   "CertificateSigningService",
                   "Certificate-based signing service"),
               logger)
    {
#if NET5_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(signingKey);
#else
        if (signingKey == null) { throw new ArgumentNullException(nameof(signingKey)); }
#endif
        SigningKeyField = signingKey;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSigningService"/> class.
    /// </summary>
    /// <param name="isRemote">Whether this is a remote signing service.</param>
    /// <param name="serviceMetadata">Optional service metadata. If null, default metadata is created.</param>
    /// <param name="logger">Optional logger for diagnostic output. If null, logging is disabled.</param>
    /// <remarks>
    /// This constructor is for derived classes that provide their own signing key implementation
    /// via the <see cref="GetSigningKey"/> method.
    /// </remarks>
    protected CertificateSigningService(bool isRemote, SigningServiceMetadata? serviceMetadata = null, ILogger? logger = null)
    {
        IsRemoteField = isRemote;
        ServiceMetadataField = serviceMetadata ?? new SigningServiceMetadata(
            GetType().Name,
            $"Certificate-based signing service: {GetType().Name}");
        Logger = logger ?? NullLogger.Instance;
    }

    #endregion

    #region Properties

    /// <summary>
    /// Gets a value indicating whether this is a remote signing service.
    /// </summary>
    public bool IsRemote => IsRemoteField;

    /// <summary>
    /// Gets metadata about the signing service.
    /// </summary>
    public SigningServiceMetadata ServiceMetadata => ServiceMetadataField;

    /// <summary>
    /// Gets the certificate signing key if one was provided directly.
    /// </summary>
    protected ICertificateSigningKey? CertificateSigningKey => SigningKeyField;

    #endregion

    /// <summary>
    /// Creates a new instance of CertificateSigningOptions appropriate for certificate-based signing.
    /// Allows callers to configure certificate-specific settings like SCITT compliance without
    /// knowing the concrete service type.
    /// </summary>
    /// <returns>A new CertificateSigningOptions instance.</returns>
    public virtual CertificateSigningOptions CreateSigningOptions()
    {
        return new CertificateSigningOptions();
    }

    /// <summary>
    /// Creates a CoseSigner for the signing operation with appropriate headers.
    /// This is the final template method that orchestrates the signing process.
    /// 
    /// Process:
    /// 1. Acquires signing key dynamically via GetSigningKey(context)
    /// 2. Gets CoseKey from signing key
    /// 3. Checks for SCITT compliance and adds CWT claims if needed
    /// 4. Builds protected and unprotected headers using contributors
    /// 5. Returns CoseSigner with CoseKey + headers
    /// </summary>
    /// <param name="context">The signing context.</param>
    /// <returns>A CoseSigner ready to sign the message.</returns>
    public CoseSigner GetCoseSigner(SigningContext context)
    {
        ThrowIfDisposed();

        if (context == null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        Logger.LogDebug(
            LogEvents.SigningKeyAcquiredEvent,
            "Acquiring signing key for context. ContentType: {ContentType}, IsRemote: {IsRemote}",
            context.ContentType,
            IsRemoteField);

        // Step 1: Acquire signing key dynamically (enables rotation, multi-key, context-aware scenarios)
        var signingKey = GetSigningKey(context);

        Logger.LogTrace(
            LogEvents.SigningKeyAcquiredEvent,
            "Signing key acquired. CoseAlgorithmId: {CoseAlgorithmId}, KeyType: {KeyType}",
            signingKey.Metadata.CoseAlgorithmId,
            signingKey.Metadata.KeyType);

        // Step 2: Get CoseKey from signing key
        var coseKey = signingKey.GetCoseKey();

        // Step 3: Build headers
        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        // Note: Algorithm header is automatically added by CoseSign1Message.Sign()

        // Create header contributor context for all contributors
        var contributorContext = new HeaderContributorContext(context, signingKey);

        // Apply certificate header contributor first (X5T, X5Chain)
        CertificateContributor.ContributeProtectedHeaders(protectedHeaders, contributorContext);
        CertificateContributor.ContributeUnprotectedHeaders(unprotectedHeaders, contributorContext);

        // Check for SCITT compliance and add CWT claims if requested
        if (context.TryGetCertificateOptions(out var certOptions) && certOptions.EnableScittCompliance)
        {
            Logger.LogDebug(
                LogEvents.SigningHeaderContributionEvent,
                "Adding SCITT-compliant CWT claims to signature headers");
            var cwtContributor = CreateScittCwtClaimsContributor(certOptions, signingKey);
            cwtContributor.ContributeProtectedHeaders(protectedHeaders, contributorContext);
            cwtContributor.ContributeUnprotectedHeaders(unprotectedHeaders, contributorContext);
        }

        // Then apply any additional header contributors from context
        if (context.AdditionalHeaderContributors != null)
        {
            Logger.LogTrace(
                LogEvents.SigningHeaderContributionEvent,
                "Applying {Count} additional header contributors",
                context.AdditionalHeaderContributors.Count);
            foreach (var contributor in context.AdditionalHeaderContributors)
            {
                contributor.ContributeProtectedHeaders(protectedHeaders, contributorContext);
                contributor.ContributeUnprotectedHeaders(unprotectedHeaders, contributorContext);
            }
        }

        // Step 4: Create and return CoseSigner
        return new CoseSigner(
            coseKey,
            protectedHeaders: protectedHeaders,
            unprotectedHeaders: unprotectedHeaders.Count > 0 ? unprotectedHeaders : null);
    }

    /// <summary>
    /// Creates a CwtClaimsHeaderContributor for SCITT compliance.
    /// Uses custom claims if provided, otherwise generates default claims with DID:x509 issuer.
    /// </summary>
    private static CwtClaimsHeaderContributor CreateScittCwtClaimsContributor(
        CertificateSigningOptions options,
        ISigningKey signingKey)
    {
        CwtClaims claims;

        if (options.CustomCwtClaims != null)
        {
            // Use custom claims provided by caller
            claims = options.CustomCwtClaims;
        }
        else
        {
            // Generate default SCITT-compliant claims
            var now = DateTimeOffset.UtcNow;

            // Cast to ICertificateSigningKey to access certificate chain
            if (signingKey is not ICertificateSigningKey certKey)
            {
                throw new InvalidOperationException("SCITT compliance requires a certificate-based signing key");
            }

            var certificateChain = certKey.GetCertificateChain(X509ChainSortOrder.LeafFirst);

            // Generate DID:x509 issuer from certificate chain using extension method
            var leafCert = certificateChain.First();
            string issuer = leafCert.GetDidWithRoot(certificateChain);

            claims = new CwtClaims
            {
                Issuer = issuer,
                Subject = CwtClaims.DefaultSubject, // "unknown.intent"
                IssuedAt = now,
                NotBefore = now
            };
        }

        // Create contributor with claims - always use protected headers for SCITT compliance
        return new CwtClaimsHeaderContributor(claims, CwtClaimsHeaderPlacement.ProtectedOnly);
    }

    /// <summary>
    /// Gets the signing key for the operation.
    /// This is the extension point for derived classes.
    /// 
    /// For local services: Return cached ISigningKey instance.
    /// For remote services: Check for certificate rotation and return appropriate key.
    /// For multi-key services: Select key based on context.
    /// </summary>
    /// <param name="context">The signing context (may be used for key selection).</param>
    /// <returns>The signing key to use for this operation.</returns>
    /// <exception cref="InvalidOperationException">Thrown if no signing key is available.</exception>
    protected virtual ISigningKey GetSigningKey(SigningContext context)
    {
        // If this instance was created with a signing key, use that
        if (SigningKeyField != null)
        {
            return SigningKeyField;
        }

        // Derived classes should override this method
        throw new InvalidOperationException(
            $"No signing key available. Derived class {GetType().Name} must override GetSigningKey() " +
            "or provide an ICertificateSigningKey to the constructor.");
    }

    /// <summary>
    /// Disposes the signing service and underlying resources.
    /// </summary>
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases resources used by the signing service.
    /// Derived classes should override to dispose their specific resources.
    /// </summary>
    /// <param name="disposing">True if disposing managed resources.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (!Disposed)
        {
            if (disposing)
            {
                // Dispose signing key if we own it
                SigningKeyField?.Dispose();
            }

            Disposed = true;
        }
    }

    /// <summary>
    /// Throws ObjectDisposedException if the service has been disposed.
    /// </summary>
    protected void ThrowIfDisposed()
    {
        if (Disposed)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
    }
}