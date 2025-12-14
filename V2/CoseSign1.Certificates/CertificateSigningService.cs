// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Certificates.Logging;
using CoseSign1.Headers;
using DIDx509;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSign1.Certificates;

/// <summary>
/// Abstract base class for certificate-based signing services.
/// Implements template method pattern where GetSigningKey() is the extension point.
/// Thread-safe: All operations are stateless or use proper locking.
/// Per V3 architecture: Keys are acquired dynamically within GetCoseSigner().
/// </summary>
public abstract class CertificateSigningService : ISigningService<CertificateSigningOptions>
{
    private static readonly CertificateHeaderContributor CertificateContributor = new();
    private bool Disposed;
    private readonly SigningServiceMetadata ServiceMetadataField;
    private readonly bool IsRemoteField;
    /// <summary>
    /// The logger for this service instance.
    /// </summary>
    protected readonly ILogger Logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSigningService"/> class.
    /// </summary>
    /// <param name="isRemote">Whether this is a remote signing service.</param>
    /// <param name="serviceMetadata">Optional service metadata. If null, default metadata is created.</param>
    /// <param name="logger">Optional logger for diagnostic output. If null, logging is disabled.</param>
    protected CertificateSigningService(bool isRemote, SigningServiceMetadata? serviceMetadata = null, ILogger? logger = null)
    {
        IsRemoteField = isRemote;
        ServiceMetadataField = serviceMetadata ?? new SigningServiceMetadata(
            GetType().Name,
            $"Certificate-based signing service: {GetType().Name}");
        Logger = logger ?? NullLogger.Instance;
    }

    /// <summary>
    /// Gets a value indicating whether this is a remote signing service.
    /// </summary>
    public bool IsRemote => IsRemoteField;

    /// <summary>
    /// Gets metadata about the signing service.
    /// </summary>
    public SigningServiceMetadata ServiceMetadata => ServiceMetadataField;

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
    protected abstract ISigningKey GetSigningKey(SigningContext context);

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
                // Derived classes should dispose their signing keys
                // Base class doesn't own the key, so nothing to dispose here
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