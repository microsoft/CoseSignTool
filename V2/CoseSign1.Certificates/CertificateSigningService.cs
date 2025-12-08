// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;

namespace CoseSign1.Certificates;

/// <summary>
/// Abstract base class for certificate-based signing services.
/// Implements template method pattern where GetSigningKey() is the extension point.
/// Thread-safe: All operations are stateless or use proper locking.
/// Per V3 architecture: Keys are acquired dynamically within GetCoseSigner().
/// </summary>
public abstract class CertificateSigningService : ISigningService
{
    private static readonly CertificateHeaderContributor CertificateContributor = new();
    private bool _disposed;
    private readonly SigningServiceMetadata _serviceMetadata;
    private readonly bool _isRemote;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSigningService"/> class.
    /// </summary>
    /// <param name="isRemote">Whether this is a remote signing service.</param>
    /// <param name="serviceMetadata">Optional service metadata. If null, default metadata is created.</param>
    protected CertificateSigningService(bool isRemote, SigningServiceMetadata? serviceMetadata = null)
    {
        _isRemote = isRemote;
        _serviceMetadata = serviceMetadata ?? new SigningServiceMetadata(
            GetType().Name,
            $"Certificate-based signing service: {GetType().Name}");
    }

    /// <summary>
    /// Gets a value indicating whether this is a remote signing service.
    /// </summary>
    public bool IsRemote => _isRemote;

    /// <summary>
    /// Gets metadata about the signing service.
    /// </summary>
    public SigningServiceMetadata ServiceMetadata => _serviceMetadata;

    /// <summary>
    /// Creates a CoseSigner for the signing operation with appropriate headers.
    /// This is the final template method that orchestrates the signing process.
    /// 
    /// Process:
    /// 1. Acquires signing key dynamically via GetSigningKey(context)
    /// 2. Gets CoseKey from signing key
    /// 3. Builds protected and unprotected headers using contributors
    /// 4. Returns CoseSigner with CoseKey + headers
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

        // Step 1: Acquire signing key dynamically (enables rotation, multi-key, context-aware scenarios)
        var signingKey = GetSigningKey(context);

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

        // Then apply any additional header contributors from context
        if (context.AdditionalHeaderContributors != null)
        {
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
        if (!_disposed)
        {
            if (disposing)
            {
                // Derived classes should dispose their signing keys
                // Base class doesn't own the key, so nothing to dispose here
            }

            _disposed = true;
        }
    }

    /// <summary>
    /// Throws ObjectDisposedException if the service has been disposed.
    /// </summary>
    protected void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
    }
}
