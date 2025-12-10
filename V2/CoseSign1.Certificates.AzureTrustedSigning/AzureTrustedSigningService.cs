// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Developer.TrustedSigning.CryptoProvider;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.ChainBuilders;

namespace CoseSign1.Certificates.AzureTrustedSigning;

/// <summary>
/// Signing service for Azure Trusted Signing.
/// Implements the V2 certificate-based signing pattern for remote signing services.
/// </summary>
/// <remarks>
/// Azure Trusted Signing is a Microsoft-managed cloud signing service that provides:
/// - Secure key storage in FIPS 140-2 Level 3 HSMs
/// - Certificate lifecycle management
/// - Support for RSA and ECDSA algorithms
/// - Compliance with industry standards (SCITT, etc.)
/// 
/// This service is thread-safe and can be used across multiple signing operations.
/// The underlying AzSignContext is provided by the caller and should be disposed by the caller.
/// </remarks>
public class AzureTrustedSigningService : CertificateSigningService
{
    private readonly AzureTrustedSigningCertificateSource _certificateSource;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureTrustedSigningService"/> class.
    /// </summary>
    /// <param name="signContext">The Azure Trusted Signing context from the SDK.</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder.</param>
    /// <param name="serviceMetadata">Optional service metadata. If null, creates default metadata.</param>
    public AzureTrustedSigningService(
        AzSignContext signContext,
        ICertificateChainBuilder? chainBuilder = null,
        SigningServiceMetadata? serviceMetadata = null)
        : base(isRemote: true, serviceMetadata ?? CreateDefaultMetadata())
    {
        if (signContext == null)
        {
            throw new ArgumentNullException(nameof(signContext));
        }

        _certificateSource = new AzureTrustedSigningCertificateSource(signContext, chainBuilder);
    }

    /// <summary>
    /// Creates default service metadata for Azure Trusted Signing.
    /// </summary>
    private static SigningServiceMetadata CreateDefaultMetadata()
    {
        return new SigningServiceMetadata(
            name: "AzureTrustedSigning",
            description: "Microsoft Azure Trusted Signing service with FIPS 140-2 Level 3 HSM-backed keys",
            additionalMetadata: new Dictionary<string, object>
            {
                ["ServiceType"] = "Remote",
                ["Provider"] = "Microsoft",
                ["Compliance"] = new[] { "FIPS 140-2 Level 3", "SCITT" }
            });
    }

    /// <summary>
    /// Gets the signing key for the current context.
    /// Azure Trusted Signing uses a single key per signing profile, so this returns the same key for all contexts.
    /// </summary>
    /// <param name="context">The signing context (not used for Azure Trusted Signing).</param>
    /// <returns>An ISigningKey that provides access to the Azure Trusted Signing key operations.</returns>
    protected override ISigningKey GetSigningKey(SigningContext context)
    {
        // Azure Trusted Signing uses a single key per signing profile
        // The RemoteSigningKeyProvider will handle the actual signing operations
        return new Remote.RemoteSigningKeyProvider(_certificateSource, this);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _certificateSource?.Dispose();
        }

        base.Dispose(disposing);
    }
}
