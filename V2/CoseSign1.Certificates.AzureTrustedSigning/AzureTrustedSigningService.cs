// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.AzureTrustedSigning;

using System.Diagnostics.CodeAnalysis;
using Azure.Developer.TrustedSigning.CryptoProvider;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Interfaces;

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
/// This service is thread-safe and can be reused across multiple signing operations.
/// The AzSignContext is created once and reused for the lifetime of this service.
/// </remarks>
public class AzureTrustedSigningService : CertificateSigningService
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ServiceName = "AzureTrustedSigning";
        public const string Description = "Microsoft Azure Trusted Signing service with FIPS 140-2 Level 3 HSM-backed keys";

        public const string AdditionalDataKeyServiceType = "ServiceType";
        public const string AdditionalDataValueRemote = "Remote";

        public const string AdditionalDataKeyProvider = "Provider";
        public const string AdditionalDataValueMicrosoft = "Microsoft";

        public const string AdditionalDataKeyCompliance = "Compliance";
        public const string ComplianceFips1402Level3 = "FIPS 140-2 Level 3";
        public const string ComplianceScitt = "SCITT";
    }

    private readonly AzSignContext SignContext;
    private readonly AzureTrustedSigningCertificateSource CertificateSource;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureTrustedSigningService"/> class.
    /// </summary>
    /// <param name="signContext">The Azure Trusted Signing context from the SDK. This will be reused across operations.</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses the certificate chain from Azure.</param>
    /// <param name="serviceMetadata">Optional service metadata. If null, creates default metadata.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="signContext"/> is null.</exception>
    public AzureTrustedSigningService(
        AzSignContext signContext,
        ICertificateChainBuilder? chainBuilder = null,
        SigningServiceMetadata? serviceMetadata = null)
        : base(isRemote: true, serviceMetadata ?? CreateDefaultMetadata())
    {
        SignContext = signContext ?? throw new ArgumentNullException(nameof(signContext));
        CertificateSource = new AzureTrustedSigningCertificateSource(SignContext, chainBuilder);
    }

    /// <summary>
    /// Creates default service metadata for Azure Trusted Signing.
    /// </summary>
    private static SigningServiceMetadata CreateDefaultMetadata()
    {
        return new SigningServiceMetadata(
            serviceName: ClassStrings.ServiceName,
            description: ClassStrings.Description,
            additionalData: new Dictionary<string, object>
            {
                [ClassStrings.AdditionalDataKeyServiceType] = ClassStrings.AdditionalDataValueRemote,
                [ClassStrings.AdditionalDataKeyProvider] = ClassStrings.AdditionalDataValueMicrosoft,
                [ClassStrings.AdditionalDataKeyCompliance] = new[] { ClassStrings.ComplianceFips1402Level3, ClassStrings.ComplianceScitt }
            });
    }

    private Remote.RemoteCertificateSigningKey? SigningKeyField;

    /// <summary>
    /// Gets the signing key for the current context.
    /// Returns the same certificate source instance for all operations (Azure Trusted Signing uses a single key per profile).
    /// </summary>
    /// <param name="context">The signing context.</param>
    /// <returns>An ISigningKey that provides access to the Azure Trusted Signing key operations.</returns>
    protected override ISigningKey GetSigningKey(SigningContext context)
    {
        // Azure Trusted Signing uses a single key per signing profile
        // Return a signing key that wraps our reusable certificate source
        SigningKeyField ??= new Remote.RemoteCertificateSigningKey(CertificateSource, this);
        return SigningKeyField;
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            SigningKeyField?.Dispose();
            CertificateSource?.Dispose();
        }

        base.Dispose(disposing);
    }
}