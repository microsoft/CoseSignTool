// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates;
using CoseSign1.Headers;

namespace CoseSign1.Certificates.AzureTrustedSigning.Extensions;

/// <summary>
/// Extension methods for configuring Azure Trusted Signing with SCITT compliance.
/// </summary>
public static class ScittExtensions
{
    /// <summary>
    /// Configures certificate signing options for SCITT compliance with Azure Trusted Signing.
    /// Uses DID:X509 with EKU policy for Azure-specific issuer identification.
    /// </summary>
    /// <param name="options">The certificate signing options to configure.</param>
    /// <param name="certificateChain">The certificate chain from Azure Trusted Signing (leaf-first).</param>
    /// <returns>The configured options for fluent chaining.</returns>
    /// <remarks>
    /// This method:
    /// 1. Enables SCITT compliance
    /// 2. Generates DID:X509 issuer with Azure-specific EKU policy
    /// 3. Creates CWT claims with proper issuer and timestamps
    /// 
    /// The issuer format follows DID:X509 EKU policy specification:
    /// did:x509:0:sha256:{base64url-hash}::eku:{microsoft-oid}
    /// </remarks>
    public static CertificateSigningOptions ConfigureForAzureScitt(
        this CertificateSigningOptions options,
        IEnumerable<System.Security.Cryptography.X509Certificates.X509Certificate2> certificateChain)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (certificateChain == null)
        {
            throw new ArgumentNullException(nameof(certificateChain));
        }

        // Generate Azure-specific DID:X509 identifier with EKU policy
        var issuer = AzureTrustedSigningDidX509.Generate(certificateChain);

        // Create SCITT-compliant CWT claims
        var now = DateTimeOffset.UtcNow;
        var claims = new CwtClaims
        {
            Issuer = issuer,
            IssuedAt = now,
            NotBefore = now
        };

        // Enable SCITT compliance with custom claims
        options.EnableScittCompliance = true;
        options.CustomCwtClaims = claims;

        return options;
    }

    /// <summary>
    /// Configures certificate signing options for SCITT compliance with custom CWT claims.
    /// </summary>
    /// <param name="options">The certificate signing options to configure.</param>
    /// <param name="certificateChain">The certificate chain from Azure Trusted Signing (leaf-first).</param>
    /// <param name="configureClaimsAction">Action to configure additional CWT claims.</param>
    /// <returns>The configured options for fluent chaining.</returns>
    public static CertificateSigningOptions ConfigureForAzureScitt(
        this CertificateSigningOptions options,
        IEnumerable<System.Security.Cryptography.X509Certificates.X509Certificate2> certificateChain,
        Action<CwtClaims> configureClaimsAction)
    {
        if (configureClaimsAction == null)
        {
            throw new ArgumentNullException(nameof(configureClaimsAction));
        }

        // First configure with default Azure SCITT settings
        options.ConfigureForAzureScitt(certificateChain);

        // Allow caller to customize claims
        if (options.CustomCwtClaims != null)
        {
            configureClaimsAction(options.CustomCwtClaims);
        }

        return options;
    }
}