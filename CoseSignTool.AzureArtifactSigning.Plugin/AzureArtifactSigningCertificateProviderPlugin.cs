// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Azure.Core 1.60.0 introduced its own DefaultAzureCredential/DefaultAzureCredentialOptions, which
// collide with the Azure.Identity ones (CS0433). Alias Azure.Identity to keep using its versions.
extern alias IdentityAlias;

namespace CoseSignTool.AzureArtifactSigning.Plugin;

using Azure.CodeSigning;
using Azure.Core;
using Azure.Developer.ArtifactSigning.CryptoProvider;
using Azure.Developer.ArtifactSigning.CryptoProvider.Models;
using CoseSign1.Certificates.AzureArtifactSigning;
using CoseSignTool.Abstractions.Helpers;
using System;
using System.Security.Cryptography;

/// <summary>
/// Certificate provider plugin for Azure Artifact Signing service.
/// Enables CoseSignTool to use Azure Artifact Signing for certificate-based COSE signing operations.
/// </summary>
/// <remarks>
/// <para>
/// This plugin integrates Azure Artifact Signing into CoseSignTool's Sign and indirect-sign commands.
/// It uses DefaultAzureCredential for secure authentication, supporting managed identities,
/// Azure CLI credentials, environment variables, and other Azure SDK authentication mechanisms.
/// </para>
/// <para>
/// Security: This plugin NEVER accepts raw tokens on the command line. All authentication
/// is handled through DefaultAzureCredential, which uses secure, industry-standard
/// credential acquisition methods.
/// </para>
/// </remarks>
public class AzureArtifactSigningCertificateProviderPlugin : ICertificateProviderPlugin
{
    /// <inheritdoc/>
    public string ProviderName => "azure-artifact-signing";

    /// <inheritdoc/>
    public string Description => "Azure Artifact Signing cloud-based certificate provider";

    /// <inheritdoc/>
    public IDictionary<string, string> GetProviderOptions()
    {
        return new Dictionary<string, string>
        {
            ["--aas-endpoint"] = "aas-endpoint",
            ["--aas-account-name"] = "aas-account-name",
            ["--aas-cert-profile-name"] = "aas-cert-profile-name",
            ["--aas-hash-algorithm"] = "aas-hash-algorithm",
            ["--aas-rsa-padding"] = "aas-rsa-padding",
            ["--aas-exclude-credentials"] = AzureCredentialFactory.ExcludeCredentialsKey,
        };
    }

    /// <inheritdoc/>
    public bool CanCreateProvider(IConfiguration configuration)
    {
        // Check for required parameters
        string? endpoint = configuration["aas-endpoint"];
        string? accountName = configuration["aas-account-name"];
        string? certProfileName = configuration["aas-cert-profile-name"];

        return !string.IsNullOrWhiteSpace(endpoint) &&
               !string.IsNullOrWhiteSpace(accountName) &&
               !string.IsNullOrWhiteSpace(certProfileName);
    }

    /// <inheritdoc/>
    public ICoseSigningKeyProvider CreateProvider(IConfiguration configuration, IPluginLogger? logger = null)
    {
        // Extract required parameters
        string? endpoint = configuration["aas-endpoint"];
        string? accountName = configuration["aas-account-name"];
        string? certProfileName = configuration["aas-cert-profile-name"];

        // Validate required parameters
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            throw new ArgumentException("Azure Artifact Signing endpoint (--aas-endpoint) is required.", nameof(configuration));
        }

        if (string.IsNullOrWhiteSpace(accountName))
        {
            throw new ArgumentException("Azure Artifact Signing account name (--aas-account-name) is required.", nameof(configuration));
        }

        if (string.IsNullOrWhiteSpace(certProfileName))
        {
            throw new ArgumentException("Azure Artifact Signing certificate profile name (--aas-cert-profile-name) is required.", nameof(configuration));
        }

        try
        {
            HashAlgorithmName hashAlgorithm = HashAlgorithmHelper.Parse(configuration, "aas-hash-algorithm");
            RSASignaturePadding rsaPadding = RsaSignaturePaddingHelper.Parse(configuration, "aas-rsa-padding");

            logger?.LogVerbose($"Creating Azure Artifact Signing provider...");
            logger?.LogVerbose($"  Endpoint: {endpoint}");
            logger?.LogVerbose($"  Account: {accountName}");
            logger?.LogVerbose($"  Certificate Profile: {certProfileName}");
            logger?.LogVerbose($"  Hash Algorithm: {hashAlgorithm.Name}");
            logger?.LogVerbose($"  COSE Algorithm: {RsaSignaturePaddingHelper.GetCoseAlgorithmName(hashAlgorithm, rsaPadding)}");

            // Create (or reuse) the Azure credential. DefaultAzureCredential supports multiple
            // authentication methods in order of precedence:
            // 1. Environment variables (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, etc.)
            // 2. Managed Identity (for Azure VMs, App Service, etc.)
            // 3. Visual Studio credential
            // 4. Azure CLI credential
            // 5. Azure PowerShell credential
            // The instance is cached per exclusion set so repeated signings reuse its token cache
            // instead of re-probing the chain and re-acquiring a token each time.
            TokenCredential credential = AzureCredentialFactory.GetCredential(
                AzureCredentialFactory.GetExclusions(configuration),
                logger);

            logger?.LogVerbose("Creating CertificateProfileClient...");
            // Create the Certificate Profile Client with fast-retry pipeline tuning so transient
            // Azure SDK retries do not balloon interactive signing latency. The default 800 ms
            // exponential back-off (3 retries, ~5 s ceiling) is replaced with 250 ms fixed retries
            // (8 retries, ~2 s ceiling). Callers can override via ConfigureAasPerformanceOptimizations.
            CertificateProfileClientOptions clientOptions = new();
            clientOptions.ConfigureAasPerformanceOptimizations();

            // Constructor: CertificateProfileClient(TokenCredential credential, Uri endpoint, options)
            Uri endpointUri = new Uri(endpoint);
            Azure.CodeSigning.CertificateProfileClient certificateProfileClient = new Azure.CodeSigning.CertificateProfileClient(
                credential,
                endpointUri,
                clientOptions);

            logger?.LogVerbose("Creating AzSignContext...");
            // Create AzSignContext with explicit performance options. Defaults match the SDK
            // baseline (3 task retries, 60 s task timeout) — surfaced here so future tuning
            // touches a single point.
            AzSignContextOptions signContextOptions = AasClientOptionsExtensions.ConfigureAasSigningPerformance();
            AzSignContext signContext = new AzSignContext(
                accountName,
                certProfileName,
                certificateProfileClient,
                null,
                signContextOptions);

            logger?.LogVerbose("Creating AzureArtifactSigningCoseSigningKeyProvider...");
            // The hash algorithm and padding together select the COSE algorithm the service is asked
            // for: PKCS#1 v1.5 yields RS256/RS384/RS512 and PSS yields PS256/PS384/PS512.
            AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(signContext, hashAlgorithm, rsaPadding);

            logger?.LogInformation("Azure Artifact Signing provider created successfully.");
            return provider;
        }
        catch (ArgumentException)
        {
            // Re-throw argument exceptions as-is
            throw;
        }
        catch (UriFormatException ex)
        {
            logger?.LogError($"Invalid Azure Artifact Signing endpoint URL: {endpoint}");
            throw new ArgumentException($"Invalid Azure Artifact Signing endpoint URL: {endpoint}. Ensure it is a valid HTTPS URL.", nameof(configuration), ex);
        }
        catch (Exception ex)
        {
            logger?.LogError($"Failed to create Azure Artifact Signing provider: {ex.Message}");
            logger?.LogException(ex);
            throw new InvalidOperationException(
                "Failed to create Azure Artifact Signing provider. " +
                "Ensure Azure credentials are properly configured (environment variables, managed identity, Azure CLI, etc.) " +
                "and the specified endpoint, account name, and certificate profile are correct.",
                ex);
        }
    }

    /// <inheritdoc/>
    public string GetUsageDocumentation()
    {
        return @"
Azure Artifact Signing Certificate Provider
==========================================

The Azure Artifact Signing provider enables signing with certificates managed by Azure Artifact Signing,
a cloud-based certificate management and signing service.

Required Parameters:
  --aas-endpoint <url>              Azure Artifact Signing endpoint URL
                                     Example: https://myaccount.codesigning.azure.net

  --aas-account-name <name>         Azure Artifact Signing account name
                                     Example: MySigningAccount

  --aas-cert-profile-name <name>    Certificate profile name within the account
                                     Example: MyCodeSigningProfile

Optional Parameters:
  --aas-hash-algorithm <name>       Hash algorithm used to sign. SHA256 (default), SHA384 or SHA512.
                                     This selects the digest size of the COSE algorithm, so SHA384 signs
                                     with PS384 by default, or RS384 with --aas-rsa-padding PKCS1.
                                     Example: --aas-hash-algorithm SHA384

  --aas-rsa-padding <name>          RSA signature padding: PSS (default) or PKCS1. This selects the COSE
                                     algorithm family, so PKCS1 signs with RS256/RS384/RS512 and PSS signs
                                     with PS256/PS384/PS512. The COSE prefixes RS and PS are also accepted.
                                     Example: --aas-rsa-padding PKCS1
                                     Combined with --aas-hash-algorithm SHA384 this produces RS384.

  --aas-exclude-credentials <list>  Comma-separated credentials to exclude from the DefaultAzureCredential chain.
                                     Excluding a credential that cannot succeed in your environment removes the
                                     probe delay it would otherwise add before the chain reaches a working credential.
                                     Example: --aas-exclude-credentials ManagedIdentityCredential
                                     May also be supplied as a JSON array under the ExcludeCredentials section:
                                       ""ExcludeCredentials"": [""ManagedIdentityCredential""]

Authentication:
  This provider uses DefaultAzureCredential for authentication, which supports:
  - Managed Identity (Azure VMs, App Service, Container Instances, etc.)
  - Environment variables (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, etc.)
  - Azure CLI (az login)
  - Azure PowerShell (Connect-AzAccount)
  - Visual Studio credential

  The credential instance is cached per exclusion set for the lifetime of the process, so repeated
  signing operations reuse the resolved credential chain and its acquired tokens.
  
  For CI/CD scenarios, configure environment variables or use managed identity.
  For local development, use 'az login' or Visual Studio authentication.

  Security Note: This provider NEVER accepts raw tokens or secrets on the command line.
  All authentication uses secure Azure SDK credential mechanisms.

Examples:
  # Sign with Azure Artifact Signing (using Azure CLI credentials)
  az login
  CoseSignTool sign --payload file.bin --signature file.cose \
    --cert-provider azure-artifact-signing \
    --aas-endpoint https://myaccount.codesigning.azure.net \
    --aas-account-name MySigningAccount \
    --aas-cert-profile-name MyCodeSigningProfile

  # Indirect sign with Azure Artifact Signing (using managed identity in Azure)
  CoseSignTool indirect-sign --payload file.bin --signature file.cose \
    --cert-provider azure-artifact-signing \
    --aas-endpoint https://myaccount.codesigning.azure.net \
    --aas-account-name MySigningAccount \
    --aas-cert-profile-name MyCodeSigningProfile

  # Using environment variables for authentication (CI/CD)
  export AZURE_TENANT_ID=your-tenant-id
  export AZURE_CLIENT_ID=your-client-id
  export AZURE_CLIENT_SECRET=your-client-secret
  CoseSignTool sign --payload file.bin --signature file.cose \
    --cert-provider azure-artifact-signing \
    --aas-endpoint https://myaccount.codesigning.azure.net \
    --aas-account-name MySigningAccount \
    --aas-cert-profile-name MyCodeSigningProfile

Troubleshooting:
  - Ensure you have proper Azure credentials configured
  - Verify the endpoint URL is correct and accessible
  - Confirm your Azure identity has appropriate permissions for the signing account
  - Check that the account name and certificate profile name exist
  - For managed identity issues, verify the identity is enabled and has required roles
  - For Azure CLI issues, try running 'az login' again
";
    }
}
