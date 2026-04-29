// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureArtifactSigning.Plugin;

using Azure.Core;
using Azure.Developer.ArtifactSigning.CryptoProvider;
using Azure.Identity;
using CoseSign1.Certificates.AzureArtifactSigning;
using System;

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
            logger?.LogVerbose($"Creating Azure Artifact Signing provider...");
            logger?.LogVerbose($"  Endpoint: {endpoint}");
            logger?.LogVerbose($"  Account: {accountName}");
            logger?.LogVerbose($"  Certificate Profile: {certProfileName}");


            // Create Azure credential using DefaultAzureCredential
            // This supports multiple authentication methods in order of precedence:
            // 1. Environment variables (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, etc.)
            // 2. Managed Identity (for Azure VMs, App Service, etc.)
            // 3. Visual Studio credential
            // 4. Azure CLI credential
            // 5. Azure PowerShell credential
            logger?.LogVerbose("Acquiring Azure credentials using DefaultAzureCredential...");
            TokenCredential credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions // CodeQL [SM02196] DefaultAzureCredential is the recommended approach for client applications and libraries to authenticate to Azure services
            {
                // Exclude interactive browser auth to avoid unexpected prompts in CI/CD
                ExcludeInteractiveBrowserCredential = true
            });

            logger?.LogVerbose("Creating CertificateProfileClient...");
            // Create the Certificate Profile Client
            // Constructor: CertificateProfileClient(TokenCredential credential, Uri endpoint, options)
            Uri endpointUri = new Uri(endpoint);
            var certificateProfileClient = new Azure.CodeSigning.CertificateProfileClient(
                credential,
                endpointUri);

            logger?.LogVerbose("Creating AzSignContext...");
            // Create AzSignContext using the certificate profile client
            AzSignContext signContext = new AzSignContext(
                accountName,
                certProfileName,
                certificateProfileClient);

            logger?.LogVerbose("Creating AzureArtifactSigningCoseSigningKeyProvider...");
            // Create and return the key provider
            AzureArtifactSigningCoseSigningKeyProvider provider = new AzureArtifactSigningCoseSigningKeyProvider(signContext);

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

Authentication:
  This provider uses DefaultAzureCredential for authentication, which supports:
  - Managed Identity (Azure VMs, App Service, Container Instances, etc.)
  - Environment variables (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, etc.)
  - Azure CLI (az login)
  - Azure PowerShell (Connect-AzAccount)
  - Visual Studio credential
  
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
