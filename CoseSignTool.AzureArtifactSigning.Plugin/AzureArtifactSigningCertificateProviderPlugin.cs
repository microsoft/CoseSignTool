// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Azure.Core 1.60.0 introduced its own DefaultAzureCredential/DefaultAzureCredentialOptions, which
// collide with the Azure.Identity ones (CS0433). Alias Azure.Identity to keep using its versions.
extern alias IdentityAlias;

namespace CoseSignTool.AzureArtifactSigning.Plugin;

using System;
using Azure.CodeSigning;
using Azure.Core;
using Azure.Developer.ArtifactSigning.CryptoProvider;
using Azure.Developer.ArtifactSigning.CryptoProvider.Models;
using CoseSign1.Certificates.AzureArtifactSigning;
using DefaultAzureCredential = IdentityAlias::Azure.Identity.DefaultAzureCredential;
using DefaultAzureCredentialOptions = IdentityAlias::Azure.Identity.DefaultAzureCredentialOptions;

/// <summary>
/// Certificate provider plugin for Azure Artifact Signing service.
/// Enables CoseSignTool to use Azure Artifact Signing for certificate-based COSE signing operations.
/// </summary>
/// <remarks>
/// <para>
/// This plugin integrates Azure Artifact Signing into CoseSignTool's Sign and indirect-sign commands.
/// By default it uses DefaultAzureCredential for secure authentication, supporting managed identities,
/// Azure CLI credentials, environment variables, and other Azure SDK authentication mechanisms.
/// </para>
/// <para>
/// Security: This plugin NEVER accepts raw tokens on the command line. All authentication
/// is handled through Azure SDK credentials, either supplied by the caller or created using DefaultAzureCredential.
/// </para>
/// </remarks>
public class AzureArtifactSigningCertificateProviderPlugin : ICertificateProviderPlugin
{
    private const string ExcludeCredentialsKey = "aas-exclude-credentials";
    private const string ExcludeCredentialsSection = "ExcludeCredentials";

    private static readonly IReadOnlyDictionary<string, Action<DefaultAzureCredentialOptions>> ExclusionSetters =
        new Dictionary<string, Action<DefaultAzureCredentialOptions>>(StringComparer.OrdinalIgnoreCase)
        {
            ["Environment"] = options => options.ExcludeEnvironmentCredential = true,
            ["WorkloadIdentity"] = options => options.ExcludeWorkloadIdentityCredential = true,
            ["ManagedIdentity"] = options => options.ExcludeManagedIdentityCredential = true,
            ["AzureDeveloperCli"] = options => options.ExcludeAzureDeveloperCliCredential = true,
#pragma warning disable CS0618 // SharedTokenCacheCredential is deprecated but still a valid exclusion name.
            ["SharedTokenCache"] = options => options.ExcludeSharedTokenCacheCredential = true,
#pragma warning restore CS0618
            ["InteractiveBrowser"] = options => options.ExcludeInteractiveBrowserCredential = true,
            ["Broker"] = options => options.ExcludeBrokerCredential = true,
            ["AzureCli"] = options => options.ExcludeAzureCliCredential = true,
            ["VisualStudio"] = options => options.ExcludeVisualStudioCredential = true,
            ["VisualStudioCode"] = options => options.ExcludeVisualStudioCodeCredential = true,
            ["AzurePowerShell"] = options => options.ExcludeAzurePowerShellCredential = true,
        };

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
            ["--aas-exclude-credentials"] = ExcludeCredentialsKey,
        };
    }

    /// <inheritdoc/>
    public bool CanCreateProvider(IConfiguration configuration)
    {
        // Check for required parameters
        string? endpoint = configuration["aas-endpoint"];
        string? accountName = configuration["aas-account-name"] ?? configuration["account-name"];
        string? certProfileName = configuration["aas-cert-profile-name"] ?? configuration["cert-profile-name"];

        return !string.IsNullOrWhiteSpace(endpoint) &&
               !string.IsNullOrWhiteSpace(accountName) &&
               !string.IsNullOrWhiteSpace(certProfileName);
    }

    /// <inheritdoc/>
    public ICoseSigningKeyProvider CreateProvider(IConfiguration configuration, IPluginLogger? logger = null)
    {
        return this.CreateProvider(configuration, logger, credential: null);
    }

    /// <summary>
    /// Creates a signing provider using a caller-supplied credential when available.
    /// </summary>
    /// <param name="configuration">The Artifact Signing configuration.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <param name="credential">
    /// An existing credential to reuse. If null, creates a DefaultAzureCredential using the configured exclusions.
    /// Exclusions do not apply to a supplied credential. Token caching and refresh remain the credential's responsibility.
    /// </param>
    /// <returns>The Artifact Signing key provider.</returns>
    public ICoseSigningKeyProvider CreateProvider(
        IConfiguration configuration,
        IPluginLogger? logger,
        TokenCredential? credential)
    {
        // Extract required parameters
        string? endpoint = configuration["aas-endpoint"];
        string? accountName = configuration["aas-account-name"] ?? configuration["account-name"];
        string? certProfileName = configuration["aas-cert-profile-name"] ?? configuration["cert-profile-name"];

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

            // Chain behavior: https://learn.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet
            credential ??= CreateDefaultCredential(configuration, logger);

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

    internal static TokenCredential CreateDefaultCredential(IConfiguration configuration, IPluginLogger? logger = null)
    {
        logger?.LogVerbose("Creating Azure credentials using DefaultAzureCredential...");
        DefaultAzureCredentialOptions options = new()
        {
            // Exclude interactive browser auth to avoid unexpected prompts in CI/CD.
            ExcludeInteractiveBrowserCredential = true
        };

        string? commandLineValue = configuration[ExcludeCredentialsKey];
        if (!string.IsNullOrWhiteSpace(commandLineValue))
        {
            foreach (string name in commandLineValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                ApplyCredentialExclusion(name, options, logger);
            }
        }

        foreach (IConfigurationSection child in configuration.GetSection(ExcludeCredentialsSection).GetChildren())
        {
            ApplyCredentialExclusion(child.Value, options, logger);
        }

        return new DefaultAzureCredential(options); // CodeQL [SM02196] DefaultAzureCredential is the recommended approach for client applications and libraries to authenticate to Azure services
    }

    private static void ApplyCredentialExclusion(
        string? name,
        DefaultAzureCredentialOptions options,
        IPluginLogger? logger)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return;
        }

        string exclusion = name.Trim();
        if (exclusion.EndsWith("Credential", StringComparison.OrdinalIgnoreCase))
        {
            exclusion = exclusion[..^"Credential".Length];
        }

        if (!ExclusionSetters.TryGetValue(exclusion, out Action<DefaultAzureCredentialOptions>? applyExclusion))
        {
            string supportedNames = string.Join(", ", ExclusionSetters.Keys
                .Select(supportedName => supportedName + "Credential")
                .OrderBy(supportedName => supportedName, StringComparer.Ordinal));
            throw new ArgumentException(
                $"'{name}' is not a recognized credential to exclude. Supported values are: {supportedNames}.",
                nameof(name));
        }

        applyExclusion(options);
        logger?.LogVerbose($"  Excluding {exclusion}Credential from the credential chain.");
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

  Programmatic callers can pass an existing TokenCredential to CreateProvider to reuse their
  authentication object. Without one, this provider creates a DefaultAzureCredential.
  Credential exclusions apply only when creating the default credential. There is no global cache.
  
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
