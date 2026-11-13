// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern alias IdentityAlias;

namespace CoseSignTool.AzureArtifactSigning.Plugin;

using System;
using System.Collections.Generic;
using System.Linq;
using Azure.Core;
using DefaultAzureCredential = IdentityAlias::Azure.Identity.DefaultAzureCredential;
using DefaultAzureCredentialOptions = IdentityAlias::Azure.Identity.DefaultAzureCredentialOptions;
using Microsoft.Extensions.Configuration;

/// <summary>
/// Creates the <see cref="TokenCredential"/> used to call Azure Artifact Signing.
/// </summary>
/// <remarks>
/// <para>
/// Callers own credential reuse. The combined <c>aas_sign_mst_register</c> command passes one credential
/// to both its signing provider and MST proxy client, and accepts an existing credential from its caller.
/// This factory does not cache credentials or tokens.
/// See <see href="https://learn.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential?view=azure-dotnet">DefaultAzureCredential</see>
/// for credential-chain behavior and instance-reuse guidance.
/// </para>
/// <para>
/// Managed identity can be worth excluding on developer machines and on hosts where
/// an unrelated identity is present, because probing it can add multi-second delays before the chain
/// falls through to the credential that actually works.
/// </para>
/// </remarks>
public static class AzureCredentialFactory
{
    /// <summary>
    /// The configuration key holding a comma-separated list of credentials to exclude.
    /// </summary>
    public const string ExcludeCredentialsKey = "aas-exclude-credentials";

    /// <summary>
    /// The configuration section holding credentials to exclude when supplied as a JSON array.
    /// </summary>
    public const string ExcludeCredentialsSection = "ExcludeCredentials";

    /// <summary>
    /// Applies a named exclusion to a <see cref="DefaultAzureCredentialOptions"/> instance.
    /// </summary>
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

    /// <summary>
    /// Gets the names that may be supplied to exclude a credential, in documentation order.
    /// </summary>
    public static IReadOnlyList<string> SupportedExclusionNames { get; } = Array.AsReadOnly(
        ExclusionSetters.Keys.Select(name => name + "Credential").OrderBy(name => name, StringComparer.Ordinal).ToArray());

    /// <summary>
    /// Reads the credential exclusions from configuration.
    /// </summary>
    /// <param name="configuration">The configuration to read from.</param>
    /// <returns>The exclusion names, which may be empty.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configuration"/> is null.</exception>
    /// <remarks>
    /// Exclusions may be supplied either as a comma-separated command line value
    /// (<c>--aas-exclude-credentials ManagedIdentityCredential</c>) or as a JSON array under the
    /// <c>ExcludeCredentials</c> section. Values from both sources are combined.
    /// </remarks>
    public static IReadOnlyList<string> GetExclusions(IConfiguration configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        IReadOnlyList<string> commandLineExclusions = Array.Empty<string>();
        string? commandLineValue = configuration[ExcludeCredentialsKey];
        if (!string.IsNullOrWhiteSpace(commandLineValue))
        {
            commandLineExclusions = commandLineValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        List<string>? exclusions = null;
        foreach (IConfigurationSection child in configuration.GetSection(ExcludeCredentialsSection).GetChildren())
        {
            if (!string.IsNullOrWhiteSpace(child.Value))
            {
                (exclusions ??= new(commandLineExclusions)).Add(child.Value.Trim());
            }
        }

        return exclusions is null ? commandLineExclusions : exclusions;
    }

    /// <summary>
    /// Creates a <see cref="DefaultAzureCredential"/> honoring the supplied exclusions.
    /// </summary>
    /// <param name="excludeCredentials">
    /// Credentials to exclude from the chain. Names are case-insensitive and the trailing "Credential"
    /// is optional, so "ManagedIdentityCredential" and "managedidentity" are equivalent.
    /// </param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <returns>A new credential. Callers may pass this instance to multiple signing operations.</returns>
    /// <exception cref="ArgumentException">Thrown when an exclusion name is not recognized.</exception>
    /// <example>
    /// <code>
    /// TokenCredential credential = AzureCredentialFactory.CreateCredential(new[] { "ManagedIdentityCredential" }, logger);
    /// </code>
    /// </example>
    public static TokenCredential CreateCredential(IEnumerable<string>? excludeCredentials, IPluginLogger? logger = null)
    {
        logger?.LogVerbose("Creating Azure credentials using DefaultAzureCredential...");

        DefaultAzureCredentialOptions options = new()
        {
            // Exclude interactive browser auth to avoid unexpected prompts in CI/CD.
            ExcludeInteractiveBrowserCredential = true
        };

        if (excludeCredentials is not null)
        {
            foreach (string name in excludeCredentials)
            {
                if (string.IsNullOrWhiteSpace(name))
                {
                    continue;
                }

                string exclusion = name.Trim();
                if (exclusion.EndsWith("Credential", StringComparison.OrdinalIgnoreCase))
                {
                    exclusion = exclusion[..^"Credential".Length];
                }

                if (!ExclusionSetters.TryGetValue(exclusion, out Action<DefaultAzureCredentialOptions>? applyExclusion))
                {
                    throw new ArgumentException(
                        $"'{name}' is not a recognized credential to exclude. Supported values are: {string.Join(", ", SupportedExclusionNames)}.",
                        nameof(excludeCredentials));
                }

                applyExclusion(options);
                logger?.LogVerbose($"  Excluding {exclusion}Credential from the credential chain.");
            }
        }

        return new DefaultAzureCredential(options); // CodeQL [SM02196] DefaultAzureCredential is the recommended approach for client applications and libraries to authenticate to Azure services
    }
}
