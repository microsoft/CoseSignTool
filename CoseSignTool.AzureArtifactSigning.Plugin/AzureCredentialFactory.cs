// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern alias IdentityAlias;

namespace CoseSignTool.AzureArtifactSigning.Plugin;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Azure.Core;
using DefaultAzureCredential = IdentityAlias::Azure.Identity.DefaultAzureCredential;
using DefaultAzureCredentialOptions = IdentityAlias::Azure.Identity.DefaultAzureCredentialOptions;
using Microsoft.Extensions.Configuration;

/// <summary>
/// Creates and caches the <see cref="TokenCredential"/> used to call Azure Artifact Signing.
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="DefaultAzureCredential"/> caches the tokens it acquires for its own lifetime, so
/// constructing a new one per signing operation throws that cache away and forces a fresh credential
/// probe and token request every time. Caching the credential instance here means repeated signings in
/// a single process reuse both the resolved credential chain and its tokens.
/// </para>
/// <para>
/// Credentials are cached per exclusion set, so callers asking for different exclusions do not share an
/// instance. Managed identity in particular is worth excluding on developer machines and on hosts where
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
    /// Caches one credential per distinct exclusion set.
    /// </summary>
    private static readonly ConcurrentDictionary<string, TokenCredential> CredentialCache = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the names that may be supplied to exclude a credential, in documentation order.
    /// </summary>
    public static IReadOnlyList<string> SupportedExclusionNames =>
        ExclusionSetters.Keys.Select(name => name + "Credential").OrderBy(name => name, StringComparer.Ordinal).ToList();

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

        List<string> exclusions = new();

        string? commandLineValue = configuration[ExcludeCredentialsKey];
        if (!string.IsNullOrWhiteSpace(commandLineValue))
        {
            exclusions.AddRange(commandLineValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }

        foreach (IConfigurationSection child in configuration.GetSection(ExcludeCredentialsSection).GetChildren())
        {
            if (!string.IsNullOrWhiteSpace(child.Value))
            {
                exclusions.Add(child.Value.Trim());
            }
        }

        return exclusions;
    }

    /// <summary>
    /// Gets a cached <see cref="TokenCredential"/> for the supplied exclusions, creating it on first use.
    /// </summary>
    /// <param name="excludeCredentials">
    /// Credentials to exclude from the chain. Names are case-insensitive and the trailing "Credential"
    /// is optional, so "ManagedIdentityCredential" and "managedidentity" are equivalent.
    /// </param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <returns>A credential shared by all callers requesting the same exclusion set.</returns>
    /// <exception cref="ArgumentException">Thrown when an exclusion name is not recognized.</exception>
    /// <example>
    /// <code>
    /// TokenCredential credential = AzureCredentialFactory.GetCredential(new[] { "ManagedIdentityCredential" }, logger);
    /// </code>
    /// </example>
    public static TokenCredential GetCredential(IEnumerable<string>? excludeCredentials, IPluginLogger? logger = null)
    {
        IReadOnlyList<string> normalized = NormalizeExclusions(excludeCredentials);
        string cacheKey = string.Join(",", normalized);

        if (CredentialCache.TryGetValue(cacheKey, out TokenCredential? cached))
        {
            logger?.LogVerbose("Reusing cached Azure credential.");
            return cached;
        }

        return CredentialCache.GetOrAdd(cacheKey, _ => CreateCredential(normalized, logger));
    }

    /// <summary>
    /// Clears the credential cache.
    /// </summary>
    /// <remarks>Intended for tests; production callers benefit from the cache living for the process lifetime.</remarks>
    public static void ClearCache()
    {
        CredentialCache.Clear();
    }

    /// <summary>
    /// Validates and canonicalizes the requested exclusion names.
    /// </summary>
    /// <param name="excludeCredentials">The raw exclusion names.</param>
    /// <returns>The canonical names, sorted and de-duplicated so equivalent requests share a cache entry.</returns>
    /// <exception cref="ArgumentException">Thrown when a name is not recognized.</exception>
    private static IReadOnlyList<string> NormalizeExclusions(IEnumerable<string>? excludeCredentials)
    {
        if (excludeCredentials is null)
        {
            return Array.Empty<string>();
        }

        SortedSet<string> normalized = new(StringComparer.Ordinal);

        foreach (string name in excludeCredentials)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            string candidate = name.Trim();
            if (candidate.EndsWith("Credential", StringComparison.OrdinalIgnoreCase))
            {
                candidate = candidate[..^"Credential".Length];
            }

            if (!ExclusionSetters.ContainsKey(candidate))
            {
                throw new ArgumentException(
                    $"'{name}' is not a recognized credential to exclude. Supported values are: {string.Join(", ", SupportedExclusionNames)}.",
                    nameof(excludeCredentials));
            }

            // Store the canonical casing from the lookup so cache keys are stable across input casings.
            normalized.Add(ExclusionSetters.Keys.First(key => string.Equals(key, candidate, StringComparison.OrdinalIgnoreCase)));
        }

        return normalized.ToList();
    }

    /// <summary>
    /// Creates a <see cref="DefaultAzureCredential"/> honoring the supplied exclusions.
    /// </summary>
    /// <param name="normalizedExclusions">The canonical exclusion names.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <returns>The new credential.</returns>
    private static TokenCredential CreateCredential(IReadOnlyList<string> normalizedExclusions, IPluginLogger? logger)
    {
        logger?.LogVerbose("Acquiring Azure credentials using DefaultAzureCredential...");

        DefaultAzureCredentialOptions options = new()
        {
            // Exclude interactive browser auth to avoid unexpected prompts in CI/CD.
            ExcludeInteractiveBrowserCredential = true
        };

        foreach (string exclusion in normalizedExclusions)
        {
            ExclusionSetters[exclusion](options);
            logger?.LogVerbose($"  Excluding {exclusion}Credential from the credential chain.");
        }

        return new DefaultAzureCredential(options); // CodeQL [SM02196] DefaultAzureCredential is the recommended approach for client applications and libraries to authenticate to Azure services
    }
}
