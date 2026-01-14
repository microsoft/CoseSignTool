// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Trust;

/// <summary>
/// Builder for configuring the Azure Key Vault trust pack.
/// </summary>
public sealed class AzureKeyVaultTrustBuilder
{
    internal AzureKeyVaultTrustOptions Options { get; } = new();

    /// <summary>
    /// Requires that the message kid appears to be an Azure Key Vault key URI.
    /// </summary>
    /// <returns>The same builder instance.</returns>
    public AzureKeyVaultTrustBuilder RequireAzureKeyVaultKid()
    {
        Options.RequireAzureKeyVaultKid = true;
        return this;
    }

    /// <summary>
    /// Configures allowed kid patterns.
    /// </summary>
    /// <param name="patterns">Allowed patterns (glob or regex: prefix).</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="patterns"/> is null.</exception>
    public AzureKeyVaultTrustBuilder AllowKidPatterns(IEnumerable<string> patterns)
    {
        if (patterns == null)
        {
            throw new ArgumentNullException(nameof(patterns));
        }

        Options.AllowedKidPatterns = patterns.ToArray();
        return this;
    }

    /// <summary>
    /// Restricts the trust pack to offline-only behavior.
    /// </summary>
    /// <returns>The same builder instance.</returns>
    public AzureKeyVaultTrustBuilder OfflineOnly()
    {
        Options.OfflineOnly = true;
        return this;
    }
}
