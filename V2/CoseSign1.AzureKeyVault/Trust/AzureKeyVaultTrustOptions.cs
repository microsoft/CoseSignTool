// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Trust;

/// <summary>
/// Configuration options for the Azure Key Vault trust pack.
/// </summary>
public sealed class AzureKeyVaultTrustOptions
{
    /// <summary>
    /// When true, the trust pack will only use offline/previously cached information.
    /// Placeholder option until AKV trust rules/facts are implemented.
    /// </summary>
    public bool OfflineOnly { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the message must contain a Key Vault key identifier (kid)
    /// that appears to be an Azure Key Vault key URI.
    /// </summary>
    public bool RequireAzureKeyVaultKid { get; set; }

    /// <summary>
    /// Gets or sets the allowed kid patterns.
    /// </summary>
    /// <remarks>
    /// Patterns may be glob-like (supports <c>*</c> and <c>?</c>) or may be prefixed with <c>regex:</c>
    /// to specify a raw regular expression.
    /// </remarks>
    public IReadOnlyList<string> AllowedKidPatterns { get; set; } = Array.Empty<string>();
}
