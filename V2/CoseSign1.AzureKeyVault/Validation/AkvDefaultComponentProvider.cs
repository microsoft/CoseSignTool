// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Validation;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Validation.Abstractions;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;

/// <summary>
/// Provides default Azure Key Vault validation components for auto-discovery.
/// </summary>
/// <remarks>
/// <para>
/// This provider supplies AKV key detection and basic validation:
/// <list type="bullet">
/// <item><description><see cref="AzureKeyVaultAssertionProvider"/> - Detects AKV keys and emits presence assertions</description></item>
/// </list>
/// </para>
/// <para>
/// The default configuration accepts ANY valid Azure Key Vault key URI. This is intentionally
/// permissive to enable detection. For production scenarios requiring specific vaults or keys,
/// use the builder pattern to configure <see cref="AzureKeyVaultAssertionProvider"/> with
/// explicit allowed patterns.
/// </para>
/// </remarks>
/// <example>
/// For stricter validation, configure explicitly:
/// <code>
/// var validator = new CoseSign1ValidationBuilder()
///     .AddComponent(new AzureKeyVaultAssertionProvider(
///         allowedPatterns: new[] { "https://my-vault.vault.azure.net/keys/*" }))
///     .Build();
/// </code>
/// </example>
public sealed class AkvDefaultComponentProvider : IDefaultValidationComponentProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        /// <summary>
        /// Wildcard pattern that matches any Azure Key Vault key URI.
        /// </summary>
        public const string AnyAkvKeyPattern = "https://*.vault.azure.net/keys/*";
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Priority 150 places AKV components after core certificate validation (100)
    /// but before transparency providers (200).
    /// </remarks>
    public int Priority => 150;

    /// <inheritdoc/>
    public IEnumerable<IValidationComponent> GetDefaultComponents(ILoggerFactory? loggerFactory)
    {
        // AKV key detection with permissive default (any AKV key is "allowed" for detection purposes)
        // Trust policy can enforce specific requirements
        yield return new AzureKeyVaultAssertionProvider(
            allowedPatterns: new[] { ClassStrings.AnyAkvKeyPattern },
            requireAzureKeyVaultKey: true);
    }
}
