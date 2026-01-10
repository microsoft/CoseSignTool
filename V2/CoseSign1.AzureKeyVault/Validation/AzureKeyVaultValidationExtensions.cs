// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Validation;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Builder for configuring Azure Key Vault trust validation.
/// </summary>
public interface IAzureKeyVaultValidatorBuilder
{
    /// <summary>
    /// Adds a trust validator that checks if the key identifier (kid) matches allowed Key Vault URI patterns.
    /// This enables trust policy evaluation based on which Key Vault the signing key came from.
    /// Emits <c>akv.key.detected</c> and <c>akv.kid.allowed</c> trust claims.
    /// </summary>
    /// <param name="allowedPatterns">
    /// Allowed Key Vault URI patterns. Supports:
    /// <list type="bullet">
    ///   <item><description>Exact URI: <c>https://myvault.vault.azure.net/keys/mykey</c></description></item>
    ///   <item><description>Vault wildcard: <c>https://myvault.vault.azure.net/keys/*</c></description></item>
    ///   <item><description>Full wildcard: <c>https://*.vault.azure.net/keys/*</c></description></item>
    ///   <item><description>Regex (prefix with <c>regex:</c>): <c>regex:https://.*\.vault\.azure\.net/keys/signing-.*</c></description></item>
    /// </list>
    /// </param>
    /// <returns>The builder instance.</returns>
    IAzureKeyVaultValidatorBuilder FromAllowedVaults(params string[] allowedPatterns);

    /// <summary>
    /// Adds a trust validator that emits <c>akv.key.detected</c> trust claim when the kid looks like an AKV key URI.
    /// Use this when you want to verify AKV signatures without restricting to specific vaults.
    /// </summary>
    /// <returns>The builder instance.</returns>
    IAzureKeyVaultValidatorBuilder RequireAzureKeyVaultOrigin();
}

/// <summary>
/// Extension methods for adding Azure Key Vault trust validation.
/// </summary>
public static class AzureKeyVaultValidationExtensions
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ObsoleteUseValidateAzureKeyVault = "Use ValidateAzureKeyVault instead for consistent fluent API.";
    }

    /// <summary>
    /// Adds the Azure Key Vault trust validator configured via a fluent builder.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="configure">Callback to configure Azure Key Vault trust validation.</param>
    /// <returns>The validation builder.</returns>
    /// <example>
    /// <code>
    /// var validator = Cose.Sign1Message()
    ///     .ValidateAzureKeyVault(akv => akv
    ///         .FromAllowedVaults("https://myvault.vault.azure.net/keys/*"))
    ///     .Build();
    /// </code>
    /// </example>
    public static ICoseSign1ValidationBuilder ValidateAzureKeyVault(
        this ICoseSign1ValidationBuilder builder,
        Action<IAzureKeyVaultValidatorBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var b = new Builder();
        configure(b);

        var trustValidator = b.BuildTrustValidator();
        if (trustValidator != null)
        {
            builder.AddComponent(trustValidator);
        }

        return builder;
    }

    private sealed class Builder : IAzureKeyVaultValidatorBuilder
    {
        public List<string>? AllowedVaultPatterns { get; private set; }
        public bool AddTrustValidator { get; private set; }

        public IAzureKeyVaultValidatorBuilder FromAllowedVaults(params string[] allowedPatterns)
        {
            AllowedVaultPatterns = allowedPatterns?.ToList() ?? new List<string>();
            AddTrustValidator = true;
            return this;
        }

        public IAzureKeyVaultValidatorBuilder RequireAzureKeyVaultOrigin()
        {
            AddTrustValidator = true;
            return this;
        }

        public AzureKeyVaultAssertionProvider? BuildTrustValidator()
        {
            if (!AddTrustValidator)
            {
                return null;
            }

            return new AzureKeyVaultAssertionProvider(AllowedVaultPatterns, requireAzureKeyVaultKey: true);
        }
    }
}
