// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Validation;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;
using CoseSign1.AzureKeyVault.Common;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Builder for configuring Azure Key Vault trust validation.
/// </summary>
public interface IAzureKeyVaultValidatorBuilder
{
    /// <summary>
    /// Adds a trust validator that checks if the key identifier (kid) matches allowed Key Vault URI patterns.
    /// This enables trust policy evaluation based on which Key Vault the signing key came from.
    /// Emits <see cref="AkvKeyDetectedAssertion"/> and <see cref="AkvKidAllowedAssertion"/> assertions.
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
    /// Adds a trust validator that emits an <see cref="AkvKeyDetectedAssertion"/> assertion when the kid looks like an AKV key URI.
    /// Use this when you want to verify AKV signatures without restricting to specific vaults.
    /// </summary>
    /// <returns>The builder instance.</returns>
    IAzureKeyVaultValidatorBuilder RequireAzureKeyVaultOrigin();

    /// <summary>
    /// Adds an online signing key resolver that fetches the public key from Azure Key Vault using the message kid header.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is optional. <see cref="AzureKeyVaultValidationExtensions.ValidateAzureKeyVault"/> always adds an offline resolver
    /// (<see cref="AzureKeyVaultCoseKeySigningKeyResolver"/>) that can verify signatures without contacting Key Vault when the signer
    /// embedded a COSE_Key.
    /// </para>
    /// </remarks>
    /// <param name="clientFactory">Key Vault client factory used to fetch key material.</param>
    /// <returns>The builder instance.</returns>
    IAzureKeyVaultValidatorBuilder WithOnlineKeyResolver(IKeyVaultClientFactory clientFactory);
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
    /// var validator = new CoseSign1ValidationBuilder()
    ///     // Requires at least one ISigningKeyResolver to verify the cryptographic signature.
    ///     .AddComponent(new CertificateSigningKeyResolver(certificateHeaderLocation: CoseHeaderLocation.Protected))
    ///     .ValidateAzureKeyVault(akv => akv
    ///         .FromAllowedVaults("https://myvault.vault.azure.net/keys/*"))
    ///     .Build();
    /// </code>
    /// </example>
    public static ICoseSign1ValidationBuilder ValidateAzureKeyVault(
        this ICoseSign1ValidationBuilder builder,
        Action<IAzureKeyVaultValidatorBuilder> configure)
    {
        Guard.ThrowIfNull(builder);
        Guard.ThrowIfNull(configure);

        // Azure Key Vault verification implies signing key resolution.
        // Prefer offline resolution via embedded COSE_Key when available.
        builder.AddComponent(new AzureKeyVaultCoseKeySigningKeyResolver());

        var b = new Builder();
        configure(b);

        var trustValidator = b.BuildTrustValidator();
        if (trustValidator != null)
        {
            builder.AddComponent(trustValidator);
        }

        var onlineResolver = b.BuildOnlineResolver();
        if (onlineResolver != null)
        {
            builder.AddComponent(onlineResolver);
        }

        return builder;
    }

    private sealed class Builder : IAzureKeyVaultValidatorBuilder
    {
        public List<string>? AllowedVaultPatterns { get; private set; }
        public bool AddTrustValidator { get; private set; }
        public IKeyVaultClientFactory? OnlineClientFactory { get; private set; }

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

        public IAzureKeyVaultValidatorBuilder WithOnlineKeyResolver(IKeyVaultClientFactory clientFactory)
        {
            Guard.ThrowIfNull(clientFactory);
            OnlineClientFactory = clientFactory;
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

        public AzureKeyVaultOnlineSigningKeyResolver? BuildOnlineResolver()
        {
            return OnlineClientFactory == null ? null : new AzureKeyVaultOnlineSigningKeyResolver(OnlineClientFactory);
        }
    }
}
