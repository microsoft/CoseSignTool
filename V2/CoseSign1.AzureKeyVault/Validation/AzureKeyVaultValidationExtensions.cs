// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Validation;

using System.Diagnostics.CodeAnalysis;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Builder for configuring Azure Key Vault key-only signature validation.
/// </summary>
public interface IAzureKeyVaultValidatorBuilder
{
    /// <summary>
    /// Supplies a detached payload for verifying detached COSE_Sign1 messages.
    /// If not set, detached messages will fail validation.
    /// </summary>
    /// <param name="detachedPayload">The detached payload bytes.</param>
    /// <returns>The builder instance.</returns>
    IAzureKeyVaultValidatorBuilder WithDetachedPayload(ReadOnlyMemory<byte> detachedPayload);

    /// <summary>
    /// Supplies a detached payload for verifying detached COSE_Sign1 messages.
    /// If not set, detached messages will fail validation.
    /// </summary>
    /// <param name="detachedPayload">The detached payload bytes.</param>
    /// <returns>The builder instance.</returns>
    IAzureKeyVaultValidatorBuilder WithDetachedPayload(byte[] detachedPayload);

    /// <summary>
    /// Requires the signature to be an Azure Key Vault key-only signature.
    /// When enabled, messages without the expected AKV headers will fail validation.
    /// </summary>
    /// <returns>The builder instance.</returns>
    IAzureKeyVaultValidatorBuilder RequireAzureKey();

    /// <summary>
    /// Allows the validator to make network calls to Azure Key Vault when needed
    /// to retrieve the public key for verification (e.g., when kid doesn't match embedded COSE_Key).
    /// </summary>
    /// <returns>The builder instance.</returns>
    IAzureKeyVaultValidatorBuilder AllowOnlineVerify();

    /// <summary>
    /// Configures the Azure credential used for online key retrieval.
    /// Only used when <see cref="AllowOnlineVerify"/> is enabled.
    /// </summary>
    /// <param name="credential">The Azure credential.</param>
    /// <returns>The builder instance.</returns>
    IAzureKeyVaultValidatorBuilder WithCredential(TokenCredential credential);

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
/// Extension methods for adding Azure Key Vault key-only signature validation.
/// </summary>
public static class AzureKeyVaultValidationExtensions
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ObsoleteUseValidateAzureKeyVault = "Use ValidateAzureKeyVault instead for consistent fluent API.";
        public const string ObsoleteUseIAzureKeyVaultValidatorBuilder = "Use IAzureKeyVaultValidatorBuilder instead.";
    }

    /// <summary>
    /// Adds the Azure Key Vault signature validator configured via a fluent builder.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="configure">Callback to configure Azure Key Vault validation.</param>
    /// <returns>The validation builder.</returns>
    /// <example>
    /// <code>
    /// var validator = Cose.Sign1Message()
    ///     .ValidateAzureKeyVault(akv => akv
    ///         .RequireAzureKey()
    ///         .AllowOnlineVerify()
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

        builder.AddValidator(b.BuildSignatureValidator());

        var trustValidator = b.BuildTrustValidator();
        if (trustValidator != null)
        {
            builder.AddValidator(trustValidator);
        }

        return builder;
    }

    /// <summary>
    /// Adds the Azure Key Vault signature validator configured via a fluent builder.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="detachedPayload">The detached payload bytes for detached signatures.</param>
    /// <param name="configure">Callback to configure Azure Key Vault validation.</param>
    /// <returns>The validation builder.</returns>
    public static ICoseSign1ValidationBuilder ValidateAzureKeyVault(
        this ICoseSign1ValidationBuilder builder,
        byte[] detachedPayload,
        Action<IAzureKeyVaultValidatorBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(detachedPayload);
        ArgumentNullException.ThrowIfNull(configure);

        var b = new Builder();
        b.WithDetachedPayload(detachedPayload);
        configure(b);

        builder.AddValidator(b.BuildSignatureValidator());

        var trustValidator = b.BuildTrustValidator();
        if (trustValidator != null)
        {
            builder.AddValidator(trustValidator);
        }

        return builder;
    }

    /// <summary>
    /// Adds the Azure Key Vault signature validator configured via a fluent builder.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="detachedPayload">The detached payload bytes for detached signatures.</param>
    /// <param name="configure">Callback to configure Azure Key Vault validation.</param>
    /// <returns>The validation builder.</returns>
    public static ICoseSign1ValidationBuilder ValidateAzureKeyVault(
        this ICoseSign1ValidationBuilder builder,
        ReadOnlyMemory<byte> detachedPayload,
        Action<IAzureKeyVaultValidatorBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var b = new Builder();
        b.WithDetachedPayload(detachedPayload);
        configure(b);

        builder.AddValidator(b.BuildSignatureValidator());

        var trustValidator = b.BuildTrustValidator();
        if (trustValidator != null)
        {
            builder.AddValidator(trustValidator);
        }

        return builder;
    }

    #region Legacy API

    /// <summary>
    /// Adds the Azure Key Vault signature validator configured via a domain-specific builder.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="configure">Callback to configure Azure Key Vault validation.</param>
    /// <returns>The validation builder.</returns>
    [Obsolete(ClassStrings.ObsoleteUseValidateAzureKeyVault)]
#pragma warning disable CS0618 // Type or member is obsolete - intentional for legacy support
    public static ICoseSign1ValidationBuilder AddAzureKeyVaultSignatureValidator(
        this ICoseSign1ValidationBuilder builder,
        Action<IAzureKeyVaultSignatureValidatorBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var b = new LegacyBuilder();
        configure(b);

        return builder.AddValidator(new AzureKeyVaultSignatureValidator(b.DetachedPayload));
    }
#pragma warning restore CS0618

    /// <summary>
    /// Legacy builder interface for backward compatibility.
    /// </summary>
    [Obsolete(ClassStrings.ObsoleteUseIAzureKeyVaultValidatorBuilder)]
    public interface IAzureKeyVaultSignatureValidatorBuilder
    {
        /// <summary>
        /// Supplies a detached payload for verifying detached COSE_Sign1 messages.
        /// </summary>
        /// <param name="detachedPayload">The detached payload bytes.</param>
        /// <returns>The builder instance.</returns>
        IAzureKeyVaultSignatureValidatorBuilder WithDetachedPayload(ReadOnlyMemory<byte> detachedPayload);

        /// <summary>
        /// Clears any detached payload.
        /// </summary>
        /// <returns>The builder instance.</returns>
        IAzureKeyVaultSignatureValidatorBuilder WithoutDetachedPayload();
    }

#pragma warning disable CS0618 // Type or member is obsolete - intentional for legacy support
    private sealed class LegacyBuilder : IAzureKeyVaultSignatureValidatorBuilder
    {
        public ReadOnlyMemory<byte>? DetachedPayload { get; private set; }

        public IAzureKeyVaultSignatureValidatorBuilder WithDetachedPayload(ReadOnlyMemory<byte> detachedPayload)
        {
            DetachedPayload = detachedPayload;
            return this;
        }

        public IAzureKeyVaultSignatureValidatorBuilder WithoutDetachedPayload()
        {
            DetachedPayload = null;
            return this;
        }
    }
#pragma warning restore CS0618

    #endregion

    private sealed class Builder : IAzureKeyVaultValidatorBuilder
    {
        public ReadOnlyMemory<byte>? DetachedPayload { get; private set; }
        public bool RequireAzureKeyFlag { get; private set; }
        public bool AllowOnlineVerifyFlag { get; private set; }
        public TokenCredential? Credential { get; private set; }
        public List<string>? AllowedVaultPatterns { get; private set; }
        public bool AddTrustValidator { get; private set; }

        public IAzureKeyVaultValidatorBuilder WithDetachedPayload(ReadOnlyMemory<byte> detachedPayload)
        {
            DetachedPayload = detachedPayload;
            return this;
        }

        public IAzureKeyVaultValidatorBuilder WithDetachedPayload(byte[] detachedPayload)
        {
            DetachedPayload = detachedPayload;
            return this;
        }

        public IAzureKeyVaultValidatorBuilder RequireAzureKey()
        {
            RequireAzureKeyFlag = true;
            return this;
        }

        public IAzureKeyVaultValidatorBuilder AllowOnlineVerify()
        {
            AllowOnlineVerifyFlag = true;
            return this;
        }

        public IAzureKeyVaultValidatorBuilder WithCredential(TokenCredential credential)
        {
            Credential = credential ?? throw new ArgumentNullException(nameof(credential));
            return this;
        }

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

        public AzureKeyVaultSignatureValidator BuildSignatureValidator()
        {
            if (Credential != null)
            {
                return new AzureKeyVaultSignatureValidator(
                    DetachedPayload,
                    RequireAzureKeyFlag,
                    AllowOnlineVerifyFlag,
                    Credential,
                    (uri, cred) => new KeyClient(uri, cred));
            }

            return new AzureKeyVaultSignatureValidator(
                DetachedPayload,
                RequireAzureKeyFlag,
                AllowOnlineVerifyFlag);
        }

        public AzureKeyVaultTrustValidator? BuildTrustValidator()
        {
            if (!AddTrustValidator)
            {
                return null;
            }

            return new AzureKeyVaultTrustValidator(AllowedVaultPatterns, requireAzureKeyVaultKey: true);
        }
    }
}
