// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Validation.Interfaces;

namespace CoseSign1.AzureKeyVault.Validation;

/// <summary>
/// Builder for configuring Azure Key Vault key-only signature validation.
/// </summary>
public interface IAzureKeyVaultSignatureValidatorBuilder
{
    /// <summary>
    /// Supplies a detached payload for verifying detached COSE_Sign1 messages.
    /// If not set, detached messages will fail validation.
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

/// <summary>
/// Extension methods for adding Azure Key Vault key-only signature validation.
/// </summary>
public static class AzureKeyVaultValidationExtensions
{
    /// <summary>
    /// Adds the Azure Key Vault signature validator configured via a domain-specific builder.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="configure">Callback to configure Azure Key Vault validation.</param>
    /// <returns>The validation builder.</returns>
    public static ICoseSign1ValidationBuilder AddAzureKeyVaultSignatureValidator(
        this ICoseSign1ValidationBuilder builder,
        Action<IAzureKeyVaultSignatureValidatorBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var b = new Builder();
        configure(b);

        return builder.AddValidator(new AzureKeyVaultSignatureValidator(b.DetachedPayload));
    }

    private sealed class Builder : IAzureKeyVaultSignatureValidatorBuilder
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
}
