// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Validation;

namespace CoseSignTool.AzureKeyVault.Plugin;

/// <summary>
/// Builder for configuring Azure Key Vault key-only signature validation.
/// </summary>
public interface IAzureKeyVaultSignatureValidatorBuilder
{
    /// <summary>
    /// Supplies a detached payload for verifying detached COSE_Sign1 messages.
    /// If not set, detached messages will fail validation.
    /// </summary>
    IAzureKeyVaultSignatureValidatorBuilder WithDetachedPayload(ReadOnlyMemory<byte> detachedPayload);

    /// <summary>
    /// Clears any detached payload.
    /// </summary>
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
    public static ICoseMessageValidationBuilder AddAzureKeyVaultSignatureValidator(
        this ICoseMessageValidationBuilder builder,
        Action<IAzureKeyVaultSignatureValidatorBuilder> configure)
    {
        if (builder == null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configure == null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

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
