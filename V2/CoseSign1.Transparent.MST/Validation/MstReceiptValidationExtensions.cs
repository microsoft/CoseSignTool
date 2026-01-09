// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Validation;

using Azure.Security.CodeTransparency;
using System.Diagnostics.CodeAnalysis;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Builder for configuring MST receipt validation.
/// Intended to be used via <c>Cose.Sign1Message().AddMstReceiptValidator(b =&gt; ...)</c>.
/// </summary>
public interface IMstReceiptValidatorBuilder
{
    /// <summary>
    /// Uses a CodeTransparency client to validate receipts.
    /// </summary>
    /// <param name="client">The Azure Code Transparency client.</param>
    /// <returns>The same builder instance.</returns>
    IMstReceiptValidatorBuilder UseClient(CodeTransparencyClient client);

    /// <summary>
    /// Uses a pre-configured transparency provider.
    /// </summary>
    /// <param name="provider">The MST transparency provider.</param>
    /// <returns>The same builder instance.</returns>
    IMstReceiptValidatorBuilder UseProvider(MstTransparencyProvider provider);

    /// <summary>
    /// Configures verification options (requires a client via <see cref="UseClient"/>).
    /// </summary>
    /// <param name="options">The verification options.</param>
    /// <param name="clientOptions">Optional client options for configuring client instances used during verification.</param>
    /// <returns>The same builder instance.</returns>
    IMstReceiptValidatorBuilder WithVerificationOptions(
        CodeTransparencyVerificationOptions options,
        CodeTransparencyClientOptions? clientOptions = null);
}

/// <summary>
/// Extension methods for adding MST receipt validation.
/// </summary>
public static class MstReceiptValidationExtensions
{
    /// <summary>
    /// Adds an MST receipt validator configured via a domain-specific builder.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="configure">The configuration callback.</param>
    /// <returns>The same validation builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configure"/> is null.</exception>
    public static ICoseSign1ValidationBuilder AddMstReceiptValidator(
        this ICoseSign1ValidationBuilder builder,
        Action<IMstReceiptValidatorBuilder> configure)
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

        return builder.AddValidator(b.Build());
    }

    private sealed class Builder : IMstReceiptValidatorBuilder
    {
        private CodeTransparencyClient? Client;
        private MstTransparencyProvider? Provider;
        private CodeTransparencyVerificationOptions? VerificationOptions;
        private CodeTransparencyClientOptions? ClientOptions;

        public IMstReceiptValidatorBuilder UseClient(CodeTransparencyClient client)
        {
            Client = client ?? throw new ArgumentNullException(nameof(client));
            Provider = null;
            return this;
        }

        public IMstReceiptValidatorBuilder UseProvider(MstTransparencyProvider provider)
        {
            Provider = provider ?? throw new ArgumentNullException(nameof(provider));
            Client = null;
            VerificationOptions = null;
            ClientOptions = null;
            return this;
        }

        public IMstReceiptValidatorBuilder WithVerificationOptions(CodeTransparencyVerificationOptions options, CodeTransparencyClientOptions? clientOptions = null)
        {
            VerificationOptions = options ?? throw new ArgumentNullException(nameof(options));
            ClientOptions = clientOptions;
            return this;
        }

        public MstReceiptValidator Build()
        {
            if (Provider != null)
            {
                return new MstReceiptValidator(Provider);
            }

            if (Client == null)
            {
                throw new InvalidOperationException(ClassStrings.ErrorMstReceiptValidationRequiresProviderOrClient);
            }

            if (VerificationOptions == null)
            {
                return new MstReceiptValidator(Client);
            }

            return new MstReceiptValidator(Client, VerificationOptions, ClientOptions);
        }

        [ExcludeFromCodeCoverage]
        internal static class ClassStrings
        {
            public const string ErrorMstReceiptValidationRequiresProviderOrClient = "MST receipt validation requires either a provider or a client.";
        }
    }
}
