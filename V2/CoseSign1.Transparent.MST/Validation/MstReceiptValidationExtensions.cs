// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Security.CodeTransparency;
using CoseSign1.Validation;

namespace CoseSign1.Transparent.MST.Validation;

/// <summary>
/// Builder for configuring MST receipt validation.
/// Intended to be used via <c>Cose.Sign1Message().AddMstReceiptValidator(b =&gt; ...)</c>.
/// </summary>
public interface IMstReceiptValidatorBuilder
{
    /// <summary>
    /// Uses a CodeTransparency client to validate receipts.
    /// </summary>
    IMstReceiptValidatorBuilder UseClient(CodeTransparencyClient client);

    /// <summary>
    /// Uses a pre-configured transparency provider.
    /// </summary>
    IMstReceiptValidatorBuilder UseProvider(MstTransparencyProvider provider);

    /// <summary>
    /// Configures verification options (requires a client via <see cref="UseClient"/>).
    /// </summary>
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
    public static ICoseMessageValidationBuilder AddMstReceiptValidator(
        this ICoseMessageValidationBuilder builder,
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
                throw new InvalidOperationException("MST receipt validation requires either a provider or a client.");
            }

            if (VerificationOptions == null)
            {
                return new MstReceiptValidator(Client);
            }

            return new MstReceiptValidator(Client, VerificationOptions, ClientOptions);
        }
    }
}
