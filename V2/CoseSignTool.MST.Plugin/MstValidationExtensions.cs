// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Security.CodeTransparency;
using System.Security.Cryptography.Cose;
using CoseSign1.Transparent.MST;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation;

namespace CoseSignTool.MST.Plugin;

/// <summary>
/// Builder for configuring MST-related validators in a fluent way.
/// </summary>
public interface IMstValidatorBuilder
{
    /// <summary>
    /// Adds a validator that requires an MST receipt to be present.
    /// </summary>
    IMstValidatorBuilder RequireReceiptPresence();

    /// <summary>
    /// Adds a validator that verifies receipts using a CodeTransparency client.
    /// </summary>
    IMstValidatorBuilder VerifyReceipt(CodeTransparencyClient client);

    /// <summary>
    /// Adds a validator that verifies receipts using a pre-configured provider.
    /// </summary>
    IMstValidatorBuilder VerifyReceipt(MstTransparencyProvider provider);
}

/// <summary>
/// Extension methods for adding MST plugin validators to the COSE validation builder.
/// </summary>
public static class MstValidationExtensions
{
    /// <summary>
    /// Adds MST validators configured via a domain-specific builder.
    /// </summary>
    public static ICoseMessageValidationBuilder AddMstValidator(
        this ICoseMessageValidationBuilder builder,
        Action<IMstValidatorBuilder> configure)
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

        foreach (var v in b.BuildValidators())
        {
            builder.AddValidator(v);
        }

        return builder;
    }

    private sealed class Builder : IMstValidatorBuilder
    {
        private readonly List<IValidator<CoseSign1Message>> Validators = new();

        public IMstValidatorBuilder RequireReceiptPresence()
        {
            Validators.Add(new MstReceiptPresenceValidator());
            return this;
        }

        public IMstValidatorBuilder VerifyReceipt(CodeTransparencyClient client)
        {
            Validators.Add(new MstReceiptValidator(client ?? throw new ArgumentNullException(nameof(client))));
            return this;
        }

        public IMstValidatorBuilder VerifyReceipt(MstTransparencyProvider provider)
        {
            Validators.Add(new MstReceiptValidator(provider ?? throw new ArgumentNullException(nameof(provider))));
            return this;
        }

        public IReadOnlyList<IValidator<CoseSign1Message>> BuildValidators()
        {
            if (Validators.Count == 0)
            {
                throw new InvalidOperationException("No MST validators configured");
            }

            return Validators;
        }
    }
}
