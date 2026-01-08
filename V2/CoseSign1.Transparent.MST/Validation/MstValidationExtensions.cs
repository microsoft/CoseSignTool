// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using Azure.Security.CodeTransparency;
using CoseSign1.Validation.Interfaces;

namespace CoseSign1.Transparent.MST.Validation;

/// <summary>
/// Builder for configuring MST-related validators in a fluent way.
/// </summary>
public interface IMstValidatorBuilder
{
    /// <summary>
    /// Adds a validator that validates receipts using a CodeTransparency client.
    /// </summary>
    /// <param name="client">The Azure Code Transparency client.</param>
    /// <returns>The same builder instance.</returns>
    IMstValidatorBuilder VerifyReceipt(CodeTransparencyClient client);

    /// <summary>
    /// Adds a validator that validates receipts using a pre-configured provider.
    /// </summary>
    /// <param name="provider">The MST transparency provider.</param>
    /// <returns>The same builder instance.</returns>
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
    /// <param name="builder">The validation builder.</param>
    /// <param name="configure">The configuration callback.</param>
    /// <returns>The same validation builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configure"/> is null.</exception>
    public static ICoseSign1ValidationBuilder AddMstValidator(
        this ICoseSign1ValidationBuilder builder,
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
        private readonly List<IValidator> Validators = new();

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

        public IReadOnlyList<IValidator> BuildValidators()
        {
            if (Validators.Count == 0)
            {
                throw new InvalidOperationException(ClassStrings.ErrorNoMstValidatorsConfigured);
            }

            return Validators;
        }

        [ExcludeFromCodeCoverage]
        internal static class ClassStrings
        {
            public const string ErrorNoMstValidatorsConfigured = "No MST validators configured";
        }
    }
}
