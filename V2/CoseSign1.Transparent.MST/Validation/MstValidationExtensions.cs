// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Validation;

using System.Diagnostics.CodeAnalysis;
using Azure.Security.CodeTransparency;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Builder for configuring MST (Merkle Search Tree) transparency validators in a fluent way.
/// </summary>
public interface IMstValidatorBuilder
{
    /// <summary>
    /// Adds a validator that validates receipts using a CodeTransparency client.
    /// This performs offline validation using cached or embedded signing keys.
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

    /// <summary>
    /// Adds a validator that performs online receipt verification by querying the
    /// transparency service for its current signing keys before validating.
    /// </summary>
    /// <param name="client">The Azure Code Transparency client.</param>
    /// <param name="issuerHost">The issuer host name for key association.</param>
    /// <returns>The same builder instance.</returns>
    IMstValidatorBuilder VerifyReceiptOnline(CodeTransparencyClient client, string issuerHost);

    /// <summary>
    /// Adds a trust validator that checks for the presence of an MST receipt.
    /// Does not verify receipt validity, only presence.
    /// Emits a <see cref="MstReceiptPresentAssertion"/> assertion.
    /// </summary>
    /// <returns>The same builder instance.</returns>
    IMstValidatorBuilder RequireReceiptPresence();
}

/// <summary>
/// Extension methods for adding MST transparency validators to the COSE validation builder.
/// </summary>
public static class MstValidationExtensions
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorNoMstValidatorsConfigured = "No MST validators configured";
        public const string ObsoleteUseValidateMst = "Use ValidateMst instead for consistent fluent API naming.";
    }

    /// <summary>
    /// Adds MST transparency validators configured via a fluent builder.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="configure">The configuration callback.</param>
    /// <returns>The same validation builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configure"/> is null.</exception>
    /// <example>
    /// <code>
    /// var validator = new CoseSign1ValidationBuilder()
    ///     .ValidateMst(mst => mst
    ///         .RequireReceiptPresence()
    ///         .VerifyReceipt(client))
    ///     .OverrideDefaultTrustPolicy(MstTrustPolicies.RequireReceiptPresentAndTrusted())
    ///     .Build();
    /// </code>
    /// </example>
    public static ICoseSign1ValidationBuilder ValidateMst(
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
            builder.AddComponent(v);
        }

        return builder;
    }

    /// <summary>
    /// Adds MST validators configured via a domain-specific builder.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="configure">The configuration callback.</param>
    /// <returns>The same validation builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configure"/> is null.</exception>
    [Obsolete(ClassStrings.ObsoleteUseValidateMst)]
    public static ICoseSign1ValidationBuilder AddMstValidator(
        this ICoseSign1ValidationBuilder builder,
        Action<IMstValidatorBuilder> configure)
    {
        return ValidateMst(builder, configure);
    }

    private sealed class Builder : IMstValidatorBuilder
    {
        private readonly List<IValidationComponent> Validators = new();

        public IMstValidatorBuilder VerifyReceipt(CodeTransparencyClient client)
        {
            Validators.Add(new MstReceiptAssertionProvider(client ?? throw new ArgumentNullException(nameof(client))));
            return this;
        }

        public IMstValidatorBuilder VerifyReceipt(MstTransparencyProvider provider)
        {
            Validators.Add(new MstReceiptAssertionProvider(provider ?? throw new ArgumentNullException(nameof(provider))));
            return this;
        }

        public IMstValidatorBuilder VerifyReceiptOnline(CodeTransparencyClient client, string issuerHost)
        {
            if (client == null)
            {
                throw new ArgumentNullException(nameof(client));
            }

            if (string.IsNullOrWhiteSpace(issuerHost))
            {
                throw new ArgumentNullException(nameof(issuerHost));
            }

            Validators.Add(new MstReceiptOnlineAssertionProvider(client, issuerHost));
            return this;
        }

        public IMstValidatorBuilder RequireReceiptPresence()
        {
            Validators.Add(new MstReceiptPresenceAssertionProvider());
            return this;
        }

        public IReadOnlyList<IValidationComponent> BuildValidators()
        {
            if (Validators.Count == 0)
            {
                throw new InvalidOperationException(ClassStrings.ErrorNoMstValidatorsConfigured);
            }

            return Validators;
        }
    }
}
