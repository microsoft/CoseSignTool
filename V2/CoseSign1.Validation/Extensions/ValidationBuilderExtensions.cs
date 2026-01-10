// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Extensions;

using CoseSign1.Validation.Builders;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.PostSignature;

/// <summary>
/// Convenience extension methods for composing validation pipelines.
/// </summary>
public static class ValidationBuilderExtensions
{
    private const string TrustPolicyOverridesKey = ClassStrings.TrustPolicyOverridesKey;

    /// <summary>
    /// Adds an assertion provider and a corresponding trust requirement.
    /// This is the recommended pattern when a provider emits trust assertions and you want the verifier
    /// to require those assertions.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="provider">The assertion provider to add.</param>
    /// <param name="requiredPolicy">The trust policy requirement associated with the provider.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/>, <paramref name="provider"/>, or <paramref name="requiredPolicy"/> is null.</exception>
    public static ICoseSign1ValidationBuilder AddAssertionProvider(
        this ICoseSign1ValidationBuilder builder,
        ISigningKeyAssertionProvider provider,
        TrustPolicy requiredPolicy)
    {
        if (builder == null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (provider == null)
        {
            throw new ArgumentNullException(nameof(provider));
        }

        if (requiredPolicy == null)
        {
            throw new ArgumentNullException(nameof(requiredPolicy));
        }

        builder.AddComponent(provider);

        // Treat this as an override of any default policy the provider may contribute.
        if (!builder.Context.Properties.TryGetValue(TrustPolicyOverridesKey, out var value) || value is not List<TrustPolicyOverride> list)
        {
            list = new List<TrustPolicyOverride>();
            builder.Context.Properties[TrustPolicyOverridesKey] = list;
        }

        list.Add(new TrustPolicyOverride(provider, requiredPolicy));
        return builder;
    }

    /// <summary>
    /// Disables automatic indirect signature validation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// By default, the validation pipeline automatically includes an <see cref="IndirectSignatureValidator"/>
    /// that verifies payload hashes for indirect signature formats:
    /// </para>
    /// <list type="bullet">
    /// <item><description><b>COSE Hash Envelope (RFC 9054)</b> - Uses PayloadHashAlg header</description></item>
    /// <item><description><b>COSE Hash V</b> - Uses +cose-hash-v content-type extension</description></item>
    /// <item><description><b>Content-Type Hash Extension</b> - Uses +hash-sha256 style extensions</description></item>
    /// </list>
    /// <para>
    /// Call this method to disable that automatic validation. This is useful when you only want
    /// to verify the cryptographic signature without validating the payload hash.
    /// </para>
    /// <example>
    /// <code>
    /// // Signature-only validation (no payload hash verification)
    /// var validator = CoseSign1Message.CreateValidator()
    ///     .AddComponent(keyResolver)
    ///     .WithoutContentVerification()
    ///     .Build();
    /// </code>
    /// </example>
    /// </remarks>
    /// <param name="builder">The validation builder.</param>
    /// <returns>The same builder instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    public static ICoseSign1ValidationBuilder WithoutContentVerification(
        this ICoseSign1ValidationBuilder builder)
    {
        if (builder == null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        // Call the builder's method to set the flag
        if (builder is CoseSign1ValidationBuilder concreteBuilder)
        {
            concreteBuilder.WithoutContentVerification();
        }

        return builder;
    }

    internal static class ClassStrings
    {
        public const string TrustPolicyOverridesKey = "CoseSign1.Validation.TrustPolicyOverrides";
    }
}
