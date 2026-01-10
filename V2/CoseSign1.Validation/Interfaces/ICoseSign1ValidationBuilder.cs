// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using CoseSign1.Validation.Builders;
using Microsoft.Extensions.Logging;

/// <summary>
/// Builder for constructing a staged COSE Sign1 validation pipeline.
/// </summary>
/// <remarks>
/// This builder composes stage-specific validators and a <see cref="TrustPolicy"/>.
/// It defaults to deny-by-default trust unless overridden.
/// </remarks>
public interface ICoseSign1ValidationBuilder
{
    /// <summary>
    /// Gets the logger factory for creating loggers in validators.
    /// May be null if logging is not configured.
    /// </summary>
    ILoggerFactory? LoggerFactory { get; }

    /// <summary>
    /// Gets the current builder context (for advanced scenarios).
    /// </summary>
    ValidationBuilderContext Context { get; }

    /// <summary>
    /// Adds a validation component to the validation pipeline.
    /// Components are filtered by type internally:
    /// <list type="bullet">
    /// <item><description><see cref="ISigningKeyResolver"/> for key resolution</description></item>
    /// <item><description><see cref="ISigningKeyAssertionProvider"/> for trust assertions</description></item>
    /// <item><description><see cref="IPostSignatureValidator"/> for post-signature policy</description></item>
    /// </list>
    /// Signature verification is performed internally using the resolved signing key.
    /// </summary>
    /// <param name="component">The component to add.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="component"/> is null.</exception>
    ICoseSign1ValidationBuilder AddComponent(IValidationComponent component);

    /// <summary>
    /// Configures validation options using an options object.
    /// </summary>
    /// <remarks>
    /// This is the preferred method for configuring validation options as it provides
    /// a single, comprehensive configuration point. The options object can be configured
    /// using fluent extension methods from <see cref="CoseSign1ValidationOptionsExtensions"/>.
    /// <example>
    /// <code>
    /// builder.WithOptions(new CoseSign1ValidationOptions()
    ///     .WithDetachedPayload(payloadStream)
    ///     .WithAssociatedData(associatedData)
    ///     .WithCancellationToken(cancellationToken));
    /// </code>
    /// </example>
    /// </remarks>
    /// <param name="options">The validation options.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    ICoseSign1ValidationBuilder WithOptions(CoseSign1ValidationOptions options);

    /// <summary>
    /// Configures validation options using an action delegate.
    /// </summary>
    /// <remarks>
    /// <example>
    /// <code>
    /// builder.WithOptions(opts => opts
    ///     .WithDetachedPayload(payloadStream));
    /// </code>
    /// </example>
    /// </remarks>
    /// <param name="configure">The configuration action.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configure"/> is null.</exception>
    ICoseSign1ValidationBuilder WithOptions(Action<CoseSign1ValidationOptions> configure);

    /// <summary>
    /// Overrides the default trust policy with a custom policy.
    /// When set, this policy replaces the automatic aggregation of default policies
    /// from assertions extracted at validation time.
    /// </summary>
    /// <remarks>
    /// Use this when you want explicit control over trust evaluation.
    /// If you need to combine multiple policies, use <see cref="TrustPolicy.And"/>
    /// or <see cref="TrustPolicy.Or"/> to compose them before calling this method.
    /// </remarks>
    /// <param name="policy">The trust policy to use.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="policy"/> is null.</exception>
    ICoseSign1ValidationBuilder OverrideDefaultTrustPolicy(TrustPolicy policy);

    /// <summary>
    /// Sets trust policy to allow all.
    /// </summary>
    /// <param name="reason">Optional reason describing why all trust is allowed.</param>
    /// <returns>The same builder instance.</returns>
    ICoseSign1ValidationBuilder AllowAllTrust(string? reason = null);

    /// <summary>
    /// Sets trust policy to deny all.
    /// </summary>
    /// <param name="reason">Optional reason describing why all trust is denied.</param>
    /// <returns>The same builder instance.</returns>
    ICoseSign1ValidationBuilder DenyAllTrust(string? reason = null);

    /// <summary>
    /// Builds a reusable validator instance.
    /// </summary>
    /// <returns>A validator instance.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the builder does not include a signing key resolver.</exception>
    ICoseSign1Validator Build();
}
