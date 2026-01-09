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
    /// Adds a validator to the validation pipeline.
    /// The verifier routes validators to stages using <see cref="IValidator.Stages"/>.
    /// </summary>
    /// <param name="validator">The validator to add.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validator"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when <paramref name="validator"/> does not specify valid stages.</exception>
    ICoseSign1ValidationBuilder AddValidator(IValidator validator);

    /// <summary>
    /// Overrides the default trust policy with a custom policy.
    /// When set, this policy replaces any default policies that would be provided
    /// by trust validators via <see cref="IProvidesDefaultTrustPolicy"/>.
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
    /// <exception cref="InvalidOperationException">Thrown when the builder does not include a signature validator.</exception>
    ICoseSign1Validator Build();
}
