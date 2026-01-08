// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using CoseSign1.Validation.Builders;

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
    /// Adds a trust requirement that must be satisfied.
    /// Multiple calls are combined with AND.
    /// </summary>
    /// <param name="policy">The required trust policy.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="policy"/> is null.</exception>
    ICoseSign1ValidationBuilder RequireTrust(TrustPolicy policy);

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
