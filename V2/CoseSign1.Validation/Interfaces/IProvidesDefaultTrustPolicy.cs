// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using CoseSign1.Validation.Builders;

/// <summary>
/// Implemented by trust-stage validators that emit trust assertions and can provide a safe default
/// <see cref="TrustPolicy"/> that should be required when the validator is used.
/// </summary>
public interface IProvidesDefaultTrustPolicy
{
    /// <summary>
    /// Gets the default trust policy associated with this validator.
    /// Callers can override this via builder APIs.
    /// </summary>
    /// <param name="context">The current validation builder context.</param>
    /// <returns>The default trust policy.</returns>
    TrustPolicy GetDefaultTrustPolicy(ValidationBuilderContext context);
}
