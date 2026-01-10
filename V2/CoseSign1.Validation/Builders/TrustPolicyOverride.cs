// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Builders;

using CoseSign1.Validation.Interfaces;

internal sealed class TrustPolicyOverride
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustPolicyOverride"/> class.
    /// </summary>
    /// <param name="component">The component whose default trust policy is being overridden.</param>
    /// <param name="policy">The override policy.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="component"/> or <paramref name="policy"/> is null.</exception>
    public TrustPolicyOverride(IValidationComponent component, TrustPolicy policy)
    {
        Component = component ?? throw new ArgumentNullException(nameof(component));
        Policy = policy ?? throw new ArgumentNullException(nameof(policy));
    }

    public IValidationComponent Component { get; }

    public TrustPolicy Policy { get; }
}
