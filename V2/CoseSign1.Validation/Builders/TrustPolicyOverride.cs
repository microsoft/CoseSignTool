// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Builders;

using CoseSign1.Validation.Interfaces;

internal sealed class TrustPolicyOverride
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustPolicyOverride"/> class.
    /// </summary>
    /// <param name="validator">The validator whose default trust policy is being overridden.</param>
    /// <param name="policy">The override policy.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validator"/> or <paramref name="policy"/> is null.</exception>
    public TrustPolicyOverride(IValidator validator, TrustPolicy policy)
    {
        Validator = validator ?? throw new ArgumentNullException(nameof(validator));
        Policy = policy ?? throw new ArgumentNullException(nameof(policy));
    }

    public IValidator Validator { get; }

    public TrustPolicy Policy { get; }
}
