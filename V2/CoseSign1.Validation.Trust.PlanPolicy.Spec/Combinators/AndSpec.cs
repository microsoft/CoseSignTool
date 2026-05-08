// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// Logical conjunction: all <see cref="Operands"/> must evaluate to trusted.
/// </summary>
public sealed record AndSpec : TrustPolicySpec
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AndSpec"/> class.
    /// </summary>
    /// <param name="operands">Child operands. May be empty (vacuously trusted).</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="operands"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when any element of <paramref name="operands"/> is null.</exception>
    [JsonConstructor]
    public AndSpec(IReadOnlyList<TrustPolicySpec> operands)
    {
        Cose.Abstractions.Guard.ThrowIfNull(operands);
        if (operands.Any(o => o is null))
        {
            throw new ArgumentException(ClassStrings.ErrAndOperandsNull, nameof(operands));
        }

        Operands = operands;
    }

    /// <summary>Gets the child operands.</summary>
    [JsonPropertyName(ClassStrings.PropertyOperands)]
    [JsonPropertyOrder(1)]
    public IReadOnlyList<TrustPolicySpec> Operands { get; init; }
}
