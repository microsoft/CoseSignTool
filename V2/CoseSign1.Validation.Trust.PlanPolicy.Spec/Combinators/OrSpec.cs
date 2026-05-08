// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// Logical disjunction: at least one of <see cref="Operands"/> must evaluate to trusted.
/// </summary>
public sealed record OrSpec : TrustPolicySpec
{
    /// <summary>
    /// Initializes a new instance of the <see cref="OrSpec"/> class.
    /// </summary>
    /// <param name="operands">Child operands. May be empty (denied per <see cref="CoseSign1.Validation.Trust.Rules.TrustRules"/> semantics).</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="operands"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when any element of <paramref name="operands"/> is null.</exception>
    [JsonConstructor]
    public OrSpec(IReadOnlyList<TrustPolicySpec> operands)
    {
        Cose.Abstractions.Guard.ThrowIfNull(operands);
        if (operands.Any(o => o is null))
        {
            throw new ArgumentException(ClassStrings.ErrOrOperandsNull, nameof(operands));
        }

        Operands = operands;
    }

    /// <summary>Gets the child operands.</summary>
    [JsonPropertyName(ClassStrings.PropertyOperands)]
    [JsonPropertyOrder(1)]
    public IReadOnlyList<TrustPolicySpec> Operands { get; init; }
}
