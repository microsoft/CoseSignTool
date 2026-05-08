// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;

using System;
using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// Logical negation: trusted when <see cref="Operand"/> is denied; denied when trusted.
/// </summary>
public sealed record NotSpec : TrustPolicySpec
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NotSpec"/> class.
    /// </summary>
    /// <param name="operand">The operand to negate.</param>
    /// <param name="reason">Optional denial reason surfaced when the operand evaluates to trusted.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="operand"/> is null.</exception>
    [JsonConstructor]
    public NotSpec(TrustPolicySpec operand, string? reason = null)
    {
        Cose.Abstractions.Guard.ThrowIfNull(operand);

        Operand = operand;
        Reason = reason;
    }

    /// <summary>Gets the operand to negate.</summary>
    [JsonPropertyName(ClassStrings.PropertyOperand)]
    [JsonPropertyOrder(1)]
    public TrustPolicySpec Operand { get; init; }

    /// <summary>Gets the optional denial reason surfaced when <see cref="Operand"/> evaluates to trusted.</summary>
    [JsonPropertyName(ClassStrings.PropertyReason)]
    [JsonPropertyOrder(2)]
    public string? Reason { get; init; }
}
