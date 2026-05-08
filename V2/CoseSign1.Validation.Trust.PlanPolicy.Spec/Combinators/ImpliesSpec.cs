// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;

using System;
using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// Logical implication: when <see cref="Antecedent"/> evaluates to trusted, the result is the
/// evaluation of <see cref="Consequent"/>; when <see cref="Antecedent"/> is denied, the result
/// is trusted (vacuously). Mirrors <see cref="CoseSign1.Validation.Trust.Rules.TrustRules.Implies"/>.
/// </summary>
public sealed record ImpliesSpec : TrustPolicySpec
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ImpliesSpec"/> class.
    /// </summary>
    /// <param name="antecedent">The antecedent.</param>
    /// <param name="consequent">The consequent.</param>
    /// <exception cref="ArgumentNullException">Thrown when either parameter is null.</exception>
    [JsonConstructor]
    public ImpliesSpec(TrustPolicySpec antecedent, TrustPolicySpec consequent)
    {
        Cose.Abstractions.Guard.ThrowIfNull(antecedent);
        Cose.Abstractions.Guard.ThrowIfNull(consequent);

        Antecedent = antecedent;
        Consequent = consequent;
    }

    /// <summary>Gets the antecedent.</summary>
    [JsonPropertyName(ClassStrings.PropertyAntecedent)]
    [JsonPropertyOrder(1)]
    public TrustPolicySpec Antecedent { get; init; }

    /// <summary>Gets the consequent.</summary>
    [JsonPropertyName(ClassStrings.PropertyConsequent)]
    [JsonPropertyOrder(2)]
    public TrustPolicySpec Consequent { get; init; }
}
