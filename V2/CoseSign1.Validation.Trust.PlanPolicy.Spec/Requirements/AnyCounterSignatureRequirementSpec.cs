// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;

using System;
using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.Rules;

/// <summary>
/// A requirement satisfied when at least one counter-signature on the message satisfies
/// <see cref="Inner"/>. <see cref="OnEmpty"/> controls behaviour when the message has no
/// counter-signatures.
/// </summary>
public sealed record AnyCounterSignatureRequirementSpec : TrustPolicySpec
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AnyCounterSignatureRequirementSpec"/> class.
    /// </summary>
    /// <param name="inner">Inner spec evaluated for each candidate counter-signature.</param>
    /// <param name="onEmpty">Behaviour when no counter-signatures are present.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="inner"/> is null.</exception>
    [JsonConstructor]
    public AnyCounterSignatureRequirementSpec(TrustPolicySpec inner, OnEmptyBehavior onEmpty = OnEmptyBehavior.Deny)
    {
        Cose.Abstractions.Guard.ThrowIfNull(inner);

        Inner = inner;
        OnEmpty = onEmpty;
    }

    /// <summary>Gets the inner spec evaluated for each candidate counter-signature.</summary>
    [JsonPropertyName(ClassStrings.PropertyInner)]
    [JsonPropertyOrder(1)]
    public TrustPolicySpec Inner { get; init; }

    /// <summary>Gets the on-empty behaviour. Default is <see cref="OnEmptyBehavior.Deny"/>.</summary>
    [JsonPropertyName(ClassStrings.PropertyOnEmpty)]
    [JsonPropertyOrder(2)]
    public OnEmptyBehavior OnEmpty { get; init; }
}
