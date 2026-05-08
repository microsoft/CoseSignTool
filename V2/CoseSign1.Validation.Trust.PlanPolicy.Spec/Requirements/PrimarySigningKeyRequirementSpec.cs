// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;

using System;
using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// A requirement evaluated against the primary-signing-key trust-subject scope. The wrapped
/// <see cref="Inner"/> spec is evaluated after the message subject is rewritten to its primary
/// signing key.
/// </summary>
public sealed record PrimarySigningKeyRequirementSpec : TrustPolicySpec
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PrimarySigningKeyRequirementSpec"/> class.
    /// </summary>
    /// <param name="inner">Inner spec evaluated against the primary-signing-key subject.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="inner"/> is null.</exception>
    [JsonConstructor]
    public PrimarySigningKeyRequirementSpec(TrustPolicySpec inner)
    {
        Cose.Abstractions.Guard.ThrowIfNull(inner);

        Inner = inner;
    }

    /// <summary>Gets the inner spec evaluated against the primary-signing-key subject.</summary>
    [JsonPropertyName(ClassStrings.PropertyInner)]
    [JsonPropertyOrder(1)]
    public TrustPolicySpec Inner { get; init; }
}
