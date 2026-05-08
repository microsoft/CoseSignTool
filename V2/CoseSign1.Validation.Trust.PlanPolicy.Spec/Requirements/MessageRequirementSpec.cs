// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;

using System;
using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// A requirement evaluated against the <c>Message</c> trust-subject scope. The wrapped
/// <see cref="Inner"/> spec is composed of <see cref="RequireFactSpec"/> nodes and combinators;
/// it MUST NOT contain other <c>*RequirementSpec</c> nodes — the requirement scope is set by
/// the wrapping requirement, not by nesting.
/// </summary>
/// <remarks>
/// Mirrors the existing fluent surface <see cref="CoseSign1.Validation.Trust.TrustPlanPolicy.Message"/>.
/// </remarks>
public sealed record MessageRequirementSpec : TrustPolicySpec
{
    /// <summary>
    /// Initializes a new instance of the <see cref="MessageRequirementSpec"/> class.
    /// </summary>
    /// <param name="inner">Inner spec evaluated against the message subject.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="inner"/> is null.</exception>
    [JsonConstructor]
    public MessageRequirementSpec(TrustPolicySpec inner)
    {
        Cose.Abstractions.Guard.ThrowIfNull(inner);

        Inner = inner;
    }

    /// <summary>Gets the inner spec evaluated against the message subject.</summary>
    [JsonPropertyName(ClassStrings.PropertyInner)]
    [JsonPropertyOrder(1)]
    public TrustPolicySpec Inner { get; init; }
}
