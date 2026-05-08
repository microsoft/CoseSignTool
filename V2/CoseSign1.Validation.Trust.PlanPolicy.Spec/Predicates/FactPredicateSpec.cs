// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;

using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;

/// <summary>
/// Base record for the hybrid fact-predicate language (D1).
/// </summary>
/// <remarks>
/// <para>
/// Two concrete subtypes are recognised: <see cref="PathOperatorPredicateSpec"/> (universal
/// path+operator form, available for every fact via reflection) and
/// <see cref="PropertyAssertionPredicateSpec"/> (per-fact property-shorthand sugar). They
/// can serialize differently but MUST evaluate identically once compiled — that invariant is
/// the conformance contract for the translator.
/// </para>
/// <para>
/// Discriminator field is <c>predicate_type</c> rather than <c>type</c> to avoid colliding with
/// the outer <see cref="TrustPolicySpec"/> discriminator on the same wire object.
/// </para>
/// </remarks>
[JsonPolymorphic(TypeDiscriminatorPropertyName = ClassStrings.PredicateDiscriminatorPropertyName)]
[JsonDerivedType(typeof(PathOperatorPredicateSpec), ClassStrings.DiscriminatorPathOperator)]
[JsonDerivedType(typeof(PropertyAssertionPredicateSpec), ClassStrings.DiscriminatorPropertyAssertion)]
public abstract record FactPredicateSpec
{
    /// <summary>
    /// Initializes a new instance of the <see cref="FactPredicateSpec"/> class.
    /// </summary>
    private protected FactPredicateSpec()
    {
    }

    /// <summary>
    /// Optional source location for diagnostics. Frontends populate this; Phase 1 leaves it null.
    /// </summary>
    [JsonPropertyName(ClassStrings.PropertyLocation)]
    [JsonPropertyOrder(1000)]
    public SourceLocation? Location { get; init; }
}
