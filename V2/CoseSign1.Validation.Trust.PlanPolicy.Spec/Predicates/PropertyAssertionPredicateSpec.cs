// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;

using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// Per-fact property-assertion sugar (D1 hybrid). Each entry asserts that the named property on
/// the fact is structurally equal to the supplied JSON value (or <see cref="PredicateOperator.In"/>
/// when the value is an array).
/// </summary>
/// <remarks>
/// <para>
/// The translator may emit this form when the fact publishes a typed predicate schema; it MUST
/// emit <see cref="PathOperatorPredicateSpec"/> as the universal fallback otherwise. Whichever
/// form is chosen, the compiled <see cref="CoseSign1.Validation.Trust.Rules.TrustRule"/> evaluates
/// identically.
/// </para>
/// <para>
/// Values may be parameter-ref shapes; the binder pass replaces them before compilation.
/// </para>
/// </remarks>
public sealed record PropertyAssertionPredicateSpec : FactPredicateSpec
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PropertyAssertionPredicateSpec"/> class.
    /// </summary>
    /// <param name="assertions">The property-name → expected-value map. The map order is preserved
    /// for diagnostics, but the canonical-JSON serializer emits keys in lexicographic order so
    /// the IR's content hash is order-independent.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="assertions"/> is null.</exception>
    [JsonConstructor]
    public PropertyAssertionPredicateSpec(IReadOnlyDictionary<string, JsonNode?> assertions)
    {
        Cose.Abstractions.Guard.ThrowIfNull(assertions);

        Assertions = assertions;
    }

    /// <summary>Gets the property-name → expected-value map.</summary>
    [JsonPropertyName(ClassStrings.PropertyAssertions)]
    [JsonPropertyOrder(1)]
    public IReadOnlyDictionary<string, JsonNode?> Assertions { get; init; }
}
