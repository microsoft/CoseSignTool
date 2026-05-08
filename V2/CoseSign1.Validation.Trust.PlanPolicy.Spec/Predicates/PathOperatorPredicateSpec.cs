// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;

using System;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// Universal path+operator predicate. Available for every registered fact via reflection-based
/// lowering — no per-fact predicate schema is required for this form.
/// </summary>
/// <remarks>
/// <para>
/// The path is a constrained JSONPath subset: <c>$</c> selects the fact's JSON projection root;
/// <c>$.PropertyName</c> selects a property on the projection; chained property accessors and
/// integer index accessors (<c>$.list[0]</c>) are allowed. Wildcards, descendants, filter
/// expressions, and slices are intentionally NOT supported — they would expose untyped
/// iteration that the translator is required to forbid (§6.5.4 #6).
/// </para>
/// <para>
/// The <see cref="Value"/> position MAY be a <see cref="Parameters.ParameterRef"/> wire
/// representation; the binder pass replaces those before <see cref="Compilation.TrustPolicySpecCompiler.Compile"/>
/// runs.
/// </para>
/// </remarks>
public sealed record PathOperatorPredicateSpec : FactPredicateSpec
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PathOperatorPredicateSpec"/> class.
    /// </summary>
    /// <param name="path">A constrained JSONPath expression rooted at the fact's JSON projection.</param>
    /// <param name="operator">The comparison operator applied at the resolved path.</param>
    /// <param name="value">
    /// The literal predicate value, or <see langword="null"/> for operators that take no value
    /// (notably <see cref="PredicateOperator.Exists"/>). May be a parameter-ref shape; see
    /// <see cref="Parameters.ParameterRef"/>.
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="path"/> is null.</exception>
    [JsonConstructor]
    public PathOperatorPredicateSpec(string path, PredicateOperator @operator, JsonNode? value)
    {
        Cose.Abstractions.Guard.ThrowIfNull(path);

        Path = path;
        Operator = @operator;
        Value = value;
    }

    /// <summary>Gets the constrained JSONPath expression rooted at the fact's JSON projection.</summary>
    [JsonPropertyName(ClassStrings.PropertyPath)]
    [JsonPropertyOrder(1)]
    public string Path { get; init; }

    /// <summary>Gets the comparison operator applied at the resolved path.</summary>
    [JsonPropertyName(ClassStrings.PropertyOperator)]
    [JsonPropertyOrder(2)]
    public PredicateOperator Operator { get; init; }

    /// <summary>Gets the literal predicate value (may be a parameter-ref shape).</summary>
    [JsonPropertyName(ClassStrings.PropertyValue)]
    [JsonPropertyOrder(3)]
    public JsonNode? Value { get; init; }
}
