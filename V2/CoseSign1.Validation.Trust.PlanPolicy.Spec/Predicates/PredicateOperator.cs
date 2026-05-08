// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;

/// <summary>
/// Operators usable in <see cref="PathOperatorPredicateSpec"/>. Mirrors the operator vocabulary
/// of §6.4.7's <c>ApplicationDataPredicate</c> so cross-frontend equivalence holds at the
/// translation contract level.
/// </summary>
public enum PredicateOperator
{
    /// <summary>The path resolves to a non-null JSON node.</summary>
    Exists,

    /// <summary>The resolved JSON value is structurally equal to the predicate value.</summary>
    Equals,

    /// <summary>The resolved JSON value is not structurally equal to the predicate value.</summary>
    NotEquals,

    /// <summary>The resolved JSON value is strictly less than the predicate value.</summary>
    LessThan,

    /// <summary>The resolved JSON value is less than or equal to the predicate value.</summary>
    LessThanOrEqual,

    /// <summary>The resolved JSON value is strictly greater than the predicate value.</summary>
    GreaterThan,

    /// <summary>The resolved JSON value is greater than or equal to the predicate value.</summary>
    GreaterThanOrEqual,

    /// <summary>The resolved JSON string value starts with the predicate string value.</summary>
    StartsWith,

    /// <summary>The resolved JSON string value ends with the predicate string value.</summary>
    EndsWith,

    /// <summary>The resolved value contains the predicate value: substring for strings, element-membership for arrays.</summary>
    Contains,

    /// <summary>The resolved value equals one of the elements in the predicate array value.</summary>
    In,
}
