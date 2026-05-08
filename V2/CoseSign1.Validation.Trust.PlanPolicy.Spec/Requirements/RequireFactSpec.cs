// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;

using System;
using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;

/// <summary>
/// A leaf requirement: at least one available fact value of the type identified by
/// <see cref="FactTypeId"/> must satisfy <see cref="Predicate"/>; otherwise the requirement is
/// denied with <see cref="FailureMessage"/>.
/// </summary>
/// <remarks>
/// The fact id is resolved against an <see cref="Registry.IFactRegistry"/> at compile time; an
/// unknown id raises <see cref="Diagnostics.TrustPolicyDiagnosticCodes.UnknownFactId"/>.
/// </remarks>
public sealed record RequireFactSpec : TrustPolicySpec
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RequireFactSpec"/> class.
    /// </summary>
    /// <param name="factTypeId">The stable fact identifier (e.g., <c>x509-chain-trusted/v1</c>).</param>
    /// <param name="predicate">The predicate the fact must satisfy.</param>
    /// <param name="failureMessage">Denial reason surfaced when no fact satisfies the predicate.</param>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="factTypeId"/> or <paramref name="failureMessage"/> is empty / whitespace.</exception>
    [JsonConstructor]
    public RequireFactSpec(string factTypeId, FactPredicateSpec predicate, string failureMessage)
    {
        Cose.Abstractions.Guard.ThrowIfNullOrWhiteSpace(factTypeId);
        Cose.Abstractions.Guard.ThrowIfNull(predicate);
        Cose.Abstractions.Guard.ThrowIfNullOrWhiteSpace(failureMessage);

        FactTypeId = factTypeId;
        Predicate = predicate;
        FailureMessage = failureMessage;
    }

    /// <summary>Gets the stable fact identifier resolved by an <see cref="Registry.IFactRegistry"/>.</summary>
    [JsonPropertyName(ClassStrings.PropertyFact)]
    [JsonPropertyOrder(1)]
    public string FactTypeId { get; init; }

    /// <summary>Gets the predicate the fact must satisfy.</summary>
    [JsonPropertyName(ClassStrings.PropertyPredicate)]
    [JsonPropertyOrder(2)]
    public FactPredicateSpec Predicate { get; init; }

    /// <summary>Gets the denial reason surfaced when no fact satisfies the predicate.</summary>
    [JsonPropertyName(ClassStrings.PropertyFailureMessage)]
    [JsonPropertyOrder(3)]
    public string FailureMessage { get; init; }
}
