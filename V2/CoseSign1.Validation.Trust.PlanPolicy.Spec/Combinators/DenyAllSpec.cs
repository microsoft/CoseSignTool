// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;

using System;
using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// Terminal: always denied. Mirrors <see cref="CoseSign1.Validation.Trust.Rules.TrustRules.DenyAll"/>.
/// </summary>
public sealed record DenyAllSpec : TrustPolicySpec
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DenyAllSpec"/> class.
    /// </summary>
    /// <param name="reason">The denial reason surfaced to consumers.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="reason"/> is null, empty, or whitespace.</exception>
    [JsonConstructor]
    public DenyAllSpec(string reason)
    {
        Cose.Abstractions.Guard.ThrowIfNullOrWhiteSpace(reason);

        Reason = reason;
    }

    /// <summary>Gets the denial reason surfaced to consumers.</summary>
    [JsonPropertyName(ClassStrings.PropertyReason)]
    [JsonPropertyOrder(1)]
    public string Reason { get; init; }
}
