// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Frontends;

using System.Collections.Generic;
using System.Text.Json.Nodes;

/// <summary>
/// The fact capabilities advertised to a frontend translator (D4). When supplied, the translator
/// validates fact references against <see cref="AvailableFactIds"/> and (optionally) validates
/// each predicate against the matching schema in <see cref="PredicateSchemas"/>.
/// </summary>
/// <remarks>
/// <para>
/// Per design decision D4, two surfaces are exposed: the id set lets the translator reject
/// unknown fact references early; the predicate schemas let it catch type-shape errors before
/// the policy reaches <see cref="CoseSign1.Validation.Trust.Engine.TrustFactEngine"/>.
/// </para>
/// <para>
/// <see cref="PredicateSchemas"/> are typed as <see cref="JsonNode"/> trees rather than the
/// validator-specific schema type so the frontend abstraction stays validator-agnostic. The
/// <c>cose-tp-json/v1</c> frontend lifts each entry into a <c>JsonSchema.Net</c> instance.
/// </para>
/// </remarks>
public sealed record FactCapabilities
{
    /// <summary>Gets the set of fact ids (e.g. <c>x509-chain-trusted/v1</c>) the host advertises.</summary>
    public required IReadOnlySet<string> AvailableFactIds { get; init; }

    /// <summary>
    /// Gets the optional per-fact predicate schemas. The dictionary key is the fact id and the
    /// value is the JSON Schema document (as a <see cref="JsonNode"/>) the predicate must match.
    /// </summary>
    public IReadOnlyDictionary<string, JsonNode>? PredicateSchemas { get; init; }
}
