// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Frontends;

using System.Collections.Generic;
using System.Text.Json.Nodes;

/// <summary>
/// Inputs supplied to <see cref="ICoseTrustPolicyFrontend{TDocument}.Translate"/> alongside the
/// parsed document.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Parameters"/> carries host-supplied values for <c>$param</c> references; per
/// design decision D5 the parameter substitution pass runs on the produced
/// <see cref="CoseSign1.Validation.Trust.PlanPolicy.Spec.TrustPolicySpec"/>, never as a string
/// macro pre-pass over the document.
/// </para>
/// <para>
/// When <see cref="AvailableFacts"/> is non-null and <see cref="AllowUnknownFacts"/> is
/// <see langword="false"/> the translator MUST reject any fact id missing from
/// <see cref="FactCapabilities.AvailableFactIds"/> with a <c>TPX200</c> diagnostic per §6.5.4 #5.
/// </para>
/// </remarks>
public sealed record TrustPolicyTranslationContext
{
    /// <summary>Gets host-supplied parameter values applied by the post-translate Bind pass.</summary>
    public IReadOnlyDictionary<string, JsonNode> Parameters { get; init; } = EmptyParameters;

    /// <summary>Gets the optional fact capability surface used to gate fact references.</summary>
    public FactCapabilities? AvailableFacts { get; init; }

    /// <summary>
    /// Gets a value indicating whether unknown fact ids are tolerated. When <see langword="false"/>
    /// (default) and <see cref="AvailableFacts"/> is supplied, references to unrecognised ids
    /// produce <c>TPX200</c> errors.
    /// </summary>
    public bool AllowUnknownFacts { get; init; }

    private static readonly IReadOnlyDictionary<string, JsonNode> EmptyParameters =
        new Dictionary<string, JsonNode>();
}
