// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;

using System.Text.Json.Serialization;

using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// Source location attached to a spec node so diagnostics can point at the originating
/// document line/column even after parameter binding.
/// </summary>
/// <remarks>
/// Phase 1 emits no source locations on its own; the type is defined here so frontends in later
/// phases (cose-tp-json, cose-tp-rego) can populate it without forcing another schema bump.
/// </remarks>
/// <param name="Source">The frontend document URI or symbolic id (e.g. <c>file://policy.json</c>).</param>
/// <param name="Line">1-based line number of the construct in the source document.</param>
/// <param name="Column">1-based column number of the construct in the source document.</param>
/// <param name="Length">Length in source characters of the construct, when known.</param>
public sealed record SourceLocation(
    [property: JsonPropertyName(ClassStrings.PropertySource)] string? Source,
    [property: JsonPropertyName(ClassStrings.PropertyLine)] int Line,
    [property: JsonPropertyName(ClassStrings.PropertyColumn)] int Column,
    [property: JsonPropertyName(ClassStrings.PropertyLength)] int Length);
