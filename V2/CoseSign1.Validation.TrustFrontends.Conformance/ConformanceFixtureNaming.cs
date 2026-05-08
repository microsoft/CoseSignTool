// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance;

using System;
using System.Collections.Generic;
using System.Globalization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;

/// <summary>
/// Conventions for naming the conformance fixture set. Frontend authors construct fixture
/// file names by combining a fact id (or special category) with a predicate-form suffix —
/// the conformance suite resolves the same name across every registered frontend so the
/// cross-frontend equivalence test (§6.5.10 #8) lights up automatically.
/// </summary>
/// <remarks>
/// <para>
/// Naming rules:
/// <list type="bullet">
///   <item>Per-fact fixtures: <c>facts/&lt;fact-id-with-slashes-replaced&gt;.&lt;form&gt;</c>.
///         For example, fact id <c>x509-chain-trusted/v1</c> becomes the logical name
///         <c>facts/x509-chain-trusted_v1.property</c> for the property-shorthand form.
///         File extensions are frontend-defined (e.g. <c>.coseTrustPolicy.json</c>).</item>
///   <item>Untranslatable fixtures: <c>untranslatable/&lt;reason&gt;</c>.</item>
///   <item>Capability-gating fixtures: <c>capability/&lt;reason&gt;</c>.</item>
///   <item>Schema-failure fixtures: <c>schema/&lt;reason&gt;</c> — these may be raw text only.</item>
///   <item>Parametric fixtures: <c>parametric/&lt;name&gt;</c>.</item>
///   <item>Perf fixture: <c>perf/representative-1kb</c> — a single representative document the
///         §6.5.10 #4 perf gate evaluates against.</item>
/// </list>
/// </para>
/// <para>
/// Replacing <c>/</c> with <c>_</c> avoids file-system-illegal characters on Windows while
/// preserving the lossless mapping fact-id ↔ fixture-name. The reverse mapping (used for
/// diagnostics) substitutes back via <see cref="FixtureNameToFactId"/>.
/// </para>
/// </remarks>
public static class ConformanceFixtureNaming
{
    /// <summary>Logical-name segment separating folder from leaf.</summary>
    public const string FolderSeparator = AssemblyStrings.PathSeparator;

    /// <summary>Suffix appended to the per-fact name when targeting the property-shorthand form.</summary>
    public const string PropertyFormSuffix = AssemblyStrings.FixtureSuffixPropertyForm;

    /// <summary>Suffix appended to the per-fact name when targeting the path+operator universal form.</summary>
    public const string PathOperatorFormSuffix = AssemblyStrings.FixtureSuffixPathOperatorForm;

    /// <summary>
    /// Translates a fact id (e.g. <c>x509-chain-trusted/v1</c>) into the logical fixture name
    /// for the supplied predicate form. The fact id is escaped using a percent-encoding-like
    /// scheme on the slash separator: <c>/</c> becomes <c>--</c>. <c>--</c> is reserved as
    /// the escape sequence and never appears in a valid fact id (the id pattern
    /// <c>^[a-z][a-z0-9-]*\/v[0-9]+$</c> forbids consecutive hyphens), so the mapping is
    /// injective and the reverse parse in <see cref="FixtureNameToFactId"/> is deterministic.
    /// </summary>
    /// <param name="factId">The stable fact id.</param>
    /// <param name="form">Either <see cref="PropertyFormSuffix"/> or <see cref="PathOperatorFormSuffix"/>.</param>
    /// <returns>The logical fixture name.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="factId"/> or <paramref name="form"/> is null.</exception>
    public static string FactFixtureName(string factId, string form)
    {
        Cose.Abstractions.Guard.ThrowIfNull(factId);
        Cose.Abstractions.Guard.ThrowIfNull(form);

        // The fact-id pattern '^[a-z][a-z0-9-]*\/v[0-9]+$' allows a single '/' but never the
        // sequence '--'; escaping '/' to '--' is therefore reversible without ambiguity.
        // This avoids the brittleness of the prior '_' substitution, which would have
        // collided with any future fact id containing an underscore in its body.
        string fileSafe = factId.Replace(AssemblyStrings.FactIdSlashSeparator, AssemblyStrings.FactIdEscapedSlash);
        return string.Format(CultureInfo.InvariantCulture, AssemblyStrings.FormatFactFixtureNamePattern, AssemblyStrings.FactsFolder, fileSafe, form);
    }

    /// <summary>
    /// Reverses <see cref="FactFixtureName"/> for the supplied logical name. Returns
    /// <see langword="null"/> when the name is not a per-fact fixture.
    /// </summary>
    /// <param name="logicalName">The logical fixture name.</param>
    /// <returns>The fact id (with <c>--</c> decoded back to <c>/</c>) or <see langword="null"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="logicalName"/> is null.</exception>
    public static string? FixtureNameToFactId(string logicalName)
    {
        Cose.Abstractions.Guard.ThrowIfNull(logicalName);

        string factsPrefix = AssemblyStrings.FactsFolder + FolderSeparator;
        if (!logicalName.StartsWith(factsPrefix, StringComparison.Ordinal))
        {
            return null;
        }

        string trimmed = logicalName.Substring(factsPrefix.Length);
        string suffix = trimmed.EndsWith(PropertyFormSuffix, StringComparison.Ordinal)
            ? PropertyFormSuffix
            : trimmed.EndsWith(PathOperatorFormSuffix, StringComparison.Ordinal)
                ? PathOperatorFormSuffix
                : string.Empty;
        if (suffix.Length == 0)
        {
            return null;
        }

        string body = trimmed.Substring(0, trimmed.Length - suffix.Length);
        return body.Replace(AssemblyStrings.FactIdEscapedSlash, AssemblyStrings.FactIdSlashSeparator);
    }

    /// <summary>
    /// Yields the canonical set of per-fact fixture names the conformance suite expects every
    /// frontend to ship — both predicate forms for every id in <paramref name="registry"/>.
    /// </summary>
    /// <param name="registry">The fact registry the conformance suite drives off (see Phase 3).</param>
    /// <returns>Two logical names per registered fact id (property form then path+operator form).</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="registry"/> is null.</exception>
    public static IEnumerable<string> EnumerateRequiredFactFixtureNames(IFactRegistry registry)
    {
        Cose.Abstractions.Guard.ThrowIfNull(registry);

        foreach (string factId in registry.AllFactIds)
        {
            yield return FactFixtureName(factId, PropertyFormSuffix);
            yield return FactFixtureName(factId, PathOperatorFormSuffix);
        }
    }

    /// <summary>
    /// Yields the conformance categories' shared logical names the suite expects every
    /// frontend to provide (untranslatable, capability, schema, parametric, perf, cross).
    /// </summary>
    /// <returns>The shared logical names.</returns>
    public static IEnumerable<string> EnumerateRequiredSharedFixtureNames()
    {
        yield return AssemblyStrings.FixtureUntranslatableFreeText;
        yield return AssemblyStrings.FixtureUntranslatableUnknownFact;
        yield return AssemblyStrings.FixtureUntranslatableUnknownOperator;
        yield return AssemblyStrings.FixtureCapabilityMissingFact;
        yield return AssemblyStrings.FixtureSchemaMalformedJson;
        yield return AssemblyStrings.FixtureSchemaShapeViolation;
        yield return AssemblyStrings.FixtureParametricHostBaseline;
        yield return AssemblyStrings.FixtureParametricHostAlternate;
        yield return AssemblyStrings.FixturePerfRepresentative;
        yield return AssemblyStrings.FixtureCrossEquivalenceCanonical;
    }
}
