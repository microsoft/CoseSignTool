// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance;

using System.Collections.Generic;
using CoseSign1.Validation.Trust.Frontends;

/// <summary>
/// The seam between <see cref="FrontendConformanceTestBase{TDocument}"/> and a concrete
/// frontend. Frontend test projects implement this interface to advertise the frontend under
/// test, the fixtures it ships, and the parsing pipeline. The conformance base class is
/// otherwise frontend-agnostic — every property of §6.5.10 routes through the adapter.
/// </summary>
/// <typeparam name="TDocument">The parsed document type the frontend accepts (e.g.
/// <c>JsonDocument</c> for cose-tp-json/v1, <c>RegoDocument</c> for cose-tp-rego/v1).</typeparam>
/// <remarks>
/// <para>
/// Why an adapter rather than a templated test class with abstract methods? Adapter pattern
/// keeps the conformance test logic in a single class and lets the cross-frontend equivalence
/// harness (§6.5.10 #8) hold heterogeneous adapters in a list — a degree of freedom the
/// inheritance-only design doesn't give us.
/// </para>
/// <para>
/// Implementors MUST guarantee:
/// <list type="bullet">
///   <item><see cref="FrontendId"/> is the stable id (e.g. <c>cose-tp-json/v1</c>).</item>
///   <item><see cref="LoadFixture"/> returns a non-null parsed document for every name in
///         <see cref="ProvidedFixtureNames"/> AND for every fact-id-derived name (see
///         <see cref="ConformanceFixtureNaming"/>).</item>
///   <item><see cref="Translate"/> is pure — invoking it twice with equal inputs MUST produce
///         byte-identical canonical specs (§6.5.10 #1).</item>
///   <item>The frontend MUST NOT throw on malformed input; failures surface as Error
///         diagnostics in the returned <see cref="TrustPolicyTranslationResult"/> per §6.5.4 #2
///         (totality).</item>
/// </list>
/// </para>
/// </remarks>
public interface IConformanceFrontendAdapter<TDocument>
{
    /// <summary>Gets the frontend's stable identifier (e.g. <c>cose-tp-json/v1</c>).</summary>
    string FrontendId { get; }

    /// <summary>
    /// Gets the set of logical fixture names this adapter can resolve. The base test class
    /// asserts every required canonical name (defined in <see cref="ConformanceFixtureNaming"/>)
    /// appears here; missing names are surfaced as test failures, not silently skipped.
    /// </summary>
    IReadOnlySet<string> ProvidedFixtureNames { get; }

    /// <summary>
    /// Loads a parsed document by logical fixture name. Returns <see langword="null"/> when the
    /// adapter chose to ship the fixture as raw text only (e.g. malformed-JSON fixtures) — in
    /// which case the caller MUST use <see cref="LoadFixtureText"/> instead.
    /// </summary>
    /// <param name="name">The logical fixture name.</param>
    /// <returns>The parsed document, or <see langword="null"/> when the fixture is text-only.</returns>
    TDocument? LoadFixture(string name);

    /// <summary>
    /// Loads a fixture as raw UTF-8 text. Used by §6.5.10 #7 schema-validation tests where the
    /// fixture is intentionally malformed and would not pass a parse step.
    /// </summary>
    /// <param name="name">The logical fixture name.</param>
    /// <returns>The raw fixture text.</returns>
    string LoadFixtureText(string name);

    /// <summary>
    /// Translates a previously-loaded document into a <see cref="TrustPolicyTranslationResult"/>.
    /// </summary>
    /// <param name="document">The document returned by <see cref="LoadFixture"/>.</param>
    /// <param name="ctx">The translation context.</param>
    /// <returns>The translation result.</returns>
    TrustPolicyTranslationResult Translate(TDocument document, TrustPolicyTranslationContext ctx);

    /// <summary>
    /// Translates raw fixture text directly. Frontends route through their text-entry overload
    /// (e.g. <c>CoseTpJsonFrontend.TranslateText</c>) so malformed input still produces a
    /// <see cref="TrustPolicyTranslationResult"/> rather than throwing.
    /// </summary>
    /// <param name="fixtureText">The raw fixture text.</param>
    /// <param name="ctx">The translation context.</param>
    /// <returns>The translation result.</returns>
    TrustPolicyTranslationResult TranslateText(string fixtureText, TrustPolicyTranslationContext ctx);
}
