// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance.Tests;

using System.Linq;
using CoseSign1.Validation.Trust.Frontends;

/// <summary>
/// Rego-frontend-specific reject tests pinned to the conformance fixture set. The Rego
/// frontend doesn't inherit <see cref="FrontendConformanceTestBase{TDocument}"/> (the
/// hybrid path/operator form is JSON-specific per the README), so these tests assert the
/// reject contract directly against the on-disk fixtures.
/// </summary>
[TestFixture]
public sealed class RegoUntranslatableFixtureTests
{
    [TestCase("untranslatable/free-text-search")]
    [TestCase("untranslatable/unconstrained-iteration")]
    [TestCase("untranslatable/http-send")]
    public void Untranslatable_fixture_produces_TPX300_error(string logicalName)
    {
        var adapter = new RegoConformanceAdapter();
        Assert.That(adapter.ProvidedFixtureNames, Contains.Item(logicalName));

        TrustPolicyTranslationResult result = adapter.TranslateText(adapter.LoadFixtureText(logicalName), new TrustPolicyTranslationContext());

        Assert.That(result.IsSuccess, Is.False, $"Untranslatable fixture '{logicalName}' should be rejected.");
        Assert.That(result.Diagnostics.Any(d => d.Severity == TrustPolicySeverity.Error && d.Code == "TPX300"), Is.True, () =>
            "Diagnostics: " + string.Join("; ", result.Diagnostics.Select(d => d.Code + ":" + d.Message)));
    }

    [Test]
    public void RegoConformanceAdapter_FrontendId_is_canonical()
    {
        Assert.That(new RegoConformanceAdapter().FrontendId, Is.EqualTo("cose-tp-rego/v1"));
    }

    [Test]
    public void RegoConformanceAdapter_LoadFixture_returns_null_for_untranslatable_fixtures()
    {
        // The adapter lifts text into RegoDocument via TryParse; for untranslatable fixtures
        // TryParse fails, so LoadFixture returns null. Callers route through LoadFixtureText
        // + TranslateText in that case (the contract documented on IConformanceFrontendAdapter).
        var adapter = new RegoConformanceAdapter();
        Assert.That(adapter.LoadFixture("untranslatable/http-send"), Is.Null);
    }

    [Test]
    public void RegoConformanceAdapter_LoadFixture_returns_parsed_document_for_valid_fixture()
    {
        var adapter = new RegoConformanceAdapter();
        Assert.That(adapter.LoadFixture("cross/canonical-policy"), Is.Not.Null);
    }

    [Test]
    public void RegoConformanceAdapter_LoadFixtureText_throws_for_unknown_name()
    {
        var adapter = new RegoConformanceAdapter();
        Assert.Throws<System.IO.FileNotFoundException>(() => adapter.LoadFixtureText("does-not-exist"));
    }

    [Test]
    public void RegoConformanceAdapter_Translate_succeeds_for_valid_fixture()
    {
        var adapter = new RegoConformanceAdapter();
        var doc = adapter.LoadFixture("cross/canonical-policy")!;
        TrustPolicyTranslationResult result = adapter.Translate(doc, new TrustPolicyTranslationContext());
        Assert.That(result.IsSuccess, Is.True, () => string.Join("; ", result.Diagnostics.Select(d => d.Code + ":" + d.Message)));
    }
}
