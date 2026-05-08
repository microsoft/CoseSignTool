// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance.Tests;

using System;
using System.Linq;

[TestFixture]
public sealed class ConformanceFixtureNamingTests
{
    [Test]
    public void FactFixtureName_PropertyForm_ProducesUnderscoreSeparatedFileSafeName()
    {
        string actual = ConformanceFixtureNaming.FactFixtureName("x509-chain-trusted/v1", ConformanceFixtureNaming.PropertyFormSuffix);

        Assert.That(actual, Is.EqualTo("facts/x509-chain-trusted_v1.property"));
    }

    [Test]
    public void FactFixtureName_PathOperatorForm_ProducesPathOperatorSuffix()
    {
        string actual = ConformanceFixtureNaming.FactFixtureName("mst-receipt-trusted/v1", ConformanceFixtureNaming.PathOperatorFormSuffix);

        Assert.That(actual, Is.EqualTo("facts/mst-receipt-trusted_v1.path-operator"));
    }

    [Test]
    public void FactFixtureName_NullFactId_Throws()
    {
        Assert.That(() => ConformanceFixtureNaming.FactFixtureName(null!, ConformanceFixtureNaming.PropertyFormSuffix), Throws.ArgumentNullException);
    }

    [Test]
    public void FactFixtureName_NullForm_Throws()
    {
        Assert.That(() => ConformanceFixtureNaming.FactFixtureName("x/v1", null!), Throws.ArgumentNullException);
    }

    [Test]
    public void FixtureNameToFactId_PropertyForm_RecoversFactId()
    {
        string? actual = ConformanceFixtureNaming.FixtureNameToFactId("facts/x509-chain-trusted_v1.property");

        Assert.That(actual, Is.EqualTo("x509-chain-trusted/v1"));
    }

    [Test]
    public void FixtureNameToFactId_PathOperatorForm_RecoversFactId()
    {
        string? actual = ConformanceFixtureNaming.FixtureNameToFactId("facts/mst-receipt-trusted_v1.path-operator");

        Assert.That(actual, Is.EqualTo("mst-receipt-trusted/v1"));
    }

    [Test]
    public void FixtureNameToFactId_NotAFactFixture_ReturnsNull()
    {
        Assert.That(ConformanceFixtureNaming.FixtureNameToFactId("untranslatable/free-text-search"), Is.Null);
    }

    [Test]
    public void FixtureNameToFactId_FactsPrefixNoSuffix_ReturnsNull()
    {
        Assert.That(ConformanceFixtureNaming.FixtureNameToFactId("facts/something-without-form-suffix"), Is.Null);
    }

    [Test]
    public void FixtureNameToFactId_NullName_Throws()
    {
        Assert.That(() => ConformanceFixtureNaming.FixtureNameToFactId(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void EnumerateRequiredFactFixtureNames_NullRegistry_Throws()
    {
        Assert.That(() => ConformanceFixtureNaming.EnumerateRequiredFactFixtureNames(null!).ToList(), Throws.ArgumentNullException);
    }

    [Test]
    public void EnumerateRequiredFactFixtureNames_EmitsTwoNamesPerRegisteredFact()
    {
        CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry.IFactRegistry registry = CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry.AttributeDrivenFactRegistry.FromLoadedAssemblies();
        int factCount = registry.AllFactIds.Count;

        var names = ConformanceFixtureNaming.EnumerateRequiredFactFixtureNames(registry).ToList();

        Assert.That(names.Count, Is.EqualTo(factCount * 2));
        Assert.That(names.Count(n => n.EndsWith(ConformanceFixtureNaming.PropertyFormSuffix, StringComparison.Ordinal)), Is.EqualTo(factCount));
        Assert.That(names.Count(n => n.EndsWith(ConformanceFixtureNaming.PathOperatorFormSuffix, StringComparison.Ordinal)), Is.EqualTo(factCount));
    }

    [Test]
    public void EnumerateRequiredSharedFixtureNames_IncludesAllCanonicalNames()
    {
        var names = ConformanceFixtureNaming.EnumerateRequiredSharedFixtureNames().ToList();

        // The canonical shared set has exactly 10 logical names per the contract; if the
        // contract grows we update this number deliberately.
        Assert.That(names.Count, Is.EqualTo(10));
        Assert.That(names, Contains.Item("perf/representative-1kb"));
        Assert.That(names, Contains.Item("cross/canonical-policy"));
    }
}
