// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance.Tests;

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;
using CoseSign1.Validation.Trust.Rules;

/// <summary>
/// Edge-case coverage for non-public helpers on
/// <see cref="FrontendConformanceTestBase{TDocument}"/>. The base class is generic and
/// abstract; we use a closed concrete instantiation purely to get at the internal static
/// helpers.
/// </summary>
[TestFixture]
public sealed class FrontendConformanceTestBaseInternalsTests
{
    private static RequireFactSpec MakeLeaf(string factId) =>
        new(factId, new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?> { ["x"] = JsonValue.Create(true) }), "fail");

    [Test]
    public void RenderDiagnostics_EmptyList_ReturnsNoneSentinel()
    {
        string text = FrontendConformanceTestBase<JsonDocument>.RenderDiagnostics(Array.Empty<TrustPolicyTranslationDiagnostic>());

        Assert.That(text, Does.Contain("none"));
    }

    [Test]
    public void RenderDiagnostics_NonEmpty_RendersSeverityCodeMessage()
    {
        var diag = new TrustPolicyTranslationDiagnostic
        {
            Severity = TrustPolicySeverity.Error,
            Code = "TPX999",
            Message = "synthetic",
            Location = null,
        };

        string text = FrontendConformanceTestBase<JsonDocument>.RenderDiagnostics(new[] { diag, diag });

        Assert.That(text, Does.Contain("TPX999"));
        Assert.That(text, Does.Contain("synthetic"));
        // Two diagnostics → list separator appears at least once.
        Assert.That(text, Does.Contain(";"));
    }

    [Test]
    public void FindFirstRequireFact_DirectLeafMatch_ReturnsLeaf()
    {
        var leaf = MakeLeaf("a/v1");

        var found = FrontendConformanceTestBase<JsonDocument>.FindFirstRequireFact(leaf, "a/v1");

        Assert.That(found, Is.SameAs(leaf));
    }

    [Test]
    public void FindFirstRequireFact_LeafIdMismatch_ReturnsNull()
    {
        var leaf = MakeLeaf("a/v1");

        var found = FrontendConformanceTestBase<JsonDocument>.FindFirstRequireFact(leaf, "b/v1");

        Assert.That(found, Is.Null);
    }

    [Test]
    public void FindFirstRequireFact_WalksMessageRequirement()
    {
        var leaf = MakeLeaf("inside-message/v1");
        var spec = new MessageRequirementSpec(leaf);

        var found = FrontendConformanceTestBase<JsonDocument>.FindFirstRequireFact(spec, "inside-message/v1");

        Assert.That(found, Is.SameAs(leaf));
    }

    [Test]
    public void FindFirstRequireFact_WalksPrimarySigningKey()
    {
        var leaf = MakeLeaf("inside-psk/v1");
        var spec = new PrimarySigningKeyRequirementSpec(leaf);

        var found = FrontendConformanceTestBase<JsonDocument>.FindFirstRequireFact(spec, "inside-psk/v1");

        Assert.That(found, Is.SameAs(leaf));
    }

    [Test]
    public void FindFirstRequireFact_WalksAnyCounterSignature()
    {
        var leaf = MakeLeaf("inside-acs/v1");
        var spec = new AnyCounterSignatureRequirementSpec(leaf, OnEmptyBehavior.Deny);

        var found = FrontendConformanceTestBase<JsonDocument>.FindFirstRequireFact(spec, "inside-acs/v1");

        Assert.That(found, Is.SameAs(leaf));
    }

    [Test]
    public void FindFirstRequireFact_WalksAnd()
    {
        var leaf = MakeLeaf("inside-and/v1");
        var spec = new AndSpec(new TrustPolicySpec[] { MakeLeaf("other/v1"), leaf });

        var found = FrontendConformanceTestBase<JsonDocument>.FindFirstRequireFact(spec, "inside-and/v1");

        Assert.That(found, Is.SameAs(leaf));
    }

    [Test]
    public void FindFirstRequireFact_WalksOr()
    {
        var leaf = MakeLeaf("inside-or/v1");
        var spec = new OrSpec(new TrustPolicySpec[] { MakeLeaf("other/v1"), leaf });

        var found = FrontendConformanceTestBase<JsonDocument>.FindFirstRequireFact(spec, "inside-or/v1");

        Assert.That(found, Is.SameAs(leaf));
    }

    [Test]
    public void FindFirstRequireFact_WalksNot()
    {
        var leaf = MakeLeaf("inside-not/v1");
        var spec = new NotSpec(leaf);

        var found = FrontendConformanceTestBase<JsonDocument>.FindFirstRequireFact(spec, "inside-not/v1");

        Assert.That(found, Is.SameAs(leaf));
    }

    [Test]
    public void FindFirstRequireFact_WalksImpliesAntecedent()
    {
        var leaf = MakeLeaf("inside-antecedent/v1");
        var spec = new ImpliesSpec(leaf, MakeLeaf("other/v1"));

        var found = FrontendConformanceTestBase<JsonDocument>.FindFirstRequireFact(spec, "inside-antecedent/v1");

        Assert.That(found, Is.SameAs(leaf));
    }

    [Test]
    public void FindFirstRequireFact_WalksImpliesConsequent()
    {
        var leaf = MakeLeaf("inside-consequent/v1");
        var spec = new ImpliesSpec(MakeLeaf("other/v1"), leaf);

        var found = FrontendConformanceTestBase<JsonDocument>.FindFirstRequireFact(spec, "inside-consequent/v1");

        Assert.That(found, Is.SameAs(leaf));
    }

    [Test]
    public void FindFirstRequireFact_AllowAllSpec_ReturnsNullViaDefault()
    {
        var spec = new AllowAllSpec();

        var found = FrontendConformanceTestBase<JsonDocument>.FindFirstRequireFact(spec, "any/v1");

        Assert.That(found, Is.Null);
    }

    [Test]
    public void SyntheticMismatch_BoolFlips()
    {
        JsonNode result = FrontendConformanceTestBase<JsonDocument>.SyntheticMismatch(JsonValue.Create(true));

        Assert.That(((JsonValue)result).GetValue<bool>(), Is.False);
    }

    [Test]
    public void SyntheticMismatch_StringSuffixed()
    {
        JsonNode result = FrontendConformanceTestBase<JsonDocument>.SyntheticMismatch(JsonValue.Create("hello"));

        Assert.That(((JsonValue)result).GetValue<string>(), Does.StartWith("hello").And.Contain("__mismatch__"));
    }

    [Test]
    public void SyntheticMismatch_LongIncrements()
    {
        JsonNode result = FrontendConformanceTestBase<JsonDocument>.SyntheticMismatch(JsonValue.Create(7L));

        Assert.That(((JsonValue)result).GetValue<long>(), Is.EqualTo(8L));
    }

    [Test]
    public void SyntheticMismatch_DoubleIncrements()
    {
        JsonNode result = FrontendConformanceTestBase<JsonDocument>.SyntheticMismatch(JsonValue.Create(2.5));

        Assert.That(((JsonValue)result).GetValue<double>(), Is.EqualTo(3.5).Within(1e-9));
    }

    [Test]
    public void SyntheticMismatch_NullFallsBackToSentinel()
    {
        JsonNode result = FrontendConformanceTestBase<JsonDocument>.SyntheticMismatch(null);

        Assert.That(((JsonValue)result).GetValue<string>(), Is.EqualTo("__mismatch__"));
    }

    [Test]
    public void EvaluatePropertyForm_ArrayValue_UsesInSemantics()
    {
        var spec = new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
        {
            ["host"] = new JsonArray(JsonValue.Create("a"), JsonValue.Create("b")),
        });

        // Projection: hosts contains "a" → matches; hosts contains "z" → doesn't.
        JsonObject yes = new() { ["host"] = JsonValue.Create("a") };
        JsonObject no = new() { ["host"] = JsonValue.Create("z") };

        Assert.That(FrontendConformanceTestBase<JsonDocument>.EvaluatePropertyForm(spec, yes), Is.True);
        Assert.That(FrontendConformanceTestBase<JsonDocument>.EvaluatePropertyForm(spec, no), Is.False);
    }

    [Test]
    public void EvaluatePathOperatorForm_BadPathReturnsFalse()
    {
        var spec = new PathOperatorPredicateSpec("not-rooted", PredicateOperator.Equals, JsonValue.Create(true));
        JsonObject projection = new() { ["x"] = JsonValue.Create(true) };

        Assert.That(FrontendConformanceTestBase<JsonDocument>.EvaluatePathOperatorForm(spec, projection), Is.False);
    }

    [Test]
    public void EvaluatePathOperatorForm_Exists_TrueWhenPresent()
    {
        var spec = new PathOperatorPredicateSpec("$.x", PredicateOperator.Exists, null);

        Assert.That(FrontendConformanceTestBase<JsonDocument>.EvaluatePathOperatorForm(spec, new JsonObject { ["x"] = JsonValue.Create(true) }), Is.True);
        Assert.That(FrontendConformanceTestBase<JsonDocument>.EvaluatePathOperatorForm(spec, new JsonObject()), Is.False);
    }

    [Test]
    public void EvaluatePathOperatorForm_NotEquals_TrueWhenAbsentOrDifferent()
    {
        var spec = new PathOperatorPredicateSpec("$.x", PredicateOperator.NotEquals, JsonValue.Create(true));

        Assert.That(FrontendConformanceTestBase<JsonDocument>.EvaluatePathOperatorForm(spec, new JsonObject()), Is.True);
        Assert.That(FrontendConformanceTestBase<JsonDocument>.EvaluatePathOperatorForm(spec, new JsonObject { ["x"] = JsonValue.Create(false) }), Is.True);
        Assert.That(FrontendConformanceTestBase<JsonDocument>.EvaluatePathOperatorForm(spec, new JsonObject { ["x"] = JsonValue.Create(true) }), Is.False);
    }

    [Test]
    public void EvaluatePathOperatorForm_UnsupportedOperator_FailsAssertion()
    {
        var spec = new PathOperatorPredicateSpec("$.x", PredicateOperator.Contains, JsonValue.Create("y"));

        Assert.That(() => FrontendConformanceTestBase<JsonDocument>.EvaluatePathOperatorForm(spec, new JsonObject { ["x"] = JsonValue.Create("y") }), Throws.TypeOf<AssertionException>());
    }
}
