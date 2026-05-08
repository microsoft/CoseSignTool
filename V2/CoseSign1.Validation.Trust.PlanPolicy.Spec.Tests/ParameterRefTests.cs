// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Parameters;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;

/// <summary>
/// Tests for <see cref="ParameterRef"/> wire-shape detection, parsing, and binding.
/// </summary>
[TestFixture]
[Category("TrustPolicySpec")]
public sealed class ParameterRefTests
{
    [Test]
    public void IsParameterRef_DetectsMarker()
    {
        var node = new JsonObject { [ParameterRef.ParameterMarker] = "x" };
        Assert.That(ParameterRef.IsParameterRef(node), Is.True);
    }

    [Test]
    public void IsParameterRef_NonObject_ReturnsFalse()
    {
        Assert.That(ParameterRef.IsParameterRef(JsonValue.Create("not a ref")), Is.False);
        Assert.That(ParameterRef.IsParameterRef(null), Is.False);
        Assert.That(ParameterRef.IsParameterRef(new JsonObject()), Is.False);
    }

    [Test]
    public void TryParse_ValidShape_ReturnsParameterRef()
    {
        var defaultValue = new JsonArray("a", "b");
        var node = new JsonObject
        {
            [ParameterRef.ParameterMarker] = "trusted_hosts",
            [ParameterRef.DefaultProperty] = defaultValue.DeepClone(),
        };

        Assert.That(ParameterRef.TryParse(node, out var parsed), Is.True);
        Assert.That(parsed!.Name, Is.EqualTo("trusted_hosts"));
        Assert.That(parsed.Default, Is.Not.Null);
        Assert.That(parsed.Default!.AsArray(), Has.Count.EqualTo(2));
    }

    [Test]
    public void TryParse_NoDefault_ReturnsParameterRefWithNullDefault()
    {
        var node = new JsonObject { [ParameterRef.ParameterMarker] = "p" };
        Assert.That(ParameterRef.TryParse(node, out var parsed), Is.True);
        Assert.That(parsed!.Default, Is.Null);
    }

    [Test]
    public void TryParse_WhitespaceName_ReturnsFalse()
    {
        var node = new JsonObject { [ParameterRef.ParameterMarker] = "" };
        Assert.That(ParameterRef.TryParse(node, out _), Is.False);
    }

    [Test]
    public void TryParse_NonObject_ReturnsFalse()
    {
        Assert.That(ParameterRef.TryParse(JsonValue.Create(42), out _), Is.False);
    }

    [Test]
    public void TryParse_NameNonString_ReturnsFalse()
    {
        var node = new JsonObject { [ParameterRef.ParameterMarker] = JsonValue.Create(42) };
        Assert.That(ParameterRef.TryParse(node, out _), Is.False);
    }

    [Test]
    public void Constructor_NullName_Throws()
    {
        Assert.Throws<ArgumentException>(() => new ParameterRef(""));
    }

    [Test]
    public void ToJsonNode_RoundTrips_CarriesDefault()
    {
        var p = new ParameterRef("size", JsonValue.Create(1024));
        JsonObject node = p.ToJsonNode();
        Assert.That(ParameterRef.TryParse(node, out var rehydrated), Is.True);
        Assert.That(rehydrated!.Name, Is.EqualTo("size"));
        Assert.That(rehydrated.Default!.GetValue<int>(), Is.EqualTo(1024));
    }

    [Test]
    public void ToJsonNode_NoDefault_OmitsDefaultKey()
    {
        var p = new ParameterRef("size");
        JsonObject node = p.ToJsonNode();
        Assert.That(node.ContainsKey(ParameterRef.DefaultProperty), Is.False);
    }

    [Test]
    public void Bind_ReplacesParameterRefWithBinding()
    {
        var node = new JsonObject
        {
            ["operator"] = "in",
            ["value"] = new ParameterRef("hosts").ToJsonNode(),
        };

        var bindings = new Dictionary<string, JsonNode?>
        {
            ["hosts"] = new JsonArray("foo.com", "bar.com"),
        };

        JsonNode? bound = ParameterRef.Bind(node, bindings);
        Assert.That(bound, Is.Not.Null);
        Assert.That(bound!["value"]!.AsArray(), Has.Count.EqualTo(2));
    }

    [Test]
    public void Bind_FallsBackToDefault_WhenNoBinding()
    {
        var node = new ParameterRef("hosts", new JsonArray("default.com")).ToJsonNode();
        JsonNode? bound = ParameterRef.Bind(node, new Dictionary<string, JsonNode?>());
        Assert.That(bound!.AsArray()[0]!.GetValue<string>(), Is.EqualTo("default.com"));
    }

    [Test]
    public void Bind_NoBinding_NoDefault_Throws()
    {
        var node = new ParameterRef("hosts").ToJsonNode();
        var ex = Assert.Throws<TrustPolicySpecCompilationException>(
            () => ParameterRef.Bind(node, new Dictionary<string, JsonNode?>()));
        Assert.That(ex!.Code, Is.EqualTo(TrustPolicyDiagnosticCodes.UnboundParameter));
    }

    [Test]
    public void Bind_NullRoot_ReturnsNull()
    {
        Assert.That(ParameterRef.Bind(null, new Dictionary<string, JsonNode?>()), Is.Null);
    }

    [Test]
    public void Bind_NullBindings_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => ParameterRef.Bind(JsonValue.Create(1), null!));
    }

    [Test]
    public void Bind_PreservesPrimitiveAndContainerStructure()
    {
        var arr = new JsonArray(JsonValue.Create(1), new ParameterRef("n", JsonValue.Create(99)).ToJsonNode());
        var bound = ParameterRef.Bind(arr, new Dictionary<string, JsonNode?>());
        Assert.That(bound!.AsArray()[0]!.GetValue<int>(), Is.EqualTo(1));
        Assert.That(bound.AsArray()[1]!.GetValue<int>(), Is.EqualTo(99));
    }

    [Test]
    public void Bind_BindingNullValue_PassesThroughAsNull()
    {
        var node = new ParameterRef("x").ToJsonNode();
        var bindings = new Dictionary<string, JsonNode?> { ["x"] = null };
        Assert.That(ParameterRef.Bind(node, bindings), Is.Null);
    }

    [Test]
    public void TrustPolicySpecExtensions_Bind_ResolvesEmbeddedParameterRefs()
    {
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PathOperatorPredicateSpec(
                "$.content_type",
                PredicateOperator.In,
                new ParameterRef("allowed_content_types", new JsonArray("application/json")).ToJsonNode()),
            "Content type not allowed"));

        var bindings = new Dictionary<string, JsonNode?>
        {
            ["allowed_content_types"] = new JsonArray("application/octet-stream"),
        };

        TrustPolicySpec bound = spec.Bind(bindings);

        // Survive re-serialisation: confirm bound spec is canonical and parameter-free.
        string json = bound.ToCanonicalJson();
        Assert.That(json, Does.Not.Contain(ParameterRef.ParameterMarker));
        Assert.That(json, Does.Contain("application/octet-stream"));
    }

    [Test]
    public void TrustPolicySpecExtensions_Bind_NullSpec_Throws()
    {
        TrustPolicySpec? spec = null;
        Assert.Throws<ArgumentNullException>(() => spec!.Bind(new Dictionary<string, JsonNode?>()));
    }

    [Test]
    public void TrustPolicySpecExtensions_Bind_NullBindings_Throws()
    {
        TrustPolicySpec spec = new AllowAllSpec();
        Assert.Throws<ArgumentNullException>(() => spec.Bind(null!));
    }
}
