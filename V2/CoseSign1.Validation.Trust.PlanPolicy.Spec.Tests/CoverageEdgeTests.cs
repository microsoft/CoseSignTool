// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.Facts;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Compilation;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Json;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Test fact that exposes a list property so array-index path traversal can be exercised.
/// </summary>
public sealed class TestListFact : IMessageFact
{
    public TestListFact(string name, IReadOnlyList<string> hosts)
    {
        Name = name;
        Hosts = hosts;
    }

    public TrustFactScope Scope => TrustFactScope.Message;

    public string Name { get; }

    public IReadOnlyList<string> Hosts { get; }
}

/// <summary>
/// Tests that exercise the deeper code paths in the canonical JSON converters and the predicate
/// lowerer's more exotic branches (null-in-array handling, deep array indexing, etc.).
/// </summary>
[TestFixture]
[Category("TrustPolicySpec")]
public sealed class CoverageEdgeTests
{
    private const string TestListFactId = "test-list/v1";

    private static StaticFactRegistry RegistryWithListFact()
    {
        var entries = new List<KeyValuePair<string, Type>>(StaticFactRegistry.BuildDefaultMappings())
        {
            new KeyValuePair<string, Type>(TestFactRegistry.TestMessage, typeof(TestMessageFact)),
            new KeyValuePair<string, Type>(TestFactRegistry.TestSigningKey, typeof(TestSigningKeyFact)),
            new KeyValuePair<string, Type>(TestFactRegistry.TestCounterSignature, typeof(TestCounterSignatureFact)),
            new KeyValuePair<string, Type>(TestListFactId, typeof(TestListFact)),
        };
        return new StaticFactRegistry(entries);
    }

    [Test]
    public void PathOperator_ArrayIndexAccessor_Resolves()
    {
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestListFactId,
            new PathOperatorPredicateSpec("$.hosts[1]", PredicateOperator.Equals, JsonValue.Create("bar.com")),
            "fail"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, RegistryWithListFact());
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new FixedFactProducer<TestListFact>(TrustSubjectKind.Message, new TestListFact("x", new[] { "foo.com", "bar.com" })));
        var compiled = policy.Compile(services.BuildServiceProvider());
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0xA0 });
        Assert.That(compiled.Evaluate(messageId, TrustSubject.Message(messageId)).IsTrusted, Is.True);
    }

    [Test]
    public void PathOperator_ArrayIndexOutOfRange_DoesNotResolve()
    {
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestListFactId,
            new PathOperatorPredicateSpec("$.hosts[99]", PredicateOperator.Exists, null),
            "fail"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, RegistryWithListFact());
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new FixedFactProducer<TestListFact>(TrustSubjectKind.Message, new TestListFact("x", new[] { "foo.com" })));
        var compiled = policy.Compile(services.BuildServiceProvider());
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0xA1 });
        Assert.That(compiled.Evaluate(messageId, TrustSubject.Message(messageId)).IsTrusted, Is.False);
    }

    [Test]
    public void PathOperator_IndexOnNonArray_DoesNotResolve()
    {
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PathOperatorPredicateSpec("$.content_type[0]", PredicateOperator.Exists, null),
            "fail"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, RegistryWithListFact());
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message, new TestMessageFact("application/json", 1, false)));
        var compiled = policy.Compile(services.BuildServiceProvider());
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0xA2 });
        Assert.That(compiled.Evaluate(messageId, TrustSubject.Message(messageId)).IsTrusted, Is.False);
    }

    [Test]
    public void PathOperator_PropertyOnNonObject_DoesNotResolve()
    {
        // $.hosts.foo — hosts is an array, so the .foo accessor cannot resolve.
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestListFactId,
            new PathOperatorPredicateSpec("$.hosts.foo", PredicateOperator.Exists, null),
            "fail"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, RegistryWithListFact());
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new FixedFactProducer<TestListFact>(TrustSubjectKind.Message, new TestListFact("x", new[] { "foo" })));
        var compiled = policy.Compile(services.BuildServiceProvider());
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0xA3 });
        Assert.That(compiled.Evaluate(messageId, TrustSubject.Message(messageId)).IsTrusted, Is.False);
    }

    [Test]
    public void Contains_OnArray_FindsMember()
    {
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestListFactId,
            new PathOperatorPredicateSpec("$.hosts", PredicateOperator.Contains, JsonValue.Create("bar.com")),
            "fail"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, RegistryWithListFact());
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new FixedFactProducer<TestListFact>(TrustSubjectKind.Message, new TestListFact("x", new[] { "foo.com", "bar.com" })));
        var compiled = policy.Compile(services.BuildServiceProvider());
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0xA4 });
        Assert.That(compiled.Evaluate(messageId, TrustSubject.Message(messageId)).IsTrusted, Is.True);
    }

    [Test]
    public void CanonicalJsonNodeConverter_RoundTripsObjectWithNullValues()
    {
        // PropertyAssertion supports null values — the canonical converter must serialize them
        // as JSON null rather than omit them or throw.
        var pred = new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
        {
            ["zeta"] = null,
            ["alpha"] = JsonValue.Create(1),
        });

        var spec = new MessageRequirementSpec(new RequireFactSpec(TestFactRegistry.TestMessage, pred, "msg"));
        string json = TrustPolicySpecSerializer.ToCanonicalJson(spec);
        Assert.That(json, Does.Contain("\"zeta\":null"));

        // Round-trip
        var rehydrated = TrustPolicySpecSerializer.FromCanonicalJson(json);
        Assert.That(TrustPolicySpecSerializer.ToCanonicalJson(rehydrated), Is.EqualTo(json));
    }

    [Test]
    public void CanonicalJsonNodeConverter_RoundTripsArrayWithNullValues()
    {
        // An array element that is null inside a property-assertion value: serialize to '[null,…]'
        // and round-trip cleanly.
        var pred = new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
        {
            ["payload"] = new JsonArray(JsonValue.Create(1), null, JsonValue.Create(2)),
        });
        var spec = new MessageRequirementSpec(new RequireFactSpec(TestFactRegistry.TestMessage, pred, "msg"));
        string json = TrustPolicySpecSerializer.ToCanonicalJson(spec);
        Assert.That(json, Does.Contain("[1,null,2]"));
        Assert.That(TrustPolicySpecSerializer.ToCanonicalJson(TrustPolicySpecSerializer.FromCanonicalJson(json)), Is.EqualTo(json));
    }

    [Test]
    public void CanonicalJsonNodeConverter_NestedObjects_KeysSortedAtEveryLevel()
    {
        var nested = new JsonObject
        {
            ["zebra"] = new JsonObject { ["zz"] = JsonValue.Create(1), ["aa"] = JsonValue.Create(2) },
            ["alpha"] = JsonValue.Create("first"),
        };

        var pred = new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
        {
            ["complex"] = nested,
        });

        var spec = new MessageRequirementSpec(new RequireFactSpec(TestFactRegistry.TestMessage, pred, "msg"));
        string json = TrustPolicySpecSerializer.ToCanonicalJson(spec);
        // alpha must appear before zebra at the outer level; aa before zz at the inner level.
        int alphaIdx = json.IndexOf("alpha", StringComparison.Ordinal);
        int zebraIdx = json.IndexOf("zebra", StringComparison.Ordinal);
        int aaIdx = json.IndexOf("\"aa\"", StringComparison.Ordinal);
        int zzIdx = json.IndexOf("\"zz\"", StringComparison.Ordinal);
        Assert.That(alphaIdx, Is.LessThan(zebraIdx));
        Assert.That(aaIdx, Is.LessThan(zzIdx));
    }

    [Test]
    public void CanonicalPredicateAssertionsConverter_NonObjectInput_ThrowsJsonException()
    {
        // Hand-craft a json string where the assertions field is not an object.
        string bad = "{\"type\":\"require_fact\",\"fact\":\"test-message/v1\",\"predicate\":{\"predicate_type\":\"property_assertion\",\"assertions\":42},\"failure_message\":\"x\"}";
        Assert.Throws<JsonException>(() => TrustPolicySpecSerializer.FromCanonicalJson(bad));
    }

    [Test]
    public void CanonicalPredicateAssertionsConverter_NullAssertionsValueRoundTrips()
    {
        // Confirm that a value-typed null inside the assertions map serializes/deserializes via
        // the converter's null branch.
        var pred = new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
        {
            ["nullable_field"] = null,
        });
        var spec = new MessageRequirementSpec(new RequireFactSpec(TestFactRegistry.TestMessage, pred, "msg"));

        string json = TrustPolicySpecSerializer.ToCanonicalJson(spec);
        var rehydrated = TrustPolicySpecSerializer.FromCanonicalJson(json);

        Assert.That(TrustPolicySpecSerializer.ToCanonicalJson(rehydrated), Is.EqualTo(json));
    }

    [Test]
    public void CanonicalPredicateAssertionsConverter_NullValueWriteEmitsNull()
    {
        // Trigger Write directly to ensure the null branch is hit.
        var converter = new CanonicalPredicateAssertionsConverter();
        var dict = (IReadOnlyDictionary<string, JsonNode?>)new Dictionary<string, JsonNode?>
        {
            ["alpha"] = null,
            ["beta"] = JsonValue.Create(1),
        };

        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms))
        {
            converter.Write(writer, dict, TrustPolicySpecSerializer.Options);
        }

        string json = Encoding.UTF8.GetString(ms.ToArray());
        Assert.That(json, Is.EqualTo("{\"alpha\":null,\"beta\":1}"));
    }

    [Test]
    public void CanonicalPredicateAssertionsConverter_NullDictionary_Write_Throws()
    {
        var converter = new CanonicalPredicateAssertionsConverter();
        using var ms = new MemoryStream();
        using var writer = new Utf8JsonWriter(ms);
        Assert.Throws<ArgumentNullException>(() => converter.Write(writer, null!, TrustPolicySpecSerializer.Options));
    }

    [Test]
    public void TrustPolicySpec_LocationOnContainerNode_RoundTrips()
    {
        // Place a SourceLocation on an OrSpec (a container that has its own Location property)
        // and confirm both the container's location and its operands' specs round-trip.
        var spec = new OrSpec(new TrustPolicySpec[] { new AllowAllSpec(), new DenyAllSpec("nope") })
        {
            Location = new SourceLocation("file://x", 1, 1, 0),
        };

        string json = spec.ToCanonicalJson();
        var rehydrated = (OrSpec)TrustPolicySpecSerializer.FromCanonicalJson(json);
        Assert.That(rehydrated.Location, Is.Not.Null);
        Assert.That(rehydrated.Operands, Has.Count.EqualTo(2));
    }

    [Test]
    public void Bind_Idempotent_WithoutParameters()
    {
        var spec = new MessageRequirementSpec(new AllowAllSpec());
        TrustPolicySpec bound = spec.Bind(new Dictionary<string, JsonNode?>());

        Assert.That(bound, Is.Not.SameAs(spec));
        Assert.That(TrustPolicySpecSerializer.ToCanonicalJson(bound),
            Is.EqualTo(TrustPolicySpecSerializer.ToCanonicalJson(spec)));
    }

    [Test]
    public void Equals_NotEquals_StringsBranch()
    {
        // String-vs-string compare goes via the string CompareOrdinal path. Coverage gap:
        // ensure GreaterThan with string values exercises that path.
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PathOperatorPredicateSpec("$.content_type", PredicateOperator.GreaterThan, JsonValue.Create("a")),
            "fail"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, RegistryWithListFact());
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message, new TestMessageFact("zzz", 1, false)));
        var compiled = policy.Compile(services.BuildServiceProvider());
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0xB0 });
        Assert.That(compiled.Evaluate(messageId, TrustSubject.Message(messageId)).IsTrusted, Is.True);
    }

    [Test]
    public void Compare_TypeMismatch_ReturnsFalse()
    {
        // Number vs string — CompareNumbers returns null, GreaterThan / LessThan returns false.
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PathOperatorPredicateSpec("$.payload_size", PredicateOperator.LessThan, JsonValue.Create("string-not-number")),
            "fail"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, RegistryWithListFact());
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message, new TestMessageFact("any", 1, false)));
        var compiled = policy.Compile(services.BuildServiceProvider());
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0xB1 });
        Assert.That(compiled.Evaluate(messageId, TrustSubject.Message(messageId)).IsTrusted, Is.False);
    }

    [Test]
    public void StartsWith_NonString_ReturnsFalse()
    {
        // StartsWith operator on a non-string predicate value yields false (not throw).
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PathOperatorPredicateSpec("$.payload_size", PredicateOperator.StartsWith, JsonValue.Create("foo")),
            "fail"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, RegistryWithListFact());
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message, new TestMessageFact("any", 1, false)));
        var compiled = policy.Compile(services.BuildServiceProvider());
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0xB2 });
        Assert.That(compiled.Evaluate(messageId, TrustSubject.Message(messageId)).IsTrusted, Is.False);
    }

    [Test]
    public void EndsWith_NonString_ReturnsFalse()
    {
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PathOperatorPredicateSpec("$.payload_size", PredicateOperator.EndsWith, JsonValue.Create("foo")),
            "fail"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, RegistryWithListFact());
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message, new TestMessageFact("any", 1, false)));
        var compiled = policy.Compile(services.BuildServiceProvider());
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0xB3 });
        Assert.That(compiled.Evaluate(messageId, TrustSubject.Message(messageId)).IsTrusted, Is.False);
    }

    [Test]
    public void DeepPath_MidSegmentMissing_StopsResolutionEarly()
    {
        // Path like `$.does_not_exist.foo` causes ResolvePath to enter the loop with
        // current=null on the second iteration — the early `if (current is null) return null;`
        // path. This is the only natural way to hit it without exposing internals.
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PathOperatorPredicateSpec("$.does_not_exist.foo", PredicateOperator.Exists, null),
            "fail"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, RegistryWithListFact());
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message, new TestMessageFact("any", 1, false)));
        var compiled = policy.Compile(services.BuildServiceProvider());
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0xB4 });
        Assert.That(compiled.Evaluate(messageId, TrustSubject.Message(messageId)).IsTrusted, Is.False);
    }

    [Test]
    public void PropertyAssertion_NumericComparison_CoversIntLongDecimal()
    {
        // Force the compiler down a number-vs-number comparison through Property assertion to
        // confirm TryGetNumber's int / long / decimal branches.
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
            {
                ["payload_size"] = JsonValue.Create((long)42),
            }),
            "fail"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, RegistryWithListFact());
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new FixedFactProducer<TestMessageFact>(TrustSubjectKind.Message, new TestMessageFact("any", 42, false)));
        var compiled = policy.Compile(services.BuildServiceProvider());
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0xB5 });
        Assert.That(compiled.Evaluate(messageId, TrustSubject.Message(messageId)).IsTrusted, Is.True);
    }
}
