// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using System.Collections.Generic;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Json;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;
using CoseSign1.Validation.Trust.Rules;

/// <summary>
/// Asserts every <see cref="TrustPolicySpec"/> node and predicate variant round-trips through
/// the canonical JSON serializer to byte-identical bytes.
/// </summary>
[TestFixture]
[Category("TrustPolicySpec")]
public sealed class TrustPolicySpecSerializationTests
{
    private static readonly object[] AllSpecNodes = new object[]
    {
        new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PathOperatorPredicateSpec("$.content_type", PredicateOperator.Equals, JsonValue.Create("application/json")),
            "Content type must be JSON")),
        new PrimarySigningKeyRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestSigningKey,
            new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
            {
                ["is_trusted"] = JsonValue.Create(true),
                ["subject"] = JsonValue.Create("CN=Test"),
            }),
            "Signing key must be trusted")),
        new AnyCounterSignatureRequirementSpec(
            new RequireFactSpec(
                TestFactRegistry.TestCounterSignature,
                new PathOperatorPredicateSpec("$.present", PredicateOperator.Equals, JsonValue.Create(true)),
                "CS must be present"),
            OnEmptyBehavior.Allow),
        new AndSpec(new TrustPolicySpec[]
        {
            new MessageRequirementSpec(new AllowAllSpec()),
            new MessageRequirementSpec(new DenyAllSpec("blocked")),
        }),
        new OrSpec(new TrustPolicySpec[]
        {
            new MessageRequirementSpec(new AllowAllSpec()),
            new PrimarySigningKeyRequirementSpec(new AllowAllSpec()),
        }),
        new NotSpec(new MessageRequirementSpec(new AllowAllSpec()), "negated"),
        new ImpliesSpec(
            new MessageRequirementSpec(new AllowAllSpec()),
            new MessageRequirementSpec(new DenyAllSpec("must satisfy"))),
        new AllowAllSpec(),
        new DenyAllSpec("nothing matches"),
    };

    [TestCaseSource(nameof(AllSpecNodes))]
    public void RoundTrip_PreservesByteIdentity(TrustPolicySpec spec)
    {
        // First trip — capture canonical bytes.
        string firstJson = TrustPolicySpecSerializer.ToCanonicalJson(spec);

        // Second trip — deserialize then re-serialize. The result must be byte-identical.
        TrustPolicySpec rehydrated = TrustPolicySpecSerializer.FromCanonicalJson(firstJson);
        string secondJson = TrustPolicySpecSerializer.ToCanonicalJson(rehydrated);

        Assert.That(secondJson, Is.EqualTo(firstJson), "Canonical JSON projection must be order-independent and lossless across one round-trip.");

        // Third trip from rehydrated — defends against accumulated drift in canonical projection.
        TrustPolicySpec rehydrated2 = TrustPolicySpecSerializer.FromCanonicalJson(secondJson);
        string thirdJson = TrustPolicySpecSerializer.ToCanonicalJson(rehydrated2);
        Assert.That(thirdJson, Is.EqualTo(firstJson), "Three round-trips must remain byte-identical.");
    }

    [Test]
    public void PropertyAssertion_KeyOrderingIndependent_ProducesIdenticalCanonicalJson()
    {
        // Same logical predicate, dictionary keys inserted in different orders. The canonical
        // converter must sort keys lexicographically so the JSON projection is identical.
        var ascending = new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
        {
            ["alpha"] = JsonValue.Create(1),
            ["beta"] = JsonValue.Create(2),
            ["gamma"] = JsonValue.Create(3),
        });

        var descending = new PropertyAssertionPredicateSpec(new Dictionary<string, JsonNode?>
        {
            ["gamma"] = JsonValue.Create(3),
            ["beta"] = JsonValue.Create(2),
            ["alpha"] = JsonValue.Create(1),
        });

        // Wrap each in a RequireFactSpec so the discriminator is exercised.
        var ascendingSpec = new MessageRequirementSpec(new RequireFactSpec(TestFactRegistry.TestMessage, ascending, "msg"));
        var descendingSpec = new MessageRequirementSpec(new RequireFactSpec(TestFactRegistry.TestMessage, descending, "msg"));

        Assert.That(
            TrustPolicySpecSerializer.ToCanonicalJson(descendingSpec),
            Is.EqualTo(TrustPolicySpecSerializer.ToCanonicalJson(ascendingSpec)));
    }

    [Test]
    public void CanonicalContentHash_StableAcrossRoundTrip()
    {
        var spec = new MessageRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestMessage,
            new PathOperatorPredicateSpec("$.payload_size", PredicateOperator.GreaterThanOrEqual, JsonValue.Create(0)),
            "size must be non-negative"));

        byte[] hashOriginal = spec.CanonicalContentHash();

        TrustPolicySpec rehydrated = TrustPolicySpecSerializer.FromCanonicalJson(spec.ToCanonicalJson());
        byte[] hashRehydrated = rehydrated.CanonicalContentHash();

        Assert.That(hashRehydrated, Is.EqualTo(hashOriginal));
        Assert.That(hashOriginal, Has.Length.EqualTo(32), "SHA-256 yields 32 bytes.");
    }

    [Test]
    public void CanonicalContentHash_NullSpec_Throws()
    {
        TrustPolicySpec? spec = null;
        Assert.Throws<System.ArgumentNullException>(() => spec!.CanonicalContentHash());
    }

    [Test]
    public void ToCanonicalJsonBytes_ProducesUtf8()
    {
        var spec = new AllowAllSpec();
        byte[] bytes = TrustPolicySpecSerializer.ToCanonicalJsonBytes(spec);

        // A UTF-8-encoded JSON object always starts with '{'.
        Assert.That(bytes[0], Is.EqualTo((byte)'{'));
    }

    [Test]
    public void ToCanonicalJsonBytes_NullSpec_Throws()
    {
        TrustPolicySpec? spec = null;
        Assert.Throws<System.ArgumentNullException>(() => TrustPolicySpecSerializer.ToCanonicalJsonBytes(spec!));
    }

    [Test]
    public void ToCanonicalJson_NullSpec_Throws()
    {
        TrustPolicySpec? spec = null;
        Assert.Throws<System.ArgumentNullException>(() => TrustPolicySpecSerializer.ToCanonicalJson(spec!));
    }

    [Test]
    public void FromCanonicalJson_NullJson_Throws()
    {
        Assert.Throws<System.ArgumentNullException>(() => TrustPolicySpecSerializer.FromCanonicalJson(null!));
    }

    [Test]
    public void FromCanonicalJson_NullDocument_ThrowsJsonException()
    {
        Assert.Throws<System.Text.Json.JsonException>(() => TrustPolicySpecSerializer.FromCanonicalJson("null"));
    }
}
