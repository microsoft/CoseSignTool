// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using System;
using System.Collections.Generic;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;

/// <summary>
/// Tests for <see cref="StaticFactRegistry"/> id ↔ type bijection and validation.
/// </summary>
[TestFixture]
[Category("TrustPolicySpec")]
public sealed class StaticFactRegistryTests
{
    [Test]
    public void Default_ContainsExpectedFactCount()
    {
        var registry = new StaticFactRegistry();
        Assert.That(registry.AllFactIds, Has.Count.EqualTo(16));
    }

    [Test]
    public void Default_RegistersX509ChainTrusted()
    {
        var registry = new StaticFactRegistry();
        Assert.That(registry.TryGetFactType("x509-chain-trusted/v1", out var clr), Is.True);
        Assert.That(clr!.Name, Is.EqualTo("X509ChainTrustedFact"));
    }

    [Test]
    public void Default_AllFactIds_AreLexicographicallyOrdered()
    {
        var registry = new StaticFactRegistry();
        var ids = new List<string>(registry.AllFactIds);

        for (int i = 1; i < ids.Count; i++)
        {
            Assert.That(StringComparer.Ordinal.Compare(ids[i - 1], ids[i]) < 0,
                $"AllFactIds must be sorted; '{ids[i - 1]}' should come before '{ids[i]}'.");
        }
    }

    [Test]
    public void TryGetFactId_RoundTripsToOriginalId()
    {
        var registry = new StaticFactRegistry();
        Assert.That(registry.TryGetFactType("mst-receipt-trusted/v1", out var clr), Is.True);
        Assert.That(registry.TryGetFactId(clr!, out var id), Is.True);
        Assert.That(id, Is.EqualTo("mst-receipt-trusted/v1"));
    }

    [Test]
    public void TryGetFactType_UnknownId_ReturnsFalse()
    {
        var registry = new StaticFactRegistry();
        Assert.That(registry.TryGetFactType("not-a-fact/v9", out _), Is.False);
    }

    [Test]
    public void TryGetFactId_UnknownType_ReturnsFalse()
    {
        var registry = new StaticFactRegistry();
        Assert.That(registry.TryGetFactId(typeof(string), out _), Is.False);
    }

    [Test]
    public void Constructor_NullMappings_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new StaticFactRegistry(null!));
    }

    [Test]
    public void Constructor_EmptyId_Throws()
    {
        Assert.Throws<ArgumentException>(() => new StaticFactRegistry(new[]
        {
            new KeyValuePair<string, Type>("", typeof(string)),
        }));
    }

    [Test]
    public void Constructor_NullType_Throws()
    {
        Assert.Throws<ArgumentException>(() => new StaticFactRegistry(new[]
        {
            new KeyValuePair<string, Type>("foo/v1", null!),
        }));
    }

    [Test]
    public void Constructor_DuplicateId_Throws()
    {
        Assert.Throws<ArgumentException>(() => new StaticFactRegistry(new[]
        {
            new KeyValuePair<string, Type>("foo/v1", typeof(int)),
            new KeyValuePair<string, Type>("foo/v1", typeof(string)),
        }));
    }

    [Test]
    public void Constructor_DuplicateType_Throws()
    {
        Assert.Throws<ArgumentException>(() => new StaticFactRegistry(new[]
        {
            new KeyValuePair<string, Type>("a/v1", typeof(int)),
            new KeyValuePair<string, Type>("b/v1", typeof(int)),
        }));
    }

    [Test]
    public void TryGetFactType_NullArg_Throws()
    {
        var registry = new StaticFactRegistry();
        Assert.Throws<ArgumentNullException>(() => registry.TryGetFactType(null!, out _));
    }

    [Test]
    public void TryGetFactId_NullArg_Throws()
    {
        var registry = new StaticFactRegistry();
        Assert.Throws<ArgumentNullException>(() => registry.TryGetFactId(null!, out _));
    }

    [Test]
    public void BuildDefaultMappings_ReturnsStableSnapshot()
    {
        var first = StaticFactRegistry.BuildDefaultMappings();
        var second = StaticFactRegistry.BuildDefaultMappings();
        Assert.That(second, Has.Count.EqualTo(first.Count));
    }
}
