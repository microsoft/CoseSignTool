// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using System;
using System.Linq;
using System.Reflection;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;
using TrustFactRegistryTestHelpers;

/// <summary>
/// Tests covering <see cref="AttributeDrivenFactRegistry"/> behaviour outside the conformance
/// path — duplicate detection, null guards, lookup correctness, ordering, and the
/// <see cref="AttributeDrivenFactRegistry.FromLoadedAssemblies"/> entry point.
/// </summary>
/// <remarks>
/// Synthetic / colliding fact types live in the <c>TrustFactRegistryTestHelpers</c> assembly
/// (intentionally NOT prefixed <c>CoseSign1.</c>) so the production
/// <see cref="AttributeDrivenFactRegistry.FromLoadedAssemblies"/> scan never sees them. This
/// fixture passes the helper assembly explicitly when it needs to exercise duplicate / no-fact
/// code paths, keeping the conformance baseline clean.
/// </remarks>
[TestFixture]
[Category("TrustPolicySpec")]
public sealed class AttributeDrivenFactRegistryTests
{
    private static Assembly HelperAsm => typeof(SyntheticAlphaFact).Assembly;
    private static Assembly EmptyAsm => typeof(Cose.Abstractions.Guard).Assembly;

    [Test]
    public void FromLoadedAssemblies_DiscoversShippedFactCount()
    {
        var registry = AttributeDrivenFactRegistry.FromLoadedAssemblies();
        Assert.That(registry.AllFactIds, Has.Count.EqualTo(16));
    }

    [Test]
    public void FromLoadedAssemblies_TryGetFactType_ResolvesKnownId()
    {
        var registry = AttributeDrivenFactRegistry.FromLoadedAssemblies();
        Assert.That(registry.TryGetFactType("x509-chain-trusted/v1", out var type), Is.True);
        Assert.That(type, Is.EqualTo(typeof(CoseSign1.Certificates.Trust.Facts.X509ChainTrustedFact)));
    }

    [Test]
    public void FromLoadedAssemblies_TryGetFactType_UnknownId_ReturnsFalse()
    {
        var registry = AttributeDrivenFactRegistry.FromLoadedAssemblies();
        Assert.That(registry.TryGetFactType("does-not-exist/v9", out _), Is.False);
    }

    [Test]
    public void FromLoadedAssemblies_TryGetFactId_ResolvesKnownType()
    {
        var registry = AttributeDrivenFactRegistry.FromLoadedAssemblies();
        Assert.That(
            registry.TryGetFactId(typeof(CoseSign1.Transparent.MST.Trust.MstReceiptTrustedFact), out var id),
            Is.True);
        Assert.That(id, Is.EqualTo("mst-receipt-trusted/v1"));
    }

    [Test]
    public void FromLoadedAssemblies_TryGetFactId_UnknownType_ReturnsFalse()
    {
        var registry = AttributeDrivenFactRegistry.FromLoadedAssemblies();
        Assert.That(registry.TryGetFactId(typeof(string), out _), Is.False);
    }

    [Test]
    public void FromLoadedAssemblies_DoesNotIncludeSyntheticHelpers()
    {
        // The helper assembly is loaded (this fixture references types in it), but its name
        // does not start with 'CoseSign1.' so the prefix-restricted scan must skip it.
        var registry = AttributeDrivenFactRegistry.FromLoadedAssemblies();
        Assert.That(registry.TryGetFactType("synthetic-alpha/v1", out _), Is.False);
        Assert.That(registry.TryGetFactType("synthetic-beta/v1", out _), Is.False);
    }

    [Test]
    public void Constructor_NullAssemblyEnumeration_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new AttributeDrivenFactRegistry(null!));
    }

    [Test]
    public void Constructor_NullAssemblyEntry_Throws()
    {
        var asms = new Assembly?[] { null };
        Assert.Throws<ArgumentException>(() => new AttributeDrivenFactRegistry(asms!));
    }

    [Test]
    public void Constructor_RepeatedSameAssembly_Idempotent()
    {
        // Same assembly listed twice — duplicate (id, type) pairs from the second pass are
        // silently ignored. Without this guard, pulling an assembly via two paths
        // (Type.Assembly + AppDomain scan) would falsely trip the duplicate-id check.
        var emptyAsm = EmptyAsm;
        var registry = new AttributeDrivenFactRegistry(new[] { emptyAsm, emptyAsm });
        Assert.That(registry.AllFactIds, Is.Empty);
    }

    [Test]
    public void Constructor_DuplicateId_ThrowsWithTpx300()
    {
        // The helper assembly contains SyntheticAlphaFact and SyntheticAlphaCollidingFact —
        // both decorated with id 'synthetic-alpha/v1'. Construction must surface the conflict
        // with diagnostic code TPX300 in the message.
        var ex = Assert.Throws<ArgumentException>(() => new AttributeDrivenFactRegistry(new[] { HelperAsm }));
        Assert.That(ex!.Message, Does.Contain("TPX300"));
        Assert.That(ex.Message, Does.Contain("synthetic-alpha/v1"));
    }

    [Test]
    public void TryGetFactType_NullArg_Throws()
    {
        var registry = new AttributeDrivenFactRegistry(new[] { EmptyAsm });
        Assert.Throws<ArgumentNullException>(() => registry.TryGetFactType(null!, out _));
    }

    [Test]
    public void TryGetFactId_NullArg_Throws()
    {
        var registry = new AttributeDrivenFactRegistry(new[] { EmptyAsm });
        Assert.Throws<ArgumentNullException>(() => registry.TryGetFactId(null!, out _));
    }

    [Test]
    public void Registry_AllFactIds_LexicographicallyOrdered()
    {
        var registry = AttributeDrivenFactRegistry.FromLoadedAssemblies();
        var ids = registry.AllFactIds.ToList();
        for (int i = 1; i < ids.Count; i++)
        {
            Assert.That(
                StringComparer.Ordinal.Compare(ids[i - 1], ids[i]) < 0,
                $"AllFactIds must be ordinal-sorted; '{ids[i - 1]}' should come before '{ids[i]}'.");
        }
    }

    [Test]
    public void Registry_UntaggedTypeIsIgnored()
    {
        // UntaggedFact is in the helper assembly but has no [TrustFactId]; building over an
        // empty assembly proves the type is not auto-registered.
        var registry = new AttributeDrivenFactRegistry(new[] { EmptyAsm });
        Assert.That(registry.TryGetFactId(typeof(UntaggedFact), out _), Is.False);
    }

    [Test]
    public void Constructor_EmptyAssemblies_BuildsEmptyRegistry()
    {
        var registry = new AttributeDrivenFactRegistry(Array.Empty<Assembly>());
        Assert.That(registry.AllFactIds, Is.Empty);
    }

    [Test]
    public void Constructor_SameAssemblyTwice_DoesNotDuplicateFacts()
    {
        // Pass a known fact-host assembly twice. The second pass observes every (id, type) pair
        // already registered → exercises the same-type idempotency continue branch in the
        // duplicate check.
        Assembly certs = typeof(CoseSign1.Certificates.Trust.Facts.X509ChainTrustedFact).Assembly;
        var registry = new AttributeDrivenFactRegistry(new[] { certs, certs });
        Assert.That(registry.AllFactIds, Contains.Item("x509-chain-trusted/v1"));
        // Cert pack ships 9 tagged facts; idempotent re-scan must not double-count.
        Assert.That(registry.AllFactIds.Count, Is.EqualTo(9));
    }

    [Test]
    public void Constructor_AssemblyWithoutTaggedTypes_BuildsEmptyRegistry()
    {
        var registry = new AttributeDrivenFactRegistry(new[] { EmptyAsm });
        Assert.That(registry.AllFactIds, Is.Empty);
    }
}
