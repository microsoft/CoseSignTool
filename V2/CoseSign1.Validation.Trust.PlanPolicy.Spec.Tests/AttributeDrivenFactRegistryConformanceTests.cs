// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;

/// <summary>
/// Immutable contract test for Phase 3: the attribute-driven registry MUST report exactly
/// the same (id, fullTypeName) tuples as the Phase 1 hand-rolled <see cref="StaticFactRegistry"/>
/// baseline.
/// </summary>
/// <remarks>
/// <para>
/// Renaming any v1 fact id is a v2 breaking change (Phase 1 ship contract). This test is the
/// guard rail: a divergence between the two registries fails the build before a rename can ship.
/// Updating the test to permit a rename requires going through the v2 migration process (and
/// updating both registries in lock-step plus the v2 changelog).
/// </para>
/// <para>
/// The test compares <see cref="SortedSet{T}"/>s of <c>"id|fullTypeName"</c> tuples so any
/// addition, removal, or rename surfaces as a clear diff in the assertion message.
/// </para>
/// </remarks>
[TestFixture]
[Category("TrustPolicySpec")]
[Category("Conformance")]
public sealed class AttributeDrivenFactRegistryConformanceTests
{
    private const string Separator = "|";

    [Test]
    public void AttributeDriven_Equals_StaticBaseline()
    {
        SortedSet<string> baselineTuples = BuildTupleSet(BuildBaselineMappings());
        SortedSet<string> attributeTuples = BuildTupleSet(BuildAttributeDrivenMappings());

        // SetEquals gives correct semantics; produce a useful failure message ourselves so a
        // diff is visible without re-running.
        bool equal = baselineTuples.SetEquals(attributeTuples);
        if (!equal)
        {
            string missingFromAttribute = string.Join(", ", baselineTuples.Except(attributeTuples));
            string extraInAttribute = string.Join(", ", attributeTuples.Except(baselineTuples));
            Assert.Fail(
                "AttributeDrivenFactRegistry diverges from StaticFactRegistry baseline.\n"
                + "  Missing from attribute-driven (present in baseline): " + missingFromAttribute + "\n"
                + "  Extra in attribute-driven (absent from baseline):    " + extraInAttribute);
        }

        Assert.That(attributeTuples, Has.Count.EqualTo(baselineTuples.Count));
    }

    [Test]
    public void AttributeDriven_HasSameCardinality_AsBaseline()
    {
        Assert.That(
            BuildAttributeDrivenMappings().Count,
            Is.EqualTo(BuildBaselineMappings().Count));
    }

    [Test]
    public void AttributeDriven_AllFactIds_AreLexicographicallyOrdered()
    {
        var registry = AttributeDrivenFactRegistry.FromLoadedAssemblies();
        var ids = registry.AllFactIds.ToList();
        for (int i = 1; i < ids.Count; i++)
        {
            Assert.That(
                StringComparer.Ordinal.Compare(ids[i - 1], ids[i]) < 0,
                $"AllFactIds must be sorted; '{ids[i - 1]}' should come before '{ids[i]}'.");
        }
    }

    private static IReadOnlyDictionary<string, Type> BuildBaselineMappings()
    {
#pragma warning disable CS0618 // StaticFactRegistry is the conformance baseline; obsolescence is intentional.
        IReadOnlyList<KeyValuePair<string, Type>> baseline = StaticFactRegistry.BuildDefaultMappings();
#pragma warning restore CS0618
        var dict = new Dictionary<string, Type>(StringComparer.Ordinal);
        foreach (var kvp in baseline)
        {
            dict[kvp.Key] = kvp.Value;
        }

        return dict;
    }

    private static IReadOnlyDictionary<string, Type> BuildAttributeDrivenMappings()
    {
        var registry = AttributeDrivenFactRegistry.FromLoadedAssemblies();
        var dict = new Dictionary<string, Type>(StringComparer.Ordinal);
        foreach (string id in registry.AllFactIds)
        {
            Assert.That(registry.TryGetFactType(id, out var type), Is.True, $"Registry id '{id}' did not resolve to a type.");
            dict[id] = type!;
        }

        return dict;
    }

    private static SortedSet<string> BuildTupleSet(IReadOnlyDictionary<string, Type> map)
    {
        var set = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var kvp in map)
        {
            set.Add(kvp.Key + Separator + (kvp.Value.FullName ?? kvp.Value.Name));
        }

        return set;
    }
}
