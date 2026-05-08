// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using System.Diagnostics;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Compilation;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Phase-1 performance smoke tests. These are NOT full BenchmarkDotNet benchmarks (Phase 4's
/// conformance suite owns rigorous benchmarking with CI-enforced thresholds); they are
/// hermetic upper-bound assertions that catch order-of-magnitude regressions in the spec
/// compile + evaluate hot path.
/// </summary>
/// <remarks>
/// <para>
/// The dispatch contract notes the "documented but unmeasured" per-evaluation
/// JsonSerializer.SerializeToNode cost in <see cref="Compilation.PredicateLowerer"/>. These
/// tests measure that cost on a representative spec and assert a sanity bound: 1000
/// evaluations of a 3-property fact must complete in well under one second. If a future
/// change drops a 100× allocation regression, this test catches it.
/// </para>
/// <para>
/// The tests intentionally use generous thresholds (an order of magnitude above the expected
/// runtime) so they don't flake on CI. Phase 4's conformance suite tightens these thresholds
/// per the §6.5.4 #7 contract (1 KB document → ≤10 ms translation).
/// </para>
/// </remarks>
[TestFixture]
[Category("TrustPolicySpec")]
[Category("Performance")]
public sealed class PerformanceSmokeTests
{
    private const int IterationCount = 1000;
    private const int MaxAllowedMillis = 5000;

    [Test]
    public void Evaluate_ThousandIterations_CompletesUnderUpperBound()
    {
        var spec = new PrimarySigningKeyRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestSigningKey,
            new PathOperatorPredicateSpec("$.is_trusted", PredicateOperator.Equals, JsonValue.Create(true)),
            "fail"));

        TrustPlanPolicy policy = TrustPolicySpecCompiler.Compile(spec, TestFactRegistry.Build());
        var services = new ServiceCollection();
        services.AddSingleton<ITrustPack>(_ => new FixedFactProducer<TestSigningKeyFact>(
            TrustSubjectKind.PrimarySigningKey,
            new TestSigningKeyFact(true, "CN=Test")));
        var compiled = policy.Compile(services.BuildServiceProvider());
        TrustSubjectId messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0xC0 });
        TrustSubject message = TrustSubject.Message(messageId);

        // Warm up — exclude JIT + first-touch allocations from the measurement.
        for (int i = 0; i < 10; i++)
        {
            _ = compiled.Evaluate(messageId, message);
        }

        var stopwatch = Stopwatch.StartNew();
        for (int i = 0; i < IterationCount; i++)
        {
            _ = compiled.Evaluate(messageId, message);
        }

        stopwatch.Stop();

        Assert.That(
            stopwatch.ElapsedMilliseconds,
            Is.LessThan(MaxAllowedMillis),
            $"Per-evaluation cost regressed: {IterationCount} evaluations took {stopwatch.ElapsedMilliseconds} ms; expected < {MaxAllowedMillis} ms.");
    }

    [Test]
    public void Compile_ThousandIterations_CompletesUnderUpperBound()
    {
        // Compile-time cost (path parsing + reflection) is amortised at policy load. This
        // test asserts the compile cost remains bounded for the typical Phase-1 workload.
        var spec = new PrimarySigningKeyRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestSigningKey,
            new PathOperatorPredicateSpec("$.is_trusted", PredicateOperator.Equals, JsonValue.Create(true)),
            "fail"));

        var registry = TestFactRegistry.Build();

        // Warm up.
        for (int i = 0; i < 10; i++)
        {
            _ = TrustPolicySpecCompiler.Compile(spec, registry);
        }

        var stopwatch = Stopwatch.StartNew();
        for (int i = 0; i < IterationCount; i++)
        {
            _ = TrustPolicySpecCompiler.Compile(spec, registry);
        }

        stopwatch.Stop();

        Assert.That(
            stopwatch.ElapsedMilliseconds,
            Is.LessThan(MaxAllowedMillis),
            $"Compile cost regressed: {IterationCount} compiles took {stopwatch.ElapsedMilliseconds} ms; expected < {MaxAllowedMillis} ms.");
    }

    [Test]
    public void Serialize_ThousandIterations_CompletesUnderUpperBound()
    {
        // Canonical JSON projection (D9 content-hash) — sanity-bound the sort-on-write cost.
        var spec = new PrimarySigningKeyRequirementSpec(new RequireFactSpec(
            TestFactRegistry.TestSigningKey,
            new PathOperatorPredicateSpec("$.is_trusted", PredicateOperator.Equals, JsonValue.Create(true)),
            "fail"));

        for (int i = 0; i < 10; i++)
        {
            _ = spec.ToCanonicalJson();
        }

        var stopwatch = Stopwatch.StartNew();
        for (int i = 0; i < IterationCount; i++)
        {
            _ = spec.ToCanonicalJson();
        }

        stopwatch.Stop();

        Assert.That(
            stopwatch.ElapsedMilliseconds,
            Is.LessThan(MaxAllowedMillis),
            $"Canonical-JSON serialization regressed: {IterationCount} serialisations took {stopwatch.ElapsedMilliseconds} ms; expected < {MaxAllowedMillis} ms.");
    }
}
