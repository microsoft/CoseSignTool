// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json.Tests;

using System.Diagnostics;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Json;

[TestFixture]
[Category("Determinism")]
public sealed class DeterminismAndPerfTests
{
    private const string Doc = """
    {
      "$schema": "https://raw.githubusercontent.com/microsoft/CoseSignTool/main/V2/schemas/cose-tp/v1.json",
      "frontend": "cose-tp-json/v1",
      "primary_signing_key": {
        "all_of": [
          { "fact": "x509-chain-trusted/v1", "predicate": { "is_trusted": true } },
          { "fact": "x509-cert-eku/v1",
            "predicate": { "operator": "Contains", "path": "$.ekus", "value": "1.3.6.1.5.5.7.3.3" }
          }
        ]
      },
      "any_counter_signature": {
        "on_empty": "deny",
        "all_of": [ { "fact": "mst-receipt-trusted/v1", "predicate": { "is_trusted": true } } ]
      }
    }
    """;

    [Test]
    public void Translate_OneThousandTimes_ProducesByteIdenticalCanonicalJson()
    {
        var f = new CoseTpJsonFrontend();
        var ctx = new TrustPolicyTranslationContext();

        TrustPolicyTranslationResult first = f.TranslateText(Doc, ctx);
        Assert.That(first.IsSuccess, Is.True);
        string canonical = TrustPolicySpecSerializer.ToCanonicalJson(first.Spec!);

        for (int i = 0; i < 1000; i++)
        {
            TrustPolicyTranslationResult r = f.TranslateText(Doc, ctx);
            Assert.That(TrustPolicySpecSerializer.ToCanonicalJson(r.Spec!), Is.EqualTo(canonical), $"Iteration {i} drifted from canonical projection.");
        }
    }

    [Test]
    public void Translate_DocumentUnderOneKb_CompletesWithinTimeBudget()
    {
        Assert.That(System.Text.Encoding.UTF8.GetByteCount(Doc), Is.LessThanOrEqualTo(1024), "Smoke-test document must be ≤1KB.");

        var f = new CoseTpJsonFrontend();
        var ctx = new TrustPolicyTranslationContext();

        // Warm-up — JsonSchema.Net amortises schema-compilation cost across calls; the budget
        // is the steady-state per-call cost, not the first-call JIT path. Phase 4's conformance
        // suite extends this with measurement-driven assertions per §6.5.4 #7.
        for (int i = 0; i < 5; i++)
        {
            _ = f.TranslateText(Doc, ctx);
        }

        var sw = Stopwatch.StartNew();
        TrustPolicyTranslationResult r = f.TranslateText(Doc, ctx);
        sw.Stop();

        Assert.That(r.IsSuccess, Is.True);

        // 10ms is the §6.5.4 #7 budget. We give it 50ms here because CI runners and dev laptops
        // can have noisy backgrounds; the real budget enforcement is in Phase 4 with statistical
        // sampling. This test is the smoke test that flags catastrophic regressions.
        Assert.That(sw.Elapsed.TotalMilliseconds, Is.LessThan(50.0), $"Translation took {sw.Elapsed.TotalMilliseconds:F1}ms, budget is 10ms (smoke threshold 50ms).");
    }
}
