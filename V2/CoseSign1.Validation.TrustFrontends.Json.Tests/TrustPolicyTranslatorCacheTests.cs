// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json.Tests;

using System.Collections.Generic;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.Frontends;

[TestFixture]
[Category("Cache")]
public sealed class TrustPolicyTranslatorCacheTests
{
    private const string DocA = """{"message":{"allow_all":true}}""";
    private const string DocB = """{"primary_signing_key":{"deny_all":"x"}}""";

    [Test]
    public void Constructor_ZeroCapacity_Throws()
    {
        Assert.Throws<System.ArgumentOutOfRangeException>(() => new TrustPolicyTranslatorCache(new TrustPolicyTranslatorOptions { CacheCapacity = 0 }));
    }

    [Test]
    public void Constructor_DefaultsCapacityTo32()
    {
        Assert.That(new TrustPolicyTranslatorCache().Capacity, Is.EqualTo(32));
    }

    [Test]
    public void TranslateText_NullFrontend_Throws()
    {
        var cache = new TrustPolicyTranslatorCache();
        Assert.Throws<System.ArgumentNullException>(() => cache.TranslateText(null!, DocA, new TrustPolicyTranslationContext()));
    }

    [Test]
    public void TranslateText_NullText_Throws()
    {
        var cache = new TrustPolicyTranslatorCache();
        Assert.Throws<System.ArgumentNullException>(() => cache.TranslateText(new CoseTpJsonFrontend(), null!, new TrustPolicyTranslationContext()));
    }

    [Test]
    public void TranslateText_NullCtx_Throws()
    {
        var cache = new TrustPolicyTranslatorCache();
        Assert.Throws<System.ArgumentNullException>(() => cache.TranslateText(new CoseTpJsonFrontend(), DocA, null!));
    }

    [Test]
    public void TranslateText_HitReturnsSameInstance_OnCacheHit()
    {
        var cache = new TrustPolicyTranslatorCache();
        var f = new CoseTpJsonFrontend();
        var ctx = new TrustPolicyTranslationContext();

        TrustPolicyTranslationResult first = cache.TranslateText(f, DocA, ctx);
        TrustPolicyTranslationResult second = cache.TranslateText(f, DocA, ctx);

        Assert.That(second, Is.SameAs(first));
        Assert.That(cache.Count, Is.EqualTo(1));
    }

    [Test]
    public void TranslateText_DifferentDocs_StoresBoth()
    {
        var cache = new TrustPolicyTranslatorCache();
        var f = new CoseTpJsonFrontend();
        var ctx = new TrustPolicyTranslationContext();

        _ = cache.TranslateText(f, DocA, ctx);
        _ = cache.TranslateText(f, DocB, ctx);
        Assert.That(cache.Count, Is.EqualTo(2));
    }

    [Test]
    public void TranslateText_EvictsLruWhenCapacityExceeded()
    {
        var cache = new TrustPolicyTranslatorCache(new TrustPolicyTranslatorOptions { CacheCapacity = 1 });
        var f = new CoseTpJsonFrontend();
        var ctx = new TrustPolicyTranslationContext();

        TrustPolicyTranslationResult a1 = cache.TranslateText(f, DocA, ctx);
        TrustPolicyTranslationResult b1 = cache.TranslateText(f, DocB, ctx);
        Assert.That(cache.Count, Is.EqualTo(1));

        // Re-translating DocA must NOT reuse the evicted entry — it should be re-translated
        // (a fresh instance, not Same as a1).
        TrustPolicyTranslationResult a2 = cache.TranslateText(f, DocA, ctx);
        Assert.That(a2, Is.Not.SameAs(a1));
    }

    [Test]
    public void TranslateText_KeySensitiveToParameters()
    {
        var cache = new TrustPolicyTranslatorCache();
        var f = new CoseTpJsonFrontend();

        var p1 = new TrustPolicyTranslationContext { Parameters = new Dictionary<string, JsonNode> { ["x"] = JsonValue.Create(1) } };
        var p2 = new TrustPolicyTranslationContext { Parameters = new Dictionary<string, JsonNode> { ["x"] = JsonValue.Create(2) } };

        _ = cache.TranslateText(f, DocA, p1);
        _ = cache.TranslateText(f, DocA, p2);
        Assert.That(cache.Count, Is.EqualTo(2));
    }

    [Test]
    public void TranslateText_KeyOrderInsensitiveForParameters()
    {
        var cache = new TrustPolicyTranslatorCache();
        var f = new CoseTpJsonFrontend();

        var p1 = new TrustPolicyTranslationContext
        {
            Parameters = new Dictionary<string, JsonNode>
            {
                ["a"] = JsonValue.Create(1),
                ["b"] = JsonValue.Create(2),
            },
        };
        var p2 = new TrustPolicyTranslationContext
        {
            Parameters = new Dictionary<string, JsonNode>
            {
                ["b"] = JsonValue.Create(2),
                ["a"] = JsonValue.Create(1),
            },
        };

        TrustPolicyTranslationResult r1 = cache.TranslateText(f, DocA, p1);
        TrustPolicyTranslationResult r2 = cache.TranslateText(f, DocA, p2);
        Assert.That(r2, Is.SameAs(r1));
    }

    [Test]
    public void TranslateText_KeySensitiveToFactCapabilities()
    {
        var cache = new TrustPolicyTranslatorCache();
        var f = new CoseTpJsonFrontend();

        var c1 = new TrustPolicyTranslationContext
        {
            AvailableFacts = new FactCapabilities { AvailableFactIds = new HashSet<string> { "f/v1" } },
        };
        var c2 = new TrustPolicyTranslationContext
        {
            AvailableFacts = new FactCapabilities { AvailableFactIds = new HashSet<string> { "g/v1" } },
        };

        _ = cache.TranslateText(f, DocA, c1);
        _ = cache.TranslateText(f, DocA, c2);
        Assert.That(cache.Count, Is.EqualTo(2));
    }

    [Test]
    public void TranslateText_KeySensitiveToPredicateSchemas()
    {
        var cache = new TrustPolicyTranslatorCache();
        var f = new CoseTpJsonFrontend();

        var c1 = new TrustPolicyTranslationContext
        {
            AvailableFacts = new FactCapabilities
            {
                AvailableFactIds = new HashSet<string> { "f/v1" },
                PredicateSchemas = new Dictionary<string, JsonNode> { ["f/v1"] = JsonNode.Parse("""{"type":"object"}""")! },
            },
        };
        var c2 = new TrustPolicyTranslationContext
        {
            AvailableFacts = new FactCapabilities
            {
                AvailableFactIds = new HashSet<string> { "f/v1" },
                PredicateSchemas = new Dictionary<string, JsonNode> { ["f/v1"] = JsonNode.Parse("""{"type":"array"}""")! },
            },
        };

        _ = cache.TranslateText(f, DocA, c1);
        _ = cache.TranslateText(f, DocA, c2);
        Assert.That(cache.Count, Is.EqualTo(2));
    }

    [Test]
    public void TranslateText_KeySensitiveToAllowUnknownFacts()
    {
        var cache = new TrustPolicyTranslatorCache();
        var f = new CoseTpJsonFrontend();

        var caps = new FactCapabilities { AvailableFactIds = new HashSet<string> { "f/v1" } };
        var c1 = new TrustPolicyTranslationContext { AvailableFacts = caps, AllowUnknownFacts = false };
        var c2 = new TrustPolicyTranslationContext { AvailableFacts = caps, AllowUnknownFacts = true };

        _ = cache.TranslateText(f, DocA, c1);
        _ = cache.TranslateText(f, DocA, c2);
        Assert.That(cache.Count, Is.EqualTo(2));
    }

    [Test]
    public void TranslateText_KeySensitiveToDocumentSource()
    {
        var cache = new TrustPolicyTranslatorCache();
        var f = new CoseTpJsonFrontend();
        var ctx = new TrustPolicyTranslationContext();

        _ = cache.TranslateText(f, DocA, ctx, "src1");
        _ = cache.TranslateText(f, DocA, ctx, "src2");
        Assert.That(cache.Count, Is.EqualTo(2));
    }
}
