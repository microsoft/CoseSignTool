// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json.Tests;

using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;

[TestFixture]
[Category("Bind")]
public sealed class BindTests
{
    private static CoseTpJsonFrontend Frontend() => new();

    [Test]
    public void Bind_NullResult_Throws()
    {
        TrustPolicyTranslationResult? result = null;
        Assert.Throws<System.ArgumentNullException>(() => result!.Bind(new Dictionary<string, JsonNode?>()));
    }

    [Test]
    public void Bind_NullParams_Throws()
    {
        var result = new TrustPolicyTranslationResult { Spec = null, Diagnostics = new List<TrustPolicyTranslationDiagnostic>() };
        Assert.Throws<System.ArgumentNullException>(() => result.Bind(null!));
    }

    [Test]
    public void Bind_FailedResult_ReturnsResultUnchanged()
    {
        var failed = new TrustPolicyTranslationResult
        {
            Spec = null,
            Diagnostics = new List<TrustPolicyTranslationDiagnostic>
            {
                new() { Severity = TrustPolicySeverity.Error, Code = "TPX001", Message = "x", Location = null },
            },
        };
        TrustPolicyTranslationResult after = failed.Bind(new Dictionary<string, JsonNode?>());
        Assert.That(after, Is.SameAs(failed));
    }

    [Test]
    public void Bind_SubstitutesParamWithSuppliedValue()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"primary_signing_key":{"fact":"f/v1","predicate":{"operator":"Equals","path":"$.host","value":{"$param":"h"}}}}""",
            new TrustPolicyTranslationContext());

        var bindings = new Dictionary<string, JsonNode?> { ["h"] = JsonValue.Create("hosted") };
        TrustPolicyTranslationResult bound = r.Bind(bindings);

        Assert.That(bound.IsSuccess, Is.True);
        string canonical = bound.Spec!.ToString()!; // record string form
        // After bind, $param should be gone from the canonical form.
        Assert.That(CoseSign1.Validation.Trust.PlanPolicy.Spec.Json.TrustPolicySpecSerializer.ToCanonicalJson(bound.Spec!), Does.Not.Contain("$param"));
    }

    [Test]
    public void Bind_MissingParamWithoutDefault_EmitsTpx400()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"primary_signing_key":{"fact":"f/v1","predicate":{"operator":"Equals","path":"$.host","value":{"$param":"h"}}}}""",
            new TrustPolicyTranslationContext());

        TrustPolicyTranslationResult bound = r.Bind(new Dictionary<string, JsonNode?>());
        Assert.That(bound.IsSuccess, Is.False);
        Assert.That(bound.Diagnostics.Any(d => d.Code == TrustPolicyDiagnosticCodes.UnboundParameter), Is.True);
    }

    [Test]
    public void Bind_MissingParamWithDefault_UsesDefault()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"primary_signing_key":{"fact":"f/v1","predicate":{"operator":"Equals","path":"$.host","value":{"$param":"h","default":"fallback"}}}}""",
            new TrustPolicyTranslationContext());

        TrustPolicyTranslationResult bound = r.Bind(new Dictionary<string, JsonNode?>());
        Assert.That(bound.IsSuccess, Is.True);
        Assert.That(CoseSign1.Validation.Trust.PlanPolicy.Spec.Json.TrustPolicySpecSerializer.ToCanonicalJson(bound.Spec!), Does.Contain("fallback"));
    }
}
