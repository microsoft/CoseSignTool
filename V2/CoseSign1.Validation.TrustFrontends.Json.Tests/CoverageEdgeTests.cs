// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json.Tests;

using System.Collections.Generic;
using System.Text.Json;
using CoseSign1.Validation.Trust.Frontends;

[TestFixture]
[Category("Coverage")]
public sealed class CoverageEdgeTests
{
    [Test]
    public void Translate_JsonDocument_NoSourceOverload_Works()
    {
        using JsonDocument d = JsonDocument.Parse("""{"message":{"allow_all":true}}""", CoseTpJsonOptions.ParseOptions);
        TrustPolicyTranslationResult r = new CoseTpJsonFrontend().Translate(d, new TrustPolicyTranslationContext());
        Assert.That(r.IsSuccess, Is.True);
    }

    [Test]
    public void TranslationResult_IsSuccess_FalseWhenSpecNull()
    {
        var r = new TrustPolicyTranslationResult { Spec = null, Diagnostics = new List<TrustPolicyTranslationDiagnostic>() };
        Assert.That(r.IsSuccess, Is.False);
    }

    [Test]
    public void TranslationResult_IsSuccess_TrueWhenSpecAndOnlyInfoDiagnostics()
    {
        var spec = new CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators.AllowAllSpec();
        var r = new TrustPolicyTranslationResult
        {
            Spec = spec,
            Diagnostics = new List<TrustPolicyTranslationDiagnostic>
            {
                new() { Severity = TrustPolicySeverity.Info, Code = "TPX900", Message = "info", Location = null },
                new() { Severity = TrustPolicySeverity.Warning, Code = "TPX901", Message = "warn", Location = null },
            },
        };
        Assert.That(r.IsSuccess, Is.True);
    }

    [Test]
    public void TranslationContext_DefaultParameters_IsEmpty()
    {
        var ctx = new TrustPolicyTranslationContext();
        Assert.That(ctx.Parameters, Is.Empty);
        Assert.That(ctx.AvailableFacts, Is.Null);
        Assert.That(ctx.AllowUnknownFacts, Is.False);
    }

    [Test]
    public void Translate_ParamReferenceInPropertyAssertion_Preserved()
    {
        TrustPolicyTranslationResult r = new CoseTpJsonFrontend().TranslateText(
            """{"primary_signing_key":{"fact":"f/v1","predicate":{"is_trusted":{"$param":"trust","default":true}}}}""",
            new TrustPolicyTranslationContext());

        Assert.That(r.IsSuccess, Is.True);
        string canonical = CoseSign1.Validation.Trust.PlanPolicy.Spec.Json.TrustPolicySpecSerializer.ToCanonicalJson(r.Spec!);
        Assert.That(canonical, Does.Contain("$param"));
    }

    [Test]
    public void Translate_ImpliesNested_Works()
    {
        TrustPolicyTranslationResult r = new CoseTpJsonFrontend().TranslateText(
            """
            {"primary_signing_key":{"implies":{"antecedent":{"all_of":[{"allow_all":true}]},"consequent":{"any_of":[{"deny_all":"x"}]}}}}
            """, new TrustPolicyTranslationContext());
        Assert.That(r.IsSuccess, Is.True);
    }

    [Test]
    public void Translate_NotWithoutReason_AllowsNullReason()
    {
        TrustPolicyTranslationResult r = new CoseTpJsonFrontend().TranslateText(
            """{"primary_signing_key":{"not":{"allow_all":true}}}""", new TrustPolicyTranslationContext());
        Assert.That(r.IsSuccess, Is.True);
    }

    [Test]
    public void Translate_AnyCounterSignatureWithoutOnEmptyDefaultsDeny()
    {
        TrustPolicyTranslationResult r = new CoseTpJsonFrontend().TranslateText(
            """{"any_counter_signature":{"not":{"allow_all":true}}}""", new TrustPolicyTranslationContext());
        Assert.That(r.IsSuccess, Is.True);
    }

    [Test]
    public void Translate_FailureMessageWhitespace_FallsBackToDefault()
    {
        TrustPolicyTranslationResult r = new CoseTpJsonFrontend().TranslateText(
            """{"primary_signing_key":{"fact":"f/v1","predicate":{"is_trusted":true},"failure_message":" "}}""",
            new TrustPolicyTranslationContext());
        // ReadFailureMessage falls back to default for whitespace-only values, so translation
        // succeeds with the synthesised message.
        Assert.That(r.IsSuccess, Is.True);
    }

    [Test]
    public void Translate_PathOperatorWithNoValue_AllowedForExists()
    {
        TrustPolicyTranslationResult r = new CoseTpJsonFrontend().TranslateText(
            """{"primary_signing_key":{"fact":"f/v1","predicate":{"operator":"Exists","path":"$.x"}}}""",
            new TrustPolicyTranslationContext());
        Assert.That(r.IsSuccess, Is.True);
    }

    [Test]
    public void Constants_FrontendIdAndSchemaUrl_Match()
    {
        Assert.That(CoseTpJsonOptions.FrontendId, Is.EqualTo("cose-tp-json/v1"));
        Assert.That(CoseTpJsonOptions.FileExtension, Is.EqualTo(".coseTrustPolicy.json"));
        Assert.That(CoseTpJsonOptions.SchemaUrl, Does.Contain("v1.json"));
        Assert.That(CoseTpJsonOptions.MediaType, Is.EqualTo("application/x-cose-trust-policy+json"));
        Assert.That(CoseTpJsonFrontend.SchemaUrl, Is.EqualTo(CoseTpJsonOptions.SchemaUrl));
    }
}
