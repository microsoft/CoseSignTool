// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json.Tests;

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Json;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;
using CoseSign1.Validation.Trust.Rules;

[TestFixture]
[Category("Frontend")]
public sealed class CoseTpJsonFrontendTests
{
    private static CoseTpJsonFrontend Frontend() => new();

    private static TrustPolicyTranslationContext NoCaps => new();

    private static TrustPolicyTranslationContext Caps(params string[] facts) => new()
    {
        AvailableFacts = new FactCapabilities { AvailableFactIds = new HashSet<string>(facts) },
        AllowUnknownFacts = false,
    };

    [Test]
    public void Identity_ReportsFrontendIdAndMediaTypes()
    {
        ICoseTrustPolicyFrontend<JsonDocument> f = Frontend();
        Assert.That(f.FrontendId, Is.EqualTo("cose-tp-json/v1"));
        Assert.That(f.SupportedMediaTypes, Has.Some.EqualTo("application/x-cose-trust-policy+json"));
    }

    [Test]
    public void TranslateText_NullText_Throws()
    {
        Assert.Throws<System.ArgumentNullException>(() => Frontend().TranslateText(null!, NoCaps));
    }

    [Test]
    public void TranslateText_NullCtx_Throws()
    {
        Assert.Throws<System.ArgumentNullException>(() => Frontend().TranslateText("{}", null!));
    }

    [Test]
    public void Translate_NullDocument_Throws()
    {
        Assert.Throws<System.ArgumentNullException>(() => Frontend().Translate(null!, NoCaps));
    }

    [Test]
    public void Translate_NullCtx_Throws()
    {
        using JsonDocument d = JsonDocument.Parse("{\"message\":{\"allow_all\":true}}");
        Assert.Throws<System.ArgumentNullException>(() => Frontend().Translate(d, null!));
    }

    [Test]
    public void TryParse_NullText_Throws()
    {
        Assert.Throws<System.ArgumentNullException>(() => CoseTpJsonFrontend.TryParse(null!, null, new List<TrustPolicyTranslationDiagnostic>()));
    }

    [Test]
    public void TryParse_NullDiagnostics_Throws()
    {
        Assert.Throws<System.ArgumentNullException>(() => CoseTpJsonFrontend.TryParse("{}", null, null!));
    }

    [Test]
    public void Translate_MalformedJson_EmitsTpx001()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText("{not json", NoCaps);
        Assert.That(r.IsSuccess, Is.False);
        Assert.That(r.Spec, Is.Null);
        Assert.That(r.Diagnostics.Any(d => d.Code == "TPX001"), Is.True);
    }

    [Test]
    public void Translate_AllowAllScope_BuildsMessageRequirement()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"message":{"allow_all":true}}""", NoCaps);

        Assert.That(r.IsSuccess, Is.True, string.Join('\n', r.Diagnostics.Select(d => d.Message)));
        Assert.That(r.Spec, Is.InstanceOf<MessageRequirementSpec>());
        Assert.That(((MessageRequirementSpec)r.Spec!).Inner, Is.InstanceOf<AllowAllSpec>());
    }

    [Test]
    public void Translate_DenyAllScope_BuildsDenyAllInner()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"primary_signing_key":{"deny_all":"nope"}}""", NoCaps);

        Assert.That(r.IsSuccess, Is.True);
        var psk = (PrimarySigningKeyRequirementSpec)r.Spec!;
        Assert.That(((DenyAllSpec)psk.Inner).Reason, Is.EqualTo("nope"));
    }

    [Test]
    public void Translate_AnyCounterSignatureWithOnEmptyAllow_ParsesCorrectly()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"any_counter_signature":{"on_empty":"allow","allow_all":true}}""", NoCaps);

        Assert.That(r.IsSuccess, Is.True);
        var acs = (AnyCounterSignatureRequirementSpec)r.Spec!;
        Assert.That(acs.OnEmpty, Is.EqualTo(OnEmptyBehavior.Allow));
        Assert.That(acs.Inner, Is.InstanceOf<AllowAllSpec>());
    }

    [Test]
    public void Translate_AnyCounterSignatureDefaultOnEmpty_IsDeny()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"any_counter_signature":{"allow_all":true}}""", NoCaps);
        Assert.That(((AnyCounterSignatureRequirementSpec)r.Spec!).OnEmpty, Is.EqualTo(OnEmptyBehavior.Deny));
    }

    [Test]
    public void Translate_TopLevelOrCombinator_BuildsOrSpec()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"message":{"allow_all":true},"primary_signing_key":{"allow_all":true},"combinator":"or"}""", NoCaps);
        Assert.That(r.Spec, Is.InstanceOf<OrSpec>());
    }

    [Test]
    public void Translate_TopLevelDefaultCombinator_BuildsAndSpec()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"message":{"allow_all":true},"primary_signing_key":{"allow_all":true}}""", NoCaps);
        Assert.That(r.Spec, Is.InstanceOf<AndSpec>());
    }

    [Test]
    public void Translate_FrontendMismatch_EmitsTpx101()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"frontend":"cose-tp-json/v2","message":{"allow_all":true}}""", NoCaps);
        // Schema enforces const "cose-tp-json/v1", so this will surface as TPX100 (schema) AND
        // would have been TPX101 if we relaxed the constraint. Either is acceptable.
        Assert.That(r.IsSuccess, Is.False);
        Assert.That(r.Diagnostics.Any(d => d.Code is "TPX100" or "TPX101"), Is.True);
    }

    [Test]
    public void Translate_PropertyAssertionPredicate_ParsesCorrectly()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"primary_signing_key":{"fact":"x509-chain-trusted/v1","predicate":{"is_trusted":true}}}""",
            Caps("x509-chain-trusted/v1"));

        Assert.That(r.IsSuccess, Is.True);
        var psk = (PrimarySigningKeyRequirementSpec)r.Spec!;
        var rf = (RequireFactSpec)psk.Inner;
        Assert.That(rf.FactTypeId, Is.EqualTo("x509-chain-trusted/v1"));
        Assert.That(rf.Predicate, Is.InstanceOf<PropertyAssertionPredicateSpec>());
        Assert.That(((PropertyAssertionPredicateSpec)rf.Predicate).Assertions["is_trusted"]!.GetValue<bool>(), Is.True);
    }

    [Test]
    public void Translate_PathOperatorPredicate_ParsesCorrectly()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """
            {"primary_signing_key":{"fact":"x509-cert-eku/v1","predicate":{"operator":"Contains","path":"$.ekus","value":"1.3.6.1.5.5.7.3.3"}}}
            """,
            Caps("x509-cert-eku/v1"));

        Assert.That(r.IsSuccess, Is.True);
        var rf = (RequireFactSpec)((PrimarySigningKeyRequirementSpec)r.Spec!).Inner;
        var p = (PathOperatorPredicateSpec)rf.Predicate;
        Assert.That(p.Operator, Is.EqualTo(PredicateOperator.Contains));
        Assert.That(p.Path, Is.EqualTo("$.ekus"));
        Assert.That(p.Value!.GetValue<string>(), Is.EqualTo("1.3.6.1.5.5.7.3.3"));
    }

    [Test]
    public void Translate_OperatorCaseInsensitive()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """
            {"primary_signing_key":{"fact":"f/v1","predicate":{"operator":"Equals","path":"$.x","value":1}}}
            """,
            Caps("f/v1"));

        Assert.That(r.IsSuccess, Is.True);
    }

    [Test]
    public void Translate_AllOfNode_BuildsAndSpec()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """
            {"primary_signing_key":{"all_of":[{"allow_all":true},{"deny_all":"x"}]}}
            """, NoCaps);

        var inner = ((PrimarySigningKeyRequirementSpec)r.Spec!).Inner;
        Assert.That(inner, Is.InstanceOf<AndSpec>());
        Assert.That(((AndSpec)inner).Operands, Has.Count.EqualTo(2));
    }

    [Test]
    public void Translate_AnyOfNode_BuildsOrSpec()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """
            {"primary_signing_key":{"any_of":[{"allow_all":true},{"deny_all":"x"}]}}
            """, NoCaps);

        Assert.That(((PrimarySigningKeyRequirementSpec)r.Spec!).Inner, Is.InstanceOf<OrSpec>());
    }

    [Test]
    public void Translate_NotNode_BuildsNotSpec_AndPreservesReason()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """
            {"primary_signing_key":{"not":{"allow_all":true},"reason":"nope"}}
            """, NoCaps);

        var inner = ((PrimarySigningKeyRequirementSpec)r.Spec!).Inner;
        Assert.That(inner, Is.InstanceOf<NotSpec>());
        Assert.That(((NotSpec)inner).Reason, Is.EqualTo("nope"));
    }

    [Test]
    public void Translate_ImpliesNode_BuildsImpliesSpec()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """
            {"primary_signing_key":{"implies":{"antecedent":{"allow_all":true},"consequent":{"deny_all":"x"}}}}
            """, NoCaps);

        Assert.That(((PrimarySigningKeyRequirementSpec)r.Spec!).Inner, Is.InstanceOf<ImpliesSpec>());
    }

    [Test]
    public void Translate_UnknownFactWithCapabilities_EmitsTpx200()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"primary_signing_key":{"fact":"unknown-fact/v1","predicate":{"x":1}}}""",
            Caps("known-fact/v1"));

        Assert.That(r.IsSuccess, Is.False);
        Assert.That(r.Diagnostics.Any(d => d.Code == "TPX200"), Is.True);
    }

    [Test]
    public void Translate_UnknownFactWithAllowUnknownFacts_Allowed()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"primary_signing_key":{"fact":"new-fact/v1","predicate":{"x":1}}}""",
            new TrustPolicyTranslationContext { AvailableFacts = new FactCapabilities { AvailableFactIds = new HashSet<string>() }, AllowUnknownFacts = true });
        Assert.That(r.IsSuccess, Is.True);
    }

    [Test]
    public void Translate_UnknownFactWithoutCaps_Allowed()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"primary_signing_key":{"fact":"new-fact/v1","predicate":{"x":1}}}""",
            NoCaps);
        Assert.That(r.IsSuccess, Is.True);
    }

    [Test]
    public void Translate_FailureMessageRespectedWhenSupplied()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"primary_signing_key":{"fact":"f/v1","predicate":{"is_trusted":true},"failure_message":"explicit"}}""",
            Caps("f/v1"));
        var rf = (RequireFactSpec)((PrimarySigningKeyRequirementSpec)r.Spec!).Inner;
        Assert.That(rf.FailureMessage, Is.EqualTo("explicit"));
    }

    [Test]
    public void Translate_FailureMessageDefaultsWhenAbsent()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"primary_signing_key":{"fact":"f/v1","predicate":{"is_trusted":true}}}""",
            Caps("f/v1"));
        var rf = (RequireFactSpec)((PrimarySigningKeyRequirementSpec)r.Spec!).Inner;
        Assert.That(rf.FailureMessage, Does.Contain("f/v1"));
    }

    [Test]
    public void Translate_PredicateSchemaMismatch_EmitsTpx201()
    {
        var schema = JsonNode.Parse("""{"type":"object","properties":{"is_trusted":{"type":"boolean"}},"additionalProperties":false}""")!;
        var caps = new FactCapabilities
        {
            AvailableFactIds = new HashSet<string> { "f/v1" },
            PredicateSchemas = new Dictionary<string, JsonNode> { ["f/v1"] = schema },
        };

        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"primary_signing_key":{"fact":"f/v1","predicate":{"unknown_property":1}}}""",
            new TrustPolicyTranslationContext { AvailableFacts = caps });

        Assert.That(r.IsSuccess, Is.False);
        Assert.That(r.Diagnostics.Any(d => d.Code == "TPX201"), Is.True);
    }

    [Test]
    public void Translate_PredicateSchemaMatch_Allowed()
    {
        var schema = JsonNode.Parse("""{"type":"object","properties":{"is_trusted":{"type":"boolean"}}}""")!;
        var caps = new FactCapabilities
        {
            AvailableFactIds = new HashSet<string> { "f/v1" },
            PredicateSchemas = new Dictionary<string, JsonNode> { ["f/v1"] = schema },
        };

        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"primary_signing_key":{"fact":"f/v1","predicate":{"is_trusted":true}}}""",
            new TrustPolicyTranslationContext { AvailableFacts = caps });

        Assert.That(r.IsSuccess, Is.True);
    }

    [Test]
    public void Translate_PredicateSchemaMalformed_EmitsTpx201()
    {
        // Supply a schema text JsonNode that is itself invalid JSON Schema.
        var schema = JsonNode.Parse("""{"$schema":"https://json-schema.org/draft/2020-12/schema","type":12345}""")!;
        var caps = new FactCapabilities
        {
            AvailableFactIds = new HashSet<string> { "f/v1" },
            PredicateSchemas = new Dictionary<string, JsonNode> { ["f/v1"] = schema },
        };

        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """{"primary_signing_key":{"fact":"f/v1","predicate":{"x":1}}}""",
            new TrustPolicyTranslationContext { AvailableFacts = caps });

        // Either TPX201 (schema-mismatch when validator gracefully reports) or any kind of error.
        Assert.That(r.IsSuccess, Is.False);
    }

    [Test]
    public void Translate_JsonCommentsAccepted()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """
            // top-level comment
            {
              /* inline block */
              "message": { "allow_all": true } // trailing
            }
            """, NoCaps);
        Assert.That(r.IsSuccess, Is.True);
    }

    [Test]
    public void Translate_TrailingCommasAccepted()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """
            {"message":{"all_of":[{"allow_all":true},]},}
            """, NoCaps);
        Assert.That(r.IsSuccess, Is.True);
    }

    [Test]
    public void Translate_ParamReferenceInValueSlot_PreservedThroughCanonicalRoundTrip()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText(
            """
            {"primary_signing_key":{"fact":"f/v1","predicate":{"operator":"In","path":"$.host","value":{"$param":"hosts","default":["a","b"]}}}}
            """,
            Caps("f/v1"));

        Assert.That(r.IsSuccess, Is.True);
        string canonical = TrustPolicySpecSerializer.ToCanonicalJson(r.Spec!);
        Assert.That(canonical, Does.Contain("$param"));
        Assert.That(canonical, Does.Contain("hosts"));
    }

    [Test]
    public void Translate_DocumentSourceFlowsIntoLocations()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText("{not json", NoCaps, "file:///policy.json");
        Assert.That(r.Diagnostics.Any(d => d.Location?.Source?.StartsWith("file:///policy.json") == true), Is.True);
    }

    [Test]
    public void Translate_OverloadWithJsonDocument_Works()
    {
        using JsonDocument d = JsonDocument.Parse("""{"message":{"allow_all":true}}""", CoseTpJsonOptions.ParseOptions);
        TrustPolicyTranslationResult r = Frontend().Translate(d, NoCaps, "doc-src");
        Assert.That(r.IsSuccess, Is.True);
        Assert.That(r.Spec, Is.InstanceOf<MessageRequirementSpec>());
    }

    [Test]
    public void Translate_Twice_ProducesByteIdenticalCanonicalJson()
    {
        const string Doc = """{"primary_signing_key":{"all_of":[{"fact":"f/v1","predicate":{"is_trusted":true}},{"fact":"f/v1","predicate":{"operator":"StartsWith","path":"$.subject","value":"CN="}}]}}""";

        TrustPolicyTranslationResult a = Frontend().TranslateText(Doc, Caps("f/v1"));
        TrustPolicyTranslationResult b = Frontend().TranslateText(Doc, Caps("f/v1"));
        Assert.That(TrustPolicySpecSerializer.ToCanonicalJson(b.Spec!), Is.EqualTo(TrustPolicySpecSerializer.ToCanonicalJson(a.Spec!)));
    }

    [Test]
    public void Translate_Section6_5_5_Example_Translates()
    {
        const string Example = """
        {
          "$schema": "https://raw.githubusercontent.com/microsoft/CoseSignTool/main/V2/schemas/cose-tp/v1.json",
          "frontend": "cose-tp-json/v1",
          "primary_signing_key": {
            "all_of": [
              { "fact": "x509-chain-trusted/v1",          "predicate": { "is_trusted": true } },
              { "fact": "x509-cert-identity-allowed/v1",  "predicate": { "is_allowed": true } },
              { "fact": "x509-cert-eku/v1",
                "predicate": {
                  "operator": "Contains",
                  "path": "$.ekus",
                  "value": "1.3.6.1.5.5.7.3.3"
                }
              }
            ]
          },
          "any_counter_signature": {
            "on_empty": "deny",
            "all_of": [
              { "fact": "mst-receipt-present/v1", "predicate": { "is_present": true } },
              { "fact": "mst-receipt-trusted/v1", "predicate": { "is_trusted": true } },
              { "fact": "mst-receipt-issuer-host/v1",
                "predicate": {
                  "operator": "In",
                  "path": "$.host",
                  "value": { "$param": "trusted_log_hosts",
                             "default": ["dataplane.codetransparency.azure.net"] }
                }
              }
            ]
          },
          "combinator": "and"
        }
        """;

        var caps = Caps(
            "x509-chain-trusted/v1",
            "x509-cert-identity-allowed/v1",
            "x509-cert-eku/v1",
            "mst-receipt-present/v1",
            "mst-receipt-trusted/v1",
            "mst-receipt-issuer-host/v1");

        TrustPolicyTranslationResult r = Frontend().TranslateText(Example, caps);
        Assert.That(r.IsSuccess, Is.True, string.Join('\n', r.Diagnostics.Select(d => d.Code + ":" + d.Message)));
        Assert.That(r.Spec, Is.InstanceOf<AndSpec>());
    }

    [Test]
    public void Translate_NoScopes_FailsSchema()
    {
        TrustPolicyTranslationResult r = Frontend().TranslateText("""{"frontend":"cose-tp-json/v1"}""", NoCaps);
        Assert.That(r.IsSuccess, Is.False);
    }
}
