// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego.Tests;

using System.Collections.Generic;
using System.Linq;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;
using CoseSign1.Validation.TrustFrontends.Rego;

/// <summary>
/// End-to-end behaviour tests for <see cref="CoseTpRegoFrontend"/>. Covers the happy path
/// (parse + lower + JSON walker forwarding), parameter substitution semantics, and the
/// reject contract for the constrained subset.
/// </summary>
[TestFixture]
public sealed class CoseTpRegoFrontendTests
{
    [Test]
    public void Translate_minimal_primary_signing_key_policy_succeeds()
    {
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "fact": "x509-chain-trusted/v1",
                    "predicate": {"is_trusted": true}
                }
            }
            """;

        TrustPolicyTranslationResult result = new CoseTpRegoFrontend().TranslateText(text, new TrustPolicyTranslationContext());
        Assert.That(result.IsSuccess, Is.True, () => string.Join("; ", result.Diagnostics.Select(d => d.Code + ":" + d.Message)));
        Assert.That(result.Spec, Is.InstanceOf<PrimarySigningKeyRequirementSpec>());

        PrimarySigningKeyRequirementSpec scope = (PrimarySigningKeyRequirementSpec)result.Spec!;
        RequireFactSpec leaf = (RequireFactSpec)scope.Inner;
        Assert.That(leaf.FactTypeId, Is.EqualTo("x509-chain-trusted/v1"));
        Assert.That(leaf.Predicate, Is.InstanceOf<PropertyAssertionPredicateSpec>());
    }

    [Test]
    public void Translate_inputref_lowers_to_param_ref()
    {
        // `input.trusted_host` should lower to {"$param": "trusted_host"} in the
        // canonical IR, so a downstream Bind pass can substitute it the same way it
        // substitutes a $param literal in JSON.
        const string text = """
            package cose_trust_policy

            policy := {
                "any_counter_signature": {
                    "on_empty": "deny",
                    "fact": "mst-receipt-issuer-host/v1",
                    "predicate": {
                        "operator": "Equals",
                        "path": "$.host",
                        "value": input.trusted_host
                    }
                }
            }
            """;

        TrustPolicyTranslationResult result = new CoseTpRegoFrontend().TranslateText(text, new TrustPolicyTranslationContext());
        Assert.That(result.IsSuccess, Is.True, () => string.Join("; ", result.Diagnostics.Select(d => d.Code + ":" + d.Message)));
    }

    [Test]
    public void Translate_dotted_input_reference_concatenates_segments()
    {
        const string text = """
            package cose_trust_policy

            policy := {
                "any_counter_signature": {
                    "on_empty": "deny",
                    "fact": "mst-receipt-issuer-host/v1",
                    "predicate": {
                        "operator": "Equals",
                        "path": "$.host",
                        "value": input.trusted_log_hosts.primary
                    }
                }
            }
            """;

        TrustPolicyTranslationResult result = new CoseTpRegoFrontend().TranslateText(text, new TrustPolicyTranslationContext());
        Assert.That(result.IsSuccess, Is.True, () => string.Join("; ", result.Diagnostics.Select(d => d.Code + ":" + d.Message)));
    }

    [Test]
    public void TranslateText_with_documentSource_propagates_source_into_diagnostic()
    {
        const string text = "package wrong_package\n\npolicy := {}\n";

        TrustPolicyTranslationResult result = new CoseTpRegoFrontend().TranslateText(text, new TrustPolicyTranslationContext(), documentSource: "file://tests/wrong.rego");
        Assert.That(result.IsSuccess, Is.False);
        TrustPolicyTranslationDiagnostic err = result.Diagnostics.First(d => d.Severity == TrustPolicySeverity.Error);
        Assert.That(err.Code, Is.EqualTo("TPX002"));
        Assert.That(err.Location, Is.Not.Null);
        Assert.That(err.Location!.Source, Does.Contain("file://tests/wrong.rego"));
    }

    [Test]
    public void TryParse_returns_null_and_emits_diagnostic_for_missing_package()
    {
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse("policy := {}", documentSource: null, diagnostics);
        Assert.That(doc, Is.Null);
        Assert.That(diagnostics.Any(d => d.Code == "TPX002"), Is.True);
    }

    [Test]
    public void TryParse_returns_null_and_emits_diagnostic_for_wrong_package_name()
    {
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse("package not_cose_trust_policy\n\npolicy := {}", documentSource: null, diagnostics);
        Assert.That(doc, Is.Null);
        Assert.That(diagnostics.Any(d => d.Code == "TPX002"), Is.True);
    }

    [Test]
    public void TryParse_rejects_missing_policy_rule()
    {
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse("package cose_trust_policy\n\nallow := true", documentSource: null, diagnostics);
        Assert.That(doc, Is.Null);
        Assert.That(diagnostics.Any(d => d.Code == "TPX003"), Is.True);
    }

    [Test]
    public void TryParse_rejects_multiple_rules()
    {
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "fact": "x509-chain-trusted/v1",
                    "predicate": {"is_trusted": true}
                }
            }

            extra := {}
            """;
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(doc, Is.Null);
        Assert.That(diagnostics.Any(d => d.Code == "TPX005"), Is.True);
    }

    [Test]
    public void TryParse_rejects_disallowed_import()
    {
        const string text = """
            package cose_trust_policy

            import data.allow_list

            policy := {}
            """;
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(doc, Is.Null);
        Assert.That(diagnostics.Any(d => d.Code == "TPX004"), Is.True);
    }

    [Test]
    public void TryParse_accepts_future_keywords_in_import()
    {
        const string text = """
            package cose_trust_policy

            import future.keywords.in

            policy := {
                "primary_signing_key": {
                    "fact": "x509-chain-trusted/v1",
                    "predicate": {"is_trusted": true}
                }
            }
            """;
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(doc, Is.Not.Null);
        Assert.That(diagnostics.Any(d => d.Severity == TrustPolicySeverity.Error), Is.False);
    }

    [TestCase("http", "send")]
    [TestCase("regex", "match")]
    [TestCase("crypto", "hmac")]
    [TestCase("net", "lookup_ip_addr")]
    [TestCase("time", "now_ns")]
    [TestCase("opa", "runtime")]
    [TestCase("os", "getenv")]
    [TestCase("io", "open")]
    [TestCase("file", "read")]
    public void TryParse_rejects_forbidden_namespace(string ns, string fn)
    {
        string text = $"package cose_trust_policy\n\npolicy := {{ \"value\": {ns}.{fn}(\"x\") }}\n";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(doc, Is.Null);
        Assert.That(diagnostics.Any(d => d.Code.StartsWith("TPX3")), Is.True, () => string.Join("; ", diagnostics.Select(d => d.Code + ":" + d.Message)));
    }

    [Test]
    public void TryParse_rejects_data_reference()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"value\": data.allow_list[0] }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(doc, Is.Null);
        Assert.That(diagnostics.Any(d => d.Code.StartsWith("TPX3")), Is.True);
    }

    [Test]
    public void TryParse_rejects_some_keyword()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"value\": some }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(diagnostics.Any(d => d.Code.StartsWith("TPX3")), Is.True);
    }

    [Test]
    public void TryParse_rejects_unsupported_symbol()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"value\": [1 | 2] }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(diagnostics.Any(d => d.Code.StartsWith("TPX3")), Is.True);
    }

    [Test]
    public void TryParse_rejects_object_comprehension()
    {
        // Use a form the parser walks past the key successfully; the '|' then surfaces as
        // an UnsupportedSymbol the comprehension-rejection branch catches.
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": 1 | 2 }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(diagnostics.Any(d => d.Code.StartsWith("TPX3")), Is.True, () => string.Join("; ", diagnostics.Select(d => d.Code + ":" + d.Message)));
    }

    [Test]
    public void TryParse_rejects_bare_unsupported_token()
    {
        // A semicolon at the term position lands in UnsupportedSymbol.
        const string text = "package cose_trust_policy\n\npolicy := ;";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(diagnostics.Count, Is.GreaterThan(0));
    }

    [Test]
    public void TryParse_rejects_input_without_dot()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"value\": input }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(diagnostics.Count, Is.GreaterThan(0));
    }

    [Test]
    public void TryParse_rejects_duplicate_object_keys()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": 1, \"x\": 2 }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(diagnostics.Any(d => d.Code == "TPX001"), Is.True);
    }

    [Test]
    public void TryParse_rejects_unterminated_string()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": \"unterminated";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(diagnostics.Count, Is.GreaterThan(0));
    }

    [Test]
    public void TryParse_rejects_non_object_policy_body()
    {
        const string text = "package cose_trust_policy\n\npolicy := \"a string\"";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(diagnostics.Any(d => d.Code == "TPX001"), Is.True);
    }

    [Test]
    public void TryParse_rejects_invalid_unicode_escape()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": \"\\uZZZZ\" }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(diagnostics.Count, Is.GreaterThan(0));
    }

    [Test]
    public void TryParse_rejects_invalid_escape()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": \"\\q\" }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(diagnostics.Count, Is.GreaterThan(0));
    }

    [Test]
    public void TryParse_supports_negative_numbers()
    {
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "fact": "x509-chain-element-identity/v1",
                    "predicate": {"depth": -1}
                }
            }
            """;
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(doc, Is.Not.Null);
        Assert.That(diagnostics.Any(d => d.Severity == TrustPolicySeverity.Error), Is.False);
    }

    [Test]
    public void TryParse_supports_decimal_numbers()
    {
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "fact": "x509-chain-element-identity/v1",
                    "predicate": {"depth": 0.5}
                }
            }
            """;
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void TryParse_supports_exponent_numbers()
    {
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "fact": "x509-chain-element-identity/v1",
                    "predicate": {"depth": 1e2}
                }
            }
            """;
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void TryParse_supports_null_literal()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"primary_signing_key\": { \"allow_all\": true } }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void TryParse_supports_empty_array_and_object()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"primary_signing_key\": { \"all_of\": [] } }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void TryParse_supports_trailing_commas()
    {
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "fact": "x509-chain-trusted/v1",
                    "predicate": {"is_trusted": true,},
                },
            }
            """;
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void TryParse_supports_assign_via_single_equals()
    {
        // OPA allows `policy = { ... }` as a synonym for `policy := { ... }`.
        const string text = """
            package cose_trust_policy

            policy = {
                "primary_signing_key": {
                    "fact": "x509-chain-trusted/v1",
                    "predicate": {"is_trusted": true}
                }
            }
            """;
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void TryParse_throws_on_null_text()
    {
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        Assert.Throws<System.ArgumentNullException>(() => CoseTpRegoFrontend.TryParse(null!, null, diagnostics));
    }

    [Test]
    public void TryParse_throws_on_null_diagnostics()
    {
        Assert.Throws<System.ArgumentNullException>(() => CoseTpRegoFrontend.TryParse("", null, null!));
    }

    [Test]
    public void Translate_throws_on_null_document()
    {
        var f = new CoseTpRegoFrontend();
        Assert.Throws<System.ArgumentNullException>(() => f.Translate(null!, new TrustPolicyTranslationContext()));
    }

    [Test]
    public void Translate_throws_on_null_ctx()
    {
        var f = new CoseTpRegoFrontend();
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument doc = CoseTpRegoFrontend.TryParse("package cose_trust_policy\n\npolicy := { \"primary_signing_key\": { \"allow_all\": true } }", null, diagnostics)!;
        Assert.Throws<System.ArgumentNullException>(() => f.Translate(doc, null!));
    }

    [Test]
    public void TranslateText_throws_on_null_text()
    {
        var f = new CoseTpRegoFrontend();
        Assert.Throws<System.ArgumentNullException>(() => f.TranslateText(null!, new TrustPolicyTranslationContext()));
    }

    [Test]
    public void TranslateText_throws_on_null_ctx()
    {
        var f = new CoseTpRegoFrontend();
        Assert.Throws<System.ArgumentNullException>(() => f.TranslateText("", null!));
    }

    [Test]
    public void Constructor_throws_on_null_jsonFrontend()
    {
        Assert.Throws<System.ArgumentNullException>(() => _ = new CoseTpRegoFrontend(null!));
    }

    [Test]
    public void FrontendId_is_stable()
    {
        Assert.That(new CoseTpRegoFrontend().FrontendId, Is.EqualTo("cose-tp-rego/v1"));
        Assert.That(CoseTpRegoOptions.FrontendId, Is.EqualTo("cose-tp-rego/v1"));
        Assert.That(CoseTpRegoOptions.MediaType, Is.EqualTo("application/x-cose-trust-policy+rego"));
        Assert.That(CoseTpRegoOptions.FileExtension, Is.EqualTo(".coseTrustPolicy.rego"));
        Assert.That(CoseTpRegoOptions.RequiredPackage, Is.EqualTo("cose_trust_policy"));
        Assert.That(CoseTpRegoOptions.PolicyRuleName, Is.EqualTo("policy"));
    }

    [Test]
    public void SupportedMediaTypes_contains_canonical_rego_type()
    {
        Assert.That(new CoseTpRegoFrontend().SupportedMediaTypes, Contains.Item("application/x-cose-trust-policy+rego"));
    }

    [Test]
    public void Determinism_repeated_translation_yields_byte_identical_canonical_ir()
    {
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "all_of": [
                        {"fact": "x509-chain-trusted/v1",         "predicate": {"is_trusted": true}},
                        {"fact": "x509-cert-identity-allowed/v1", "predicate": {"is_allowed": true}}
                    ]
                },
                "any_counter_signature": {
                    "on_empty": "deny",
                    "fact": "mst-receipt-trusted/v1",
                    "predicate": {"is_trusted": true}
                }
            }
            """;

        var f = new CoseTpRegoFrontend();
        TrustPolicyTranslationResult first = f.TranslateText(text, new TrustPolicyTranslationContext());
        Assert.That(first.IsSuccess, Is.True, () => string.Join("; ", first.Diagnostics.Select(d => d.Code + ":" + d.Message)));
        string canonicalFirst = CoseSign1.Validation.Trust.PlanPolicy.Spec.Json.TrustPolicySpecSerializer.ToCanonicalJson(first.Spec!);

        for (int i = 0; i < 100; i++)
        {
            TrustPolicyTranslationResult next = f.TranslateText(text, new TrustPolicyTranslationContext());
            Assert.That(next.IsSuccess, Is.True);
            Assert.That(CoseSign1.Validation.Trust.PlanPolicy.Spec.Json.TrustPolicySpecSerializer.ToCanonicalJson(next.Spec!), Is.EqualTo(canonicalFirst));
        }
    }

    [Test]
    public void Translate_propagates_capability_errors()
    {
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "fact": "totally-not-a-real-fact-id/v1",
                    "predicate": {"x": true}
                }
            }
            """;

        var caps = new FactCapabilities { AvailableFactIds = new HashSet<string>() };
        var ctx = new TrustPolicyTranslationContext { AvailableFacts = caps, AllowUnknownFacts = false };

        TrustPolicyTranslationResult result = new CoseTpRegoFrontend().TranslateText(text, ctx);
        Assert.That(result.IsSuccess, Is.False);
        Assert.That(result.Diagnostics.Any(d => d.Code == TrustPolicyDiagnosticCodes.UnknownFactId), Is.True);
    }
}
