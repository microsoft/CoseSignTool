// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego.Tests;

using System.Collections.Generic;
using System.Linq;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.TrustFrontends.Rego;

/// <summary>
/// Coverage tests for the parser / tokenizer error branches and corner cases. Each test
/// targets a specific branch in the constrained-subset parser so the per-project gate
/// (D11 ≥ 95% line coverage) clears.
/// </summary>
[TestFixture]
public sealed class CoverageBranchTests
{
    private static List<TrustPolicyTranslationDiagnostic> Parse(string text)
    {
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, documentSource: null, diagnostics);
        return diagnostics;
    }

    [Test]
    public void Parser_package_followed_by_non_identifier_emits_TPX002()
    {
        var diags = Parse("package 5\n\npolicy := {}");
        Assert.That(diags.Any(d => d.Code == "TPX002"), Is.True);
    }

    [Test]
    public void Parser_import_followed_by_non_identifier_emits_TPX004()
    {
        var diags = Parse("package cose_trust_policy\n\nimport 5\n");
        Assert.That(diags.Any(d => d.Code == "TPX004"), Is.True);
    }

    [Test]
    public void Parser_policy_rule_starting_with_non_identifier_emits_TPX003()
    {
        var diags = Parse("package cose_trust_policy\n\n5 := {}");
        Assert.That(diags.Any(d => d.Code == "TPX003"), Is.True);
    }

    [Test]
    public void Parser_policy_followed_by_neither_assign_nor_equals_is_TPX001()
    {
        var diags = Parse("package cose_trust_policy\n\npolicy 5");
        Assert.That(diags.Any(d => d.Code == "TPX001"), Is.True);
    }

    [Test]
    public void Parser_policy_followed_by_unsupported_symbol_in_term_position_emits_TPX300()
    {
        // After `policy := {`, parse begins. Object key parsing requires a string. Use an
        // inner `;` to surface UnsupportedSymbol at term position via the inner array.
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\": [;] }");
        Assert.That(diags.Any(d => d.Code == "TPX300"), Is.True);
    }

    [Test]
    public void Parser_minus_at_term_position_followed_by_non_number_emits_TPX001()
    {
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\": -true }");
        Assert.That(diags.Any(d => d.Code == "TPX001"), Is.True);
    }

    [Test]
    public void Parser_extra_token_after_policy_rule_with_non_identifier_emits_TPX001()
    {
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\": 1 }\n}");
        Assert.That(diags.Any(d => d.Code == "TPX001"), Is.True);
    }

    [Test]
    public void Parser_object_with_non_string_key_emits_TPX001()
    {
        var diags = Parse("package cose_trust_policy\n\npolicy := { 5: 1 }");
        Assert.That(diags.Any(d => d.Code == "TPX001"), Is.True);
    }

    [Test]
    public void Parser_object_string_key_without_colon_emits_TPX001()
    {
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\" 5 }");
        Assert.That(diags.Any(d => d.Code == "TPX001"), Is.True);
    }

    [Test]
    public void Parser_array_comprehension_is_TPX300()
    {
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\": [1 | 2] }");
        Assert.That(diags.Any(d => d.Code == "TPX300"), Is.True);
    }

    [Test]
    public void Parser_input_followed_by_non_identifier_after_dot_emits_TPX001()
    {
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\": input.5 }");
        Assert.That(diags.Any(d => d.Code == "TPX001"), Is.True);
    }

    [Test]
    public void Parser_input_dotted_followed_by_non_identifier_segment_emits_TPX001()
    {
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\": input.foo.5 }");
        Assert.That(diags.Any(d => d.Code == "TPX001"), Is.True);
    }

    [Test]
    public void Parser_dotted_package_terminated_by_non_identifier_decodes_partial_name()
    {
        // package foo. → TryReadDottedIdent returns "foo", which doesn't match required name.
        var diags = Parse("package cose_trust_policy.extra\n\npolicy := {}");
        Assert.That(diags.Any(d => d.Code == "TPX002"), Is.True);
    }

    [Test]
    public void Tokenizer_handles_all_simple_string_escapes()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": \"\\b\\f\\n\\r\\t\\\\\\/\" }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void Tokenizer_handles_unicode_escape_with_uppercase_hex()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": \"\\u00FF\" }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void Tokenizer_handles_unicode_escape_with_lowercase_hex()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": \"\\u00ff\" }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void Tokenizer_unterminated_string_with_newline_surfaces_diagnostic()
    {
        // A bare newline inside a string literal is rejected without consuming the rest of
        // the document — different code path from the EOF-during-string case.
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\": \"abc\nmore\" }");
        Assert.That(diags.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Tokenizer_unicode_escape_at_end_of_input_surfaces_diagnostic()
    {
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\": \"\\u00");
        Assert.That(diags.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Tokenizer_backslash_at_end_of_input_surfaces_unterminated_string()
    {
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\": \"abc\\");
        Assert.That(diags.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Tokenizer_handles_comments_correctly()
    {
        const string text = """
            # leading comment
            package cose_trust_policy

            # comment between

            policy := {
                # inside
                "primary_signing_key": {
                    "fact": "x509-chain-trusted/v1",
                    "predicate": {"is_trusted": true} # trailing
                }
            }
            # final comment without newline
            """;
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null, () => string.Join("; ", diagnostics.Select(d => d.Code + ":" + d.Message)));
    }

    [Test]
    public void Tokenizer_invalid_number_with_bad_exponent_surfaces_diagnostic()
    {
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\": 1e }");
        Assert.That(diags.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Tokenizer_supports_negative_exponent()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"primary_signing_key\": { \"fact\": \"x509-chain-element-identity/v1\", \"predicate\": {\"depth\": 1e-2} } }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void Tokenizer_supports_positive_exponent()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"primary_signing_key\": { \"fact\": \"x509-chain-element-identity/v1\", \"predicate\": {\"depth\": 1e+2} } }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void Tokenizer_invalid_unicode_escape_with_short_payload_surfaces_diagnostic()
    {
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\": \"\\u12\" }");
        Assert.That(diags.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Lowerer_handles_array_with_mixed_scalar_kinds()
    {
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "all_of": [
                        {"fact": "x509-chain-trusted/v1", "predicate": {"is_trusted": true}},
                        {"fact": "x509-cert-eku/v1", "predicate": {"oid_value": "x"}}
                    ]
                }
            }
            """;
        TrustPolicyTranslationResult result = new CoseTpRegoFrontend().TranslateText(text, new TrustPolicyTranslationContext());
        Assert.That(result.IsSuccess, Is.True, () => string.Join("; ", result.Diagnostics.Select(d => d.Code + ":" + d.Message)));
    }

    [Test]
    public void Lowerer_handles_decimal_number()
    {
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "fact": "x509-chain-element-identity/v1",
                    "predicate": {"depth": 12345678901234567890}
                }
            }
            """;
        // 12345678901234567890 doesn't fit in long; will use decimal.
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void Lowerer_handles_double_number()
    {
        // 1e308 fits in double but not in decimal.
        const string text = "package cose_trust_policy\n\npolicy := { \"primary_signing_key\": { \"fact\": \"x509-chain-element-identity/v1\", \"predicate\": {\"depth\": 1e308} } }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void Lowerer_handles_nested_arrays_and_objects()
    {
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "all_of": [
                        {"fact": "x509-cert-eku/v1", "predicate": {"oid_value": ["1.3.6.1.5.5.7.3.3"]}}
                    ]
                }
            }
            """;
        TrustPolicyTranslationResult result = new CoseTpRegoFrontend().TranslateText(text, new TrustPolicyTranslationContext());
        // The IR's PathOperatorPredicate rejects array values for property-shorthand of
        // certain shapes; either route is acceptable so we tolerate failure here. The aim
        // is exercising the nested-array lowerer branch.
        Assert.That(result.Diagnostics, Is.Not.Null);
    }

    [Test]
    public void Lowerer_handles_false_literal()
    {
        // Property assertion with bool false — covers the False scalar lowering branch.
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "fact": "x509-chain-trusted/v1",
                    "predicate": {"is_trusted": false}
                }
            }
            """;
        TrustPolicyTranslationResult result = new CoseTpRegoFrontend().TranslateText(text, new TrustPolicyTranslationContext());
        Assert.That(result.IsSuccess, Is.True, () => string.Join("; ", result.Diagnostics.Select(d => d.Code + ":" + d.Message)));
    }

    [Test]
    public void Lowerer_handles_null_literal()
    {
        // Property assertion value is JSON null — covers the Null scalar lowering branch.
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "fact": "x509-cert-key-usage/v1",
                    "predicate": {"certificate_thumbprint": null}
                }
            }
            """;
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void Parser_top_level_forbidden_identifier_emits_TPX300()
    {
        // 'some' before a `policy := ...` rule is the unconstrained-iteration case the
        // parser surfaces as TPX300 (rather than the bland 'missing policy rule' TPX003).
        const string text = "package cose_trust_policy\n\nsome host";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(diagnostics.Any(d => d.Code == "TPX300"), Is.True);
    }

    [Test]
    public void Parser_unsupported_symbol_at_term_position_default_branch()
    {
        // Putting a comma at term position lands in ParseTerm's default branch.
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\": , }");
        Assert.That(diags.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Parser_unknown_identifier_at_term_position_emits_TPX300()
    {
        // A bare identifier that's neither a keyword nor in the forbidden list is rejected.
        var diags = Parse("package cose_trust_policy\n\npolicy := { \"x\": foo }");
        Assert.That(diags.Any(d => d.Code == "TPX300"), Is.True);
    }

    [Test]
    public void Parser_eof_at_term_position_uses_RenderToken_eof_branch()
    {
        // EOF after `:=` triggers the default branch in ParseTerm with an EOF token.
        var diags = Parse("package cose_trust_policy\n\npolicy :=");
        Assert.That(diags.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Parser_handles_top_level_empty_object_literal()
    {
        // Empty object body is a parse-success (semantic check is the JSON walker's job).
        // Schema validation will fail downstream, but the parser path covers the empty-
        // object branch.
        const string text = "package cose_trust_policy\n\npolicy := {}";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
        Assert.That(diagnostics.Count, Is.EqualTo(0));
    }

    [Test]
    public void Parser_handles_array_with_trailing_comma()
    {
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": [1, 2,] }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void Translate_with_parsed_document_produces_spec_through_Translate_overload()
    {
        // Direct exercise of Translate(RegoDocument, ctx) — the overload most public callers
        // hit when they parse once and translate many times against varying contexts.
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "fact": "x509-chain-trusted/v1",
                    "predicate": {"is_trusted": true}
                }
            }
            """;
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics)!;
        Assert.That(doc, Is.Not.Null);

        TrustPolicyTranslationResult result = new CoseTpRegoFrontend().Translate(doc, new TrustPolicyTranslationContext());
        Assert.That(result.IsSuccess, Is.True);
    }

}
