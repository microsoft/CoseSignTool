// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Tests.AntiPatterns;

using CoseSign1.Trust.Integration.Infrastructure;

/// <summary>
/// Anti-pattern matrix for malformed and schema-violating documents. Each test confirms the
/// CLI fails fast (non-zero exit) BEFORE invoking the verify pipeline, with the appropriate
/// TPX-band diagnostic on stderr.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class MalformedDocumentTests
{
    private const string RevocationModeNone = "none";

    [TestCase(PolicyFormat.Json, "TPX001")]
    [TestCase(PolicyFormat.Rego, "TPX001")]
    public void Verify_MalformedDocument_AbortsWithParserDiagnostic(PolicyFormat format, string expectedCode)
    {
        // Build a document the parser cannot consume. For JSON this is unbalanced braces; for
        // Rego it is an unterminated string literal that trips the tokenizer. Either way the
        // translator surfaces TPX001 (malformed) before walking the document.
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_MalformedDocument_AbortsWithParserDiagnostic));

        string body = format switch
        {
            PolicyFormat.Json => "{ this is not json }",
            PolicyFormat.Rego => "package cose_trust_policy\n\npolicy := { \"unterminated string",
            _ => throw new System.ArgumentOutOfRangeException(nameof(format))
        };
        string policyPath = PolicyDocumentBuilder.Write(format, body, "anti-malformed");

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: $"anti / malformed-document / {format}",
            expectedDiagnosticCode: expectedCode);
    }

    [Test]
    public void Verify_JsonSchemaViolation_UnknownTopLevelField_AbortsWithSchemaDiagnostic()
    {
        // The schema declares additionalProperties:false at the document root. A bogus
        // top-level key triggers a TPX100 schema diagnostic before any IR walking happens.
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_JsonSchemaViolation_UnknownTopLevelField_AbortsWithSchemaDiagnostic));
        const string body = """
        {
            "primary_signing_key": {
                "fact": "x509-chain-trusted/v1",
                "predicate": {"is_trusted": true}
            },
            "totally_unknown_top_level": "boom"
        }
        """;
        string policyPath = PolicyDocumentBuilder.Write(PolicyFormat.Json, body, "anti-schema");

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: "anti / schema-violation / json",
            expectedDiagnosticCode: "TPX100");
    }

    [Test]
    public void Verify_JsonSchemaViolation_PredicateValueWrongType_AbortsWithSchemaDiagnostic()
    {
        // `is_trusted` must be a JSON value (boolean for this fact's underlying property). An
        // explicit object that doesn't match $param shape, on a property assertion, fails the
        // property_assertion_predicate schema → TPX100. This is the matrix's "wrong type" cell.
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_JsonSchemaViolation_PredicateValueWrongType_AbortsWithSchemaDiagnostic));
        const string body = """
        {
            "primary_signing_key": {
                "fact": "x509-chain-trusted/v1",
                "predicate": {"operator": 12345, "path": "$.is_trusted"}
            }
        }
        """;
        string policyPath = PolicyDocumentBuilder.Write(PolicyFormat.Json, body, "anti-schema-type");

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: "anti / schema-violation-wrong-type / json",
            expectedDiagnosticCode: "TPX100");
    }
}
