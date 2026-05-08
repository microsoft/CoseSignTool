// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Tests.AntiPatterns;

using CoseSign1.Trust.Integration.Infrastructure;

/// <summary>
/// Anti-pattern matrix for forbidden Rego constructs. The Rego frontend accepts a constrained
/// subset; every forbidden construct surfaces a TPX300-band sub-code. These tests pin one
/// case per sub-code so future relaxations of the dialect can't slip through unnoticed.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class ForbiddenRegoConstructTests
{
    private const string RevocationModeNone = "none";

    [Test]
    public void Verify_RegoWithHttpSendBuiltin_AbortsWithForbiddenBuiltinDiagnostic()
    {
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_RegoWithHttpSendBuiltin_AbortsWithForbiddenBuiltinDiagnostic));
        const string body = """
        package cose_trust_policy

        # http.send is on the closed reject-list — translation MUST surface TPX301.
        policy := {
            "primary_signing_key": {
                "fact": "x509-chain-trusted/v1",
                "predicate": {
                    "operator": "Equals",
                    "path": "$.is_trusted",
                    "value": http.send({"url": "https://example.com/allow", "method": "GET"})
                }
            }
        }
        """;
        string policyPath = PolicyDocumentBuilder.Write(PolicyFormat.Rego, body, "anti-rego-http");

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: "anti / rego http.send / rego",
            expectedDiagnosticCode: "TPX301");
    }

    [Test]
    public void Verify_RegoWithRegexMatchBuiltin_AbortsWithForbiddenBuiltinDiagnostic()
    {
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_RegoWithRegexMatchBuiltin_AbortsWithForbiddenBuiltinDiagnostic));
        const string body = """
        package cose_trust_policy

        # regex.* is on the reject-list. Surfaces TPX301.
        policy := {
            "primary_signing_key": {
                "fact": "x509-cert-identity/v1",
                "predicate": {
                    "operator": "Equals",
                    "path": "$.subject",
                    "value": regex.match("secret search phrase", "$.subject")
                }
            }
        }
        """;
        string policyPath = PolicyDocumentBuilder.Write(PolicyFormat.Rego, body, "anti-rego-regex");

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: "anti / rego regex.match / rego",
            expectedDiagnosticCode: "TPX301");
    }

    [Test]
    public void Verify_RegoWithSomeIteration_AbortsWithUnconstrainedIterationDiagnostic()
    {
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_RegoWithSomeIteration_AbortsWithUnconstrainedIterationDiagnostic));
        const string body = """
        package cose_trust_policy

        import future.keywords.in

        # 'some x in coll' is unconstrained iteration. Surfaces TPX302.
        some host in input.trusted_log_hosts

        policy := {
            "any_counter_signature": {
                "on_empty": "deny",
                "fact": "mst-receipt-issuer-host/v1",
                "predicate": {"operator": "Equals", "path": "$.host", "value": host}
            }
        }
        """;
        string policyPath = PolicyDocumentBuilder.Write(PolicyFormat.Rego, body, "anti-rego-some");

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: "anti / rego some-iter / rego",
            expectedDiagnosticCode: "TPX302");
    }

    [Test]
    public void Verify_RegoWithMultipleRulesPerPackage_AbortsWithMultipleRulesDiagnostic()
    {
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_RegoWithMultipleRulesPerPackage_AbortsWithMultipleRulesDiagnostic));
        const string body = """
        package cose_trust_policy

        # The constrained dialect requires exactly one rule per package. Surfaces TPX005.
        policy := {
            "primary_signing_key": {"fact": "x509-chain-trusted/v1", "predicate": {"is_trusted": true}}
        }

        other := {
            "primary_signing_key": {"fact": "x509-chain-trusted/v1", "predicate": {"is_trusted": false}}
        }
        """;
        string policyPath = PolicyDocumentBuilder.Write(PolicyFormat.Rego, body, "anti-rego-multirule");

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: "anti / rego multiple-rules / rego",
            expectedDiagnosticCode: "TPX005");
    }
}
