// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Tests;

using CoseSign1.Trust.Integration.Infrastructure;

/// <summary>
/// Cross-format equivalence regression. For every logical scenario in the matrix that has
/// both a JSON and a Rego variant, the CLI MUST produce the same exit code and the same
/// observable diagnostic surface (TPX-band codes only, line numbers stripped) regardless of
/// which frontend authored the document. This is the integration-test analog of the Phase 4
/// canonical-IR equivalence assertion: it locks the contract that switching formats does not
/// change verifier behaviour.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class CrossFormatEquivalenceTests
{
    private const string RevocationModeNone = "none";

    private static CliResult RunVerifyX509(SignedFixture fixture, string policyPath, params string[] extraArgs)
    {
        var args = new System.Collections.Generic.List<string>
        {
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath,
        };
        args.AddRange(extraArgs);
        return CliRunner.Run([.. args]);
    }

    private static CliResult RunVerifyScitt(string sigPath, string jwksPath, string policyPath, params string[] extraArgs)
    {
        var args = new System.Collections.Generic.List<string>
        {
            "verify", "scitt", sigPath,
            "--issuer-offline-keys", $"{SignedFixtureBuilder.MstIssuerHost}={jwksPath}",
            "--trust-policy", policyPath,
        };
        args.AddRange(extraArgs);
        return CliRunner.Run([.. args]);
    }

    [Test]
    public void X509ChainTrusted_HappyPath_IsCrossFormatEquivalent()
    {
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(X509ChainTrusted_HappyPath_IsCrossFormatEquivalent));
        (string json, string rego) = PolicyDocumentBuilder.X509ChainTrusted();
        string jsonPath = PolicyDocumentBuilder.Write(PolicyFormat.Json, json, "cross-x509-happy");
        string regoPath = PolicyDocumentBuilder.Write(PolicyFormat.Rego, rego, "cross-x509-happy");

        CliResult jsonRun = RunVerifyX509(fixture, jsonPath);
        CliResult regoRun = RunVerifyX509(fixture, regoPath);

        CliAssertions.AssertCrossFormatEquivalent(jsonRun, regoRun, "cross / x509 chain-trusted happy");
    }

    [Test]
    public void X509ChainUntrusted_DenyPath_IsCrossFormatEquivalent()
    {
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(X509ChainUntrusted_DenyPath_IsCrossFormatEquivalent));
        (string json, string rego) = PolicyDocumentBuilder.X509ChainTrusted();
        string jsonPath = PolicyDocumentBuilder.Write(PolicyFormat.Json, json, "cross-x509-untrusted");
        string regoPath = PolicyDocumentBuilder.Write(PolicyFormat.Rego, rego, "cross-x509-untrusted");

        // Same fixture, no --trust-roots, --trust-system-roots false → chain not trusted.
        var args = new[] { "--trust-system-roots", "false" };
        CliResult jsonRun = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-system-roots", "false",
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", jsonPath);
        CliResult regoRun = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-system-roots", "false",
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", regoPath);

        CliAssertions.AssertCrossFormatEquivalent(jsonRun, regoRun, "cross / x509 chain untrusted deny");
    }

    [Test]
    public void MstReceiptPresentAndTrusted_HappyPath_IsCrossFormatEquivalent()
    {
        string sigPath = SignedFixtureBuilder.GetMstReceiptFixturePath();
        string jwksPath = SignedFixtureBuilder.GetMstIssuerJwksPath();
        (string json, string rego) = PolicyDocumentBuilder.MstReceiptPresentAndTrusted();
        string jsonPath = PolicyDocumentBuilder.Write(PolicyFormat.Json, json, "cross-mst-happy");
        string regoPath = PolicyDocumentBuilder.Write(PolicyFormat.Rego, rego, "cross-mst-happy");

        CliResult jsonRun = RunVerifyScitt(sigPath, jwksPath, jsonPath);
        CliResult regoRun = RunVerifyScitt(sigPath, jwksPath, regoPath);

        CliAssertions.AssertCrossFormatEquivalent(jsonRun, regoRun, "cross / mst present+trusted happy");
    }

    [Test]
    public void UnknownFactId_TranslationDeny_IsCrossFormatEquivalent()
    {
        // Translation-time failure: both frontends must surface the same TPX200 code.
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(UnknownFactId_TranslationDeny_IsCrossFormatEquivalent));
        const string body = """
        {
            "primary_signing_key": {
                "fact": "totally-not-a-real-fact-id/v1",
                "predicate": {"operator": "Equals", "path": "$.something", "value": true}
            }
        }
        """;
        string jsonPath = PolicyDocumentBuilder.Write(PolicyFormat.Json, body, "cross-unknown-fact");
        string regoPath = PolicyDocumentBuilder.Write(PolicyFormat.Rego, PolicyDocumentBuilder.WrapAsRego(body), "cross-unknown-fact");

        CliResult jsonRun = RunVerifyX509(fixture, jsonPath);
        CliResult regoRun = RunVerifyX509(fixture, regoPath);

        CliAssertions.AssertCrossFormatEquivalent(jsonRun, regoRun, "cross / unknown-fact-id translation");
    }

    [Test]
    public void UnboundParameter_TranslationDeny_IsCrossFormatEquivalent()
    {
        // Both frontends share the binder pass: TPX400 must surface identically across formats.
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(UnboundParameter_TranslationDeny_IsCrossFormatEquivalent));
        (string json, string rego) = PolicyDocumentBuilder.MstReceiptIssuerHostUnboundParam("missing_binding");
        string jsonPath = PolicyDocumentBuilder.Write(PolicyFormat.Json, json, "cross-unbound");
        string regoPath = PolicyDocumentBuilder.Write(PolicyFormat.Rego, rego, "cross-unbound");

        CliResult jsonRun = RunVerifyX509(fixture, jsonPath);
        CliResult regoRun = RunVerifyX509(fixture, regoPath);

        CliAssertions.AssertCrossFormatEquivalent(jsonRun, regoRun, "cross / unbound-param translation");
    }
}
