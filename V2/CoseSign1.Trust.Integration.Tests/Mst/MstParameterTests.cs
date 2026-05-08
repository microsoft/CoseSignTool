// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Tests.Mst;

using CoseSign1.Trust.Integration.Infrastructure;

/// <summary>
/// MST parametrised matrix: <c>$param</c>-bound issuer host matching against the bundled
/// receipt. Matching binding succeeds, mismatched binding denies; both invocations exercise
/// the post-translate Bind pass + the Contains predicate against the
/// <c>mst-receipt-issuer-host/v1</c> fact.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class MstParameterTests
{
    private const string ParamName = "trusted_issuer_host";

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_RealReceipt_ParamMatchesActualIssuer_Succeeds(PolicyFormat format)
    {
        string sigPath = SignedFixtureBuilder.GetMstReceiptFixturePath();
        string jwksPath = SignedFixtureBuilder.GetMstIssuerJwksPath();

        (string json, string rego) = PolicyDocumentBuilder.MstReceiptIssuerHostParam(ParamName, defaultHost: "PLACEHOLDER");
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "mst-param-match");

        CliResult result = CliRunner.Run(
            "verify", "scitt", sigPath,
            "--issuer-offline-keys", $"{SignedFixtureBuilder.MstIssuerHost}={jwksPath}",
            "--trust-policy", policyPath,
            "--trust-policy-param", $"{ParamName}=\"{SignedFixtureBuilder.MstIssuerHost}\"");

        CliAssertions.AssertVerifySucceeded(result, $"mst param / matching / {format}");
    }

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_RealReceipt_ParamDoesNotMatchActualIssuer_Denies(PolicyFormat format)
    {
        string sigPath = SignedFixtureBuilder.GetMstReceiptFixturePath();
        string jwksPath = SignedFixtureBuilder.GetMstIssuerJwksPath();

        (string json, string rego) = PolicyDocumentBuilder.MstReceiptIssuerHostParam(ParamName, defaultHost: "PLACEHOLDER");
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "mst-param-miss");

        CliResult result = CliRunner.Run(
            "verify", "scitt", sigPath,
            "--issuer-offline-keys", $"{SignedFixtureBuilder.MstIssuerHost}={jwksPath}",
            "--trust-policy", policyPath,
            "--trust-policy-param", $"{ParamName}=\"some-other-host.example.org\"");

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: $"mst param / mismatching / {format}",
            expectedStderrSubstring: "TRUST_PLAN_NOT_SATISFIED");
    }
}
