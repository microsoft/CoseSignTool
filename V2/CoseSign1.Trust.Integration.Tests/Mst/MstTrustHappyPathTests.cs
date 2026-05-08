// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Tests.Mst;

using System.IO;
using CoseSign1.Trust.Integration.Infrastructure;

/// <summary>
/// MST happy-path matrix: a real signed SCITT receipt + a trust-policy demanding the receipt
/// be present, cryptographically trusted, and bound to an authorised issuer host. The
/// fixtures (1ts-statement.scitt + the offline JWKS) are reused from
/// <c>CoseSign1.Transparent.MST.Tests</c> via project links so the bytes are canonical and
/// the test exercises the production verify-pipeline end to end.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class MstTrustHappyPathTests
{
    [SetUp]
    public void EnsureFixturesPresent()
    {
        // The fixture deployment is part of the project file. If a future train rearranges the
        // layout we want the failure to be loud + descriptive instead of a misleading
        // "verify fails" symptom. NUnit's Ignore is appropriate here only when the bundled
        // assets genuinely cannot be located; for this project they MUST be present.
        Assert.That(File.Exists(SignedFixtureBuilder.GetMstReceiptFixturePath()),
            "Bundled SCITT receipt fixture must be deployed alongside the test assembly.");
        Assert.That(File.Exists(SignedFixtureBuilder.GetMstIssuerJwksPath()),
            "Bundled MST issuer JWKS must be deployed alongside the test assembly.");
    }

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_RealReceipt_PolicyRequiresPresentAndTrusted_Succeeds(PolicyFormat format)
    {
        string sigPath = SignedFixtureBuilder.GetMstReceiptFixturePath();
        string jwksPath = SignedFixtureBuilder.GetMstIssuerJwksPath();

        (string json, string rego) = PolicyDocumentBuilder.MstReceiptPresentAndTrusted();
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "mst-present-trusted");

        CliResult result = CliRunner.Run(
            "verify", "scitt", sigPath,
            "--issuer-offline-keys", $"{SignedFixtureBuilder.MstIssuerHost}={jwksPath}",
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifySucceeded(result, $"mst happy / present+trusted / {format}");
    }

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_RealReceipt_PolicyFiltersIssuerHost_Match_Succeeds(PolicyFormat format)
    {
        string sigPath = SignedFixtureBuilder.GetMstReceiptFixturePath();
        string jwksPath = SignedFixtureBuilder.GetMstIssuerJwksPath();

        (string json, string rego) = PolicyDocumentBuilder.MstReceiptIssuerHost(SignedFixtureBuilder.MstIssuerHost);
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "mst-issuer-match");

        CliResult result = CliRunner.Run(
            "verify", "scitt", sigPath,
            "--issuer-offline-keys", $"{SignedFixtureBuilder.MstIssuerHost}={jwksPath}",
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifySucceeded(result, $"mst happy / issuer-host-match / {format}");
    }
}
