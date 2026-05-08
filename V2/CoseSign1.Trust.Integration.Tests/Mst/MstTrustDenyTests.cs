// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Tests.Mst;

using CoseSign1.Trust.Integration.Infrastructure;

/// <summary>
/// MST deny matrix: missing receipt against an MST-required policy, and a wrong-issuer
/// allow-list. Each cell drives a different fact-evaluation failure path.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class MstTrustDenyTests
{
    private const string RevocationModeNone = "none";
    private const string TrustFailureFactRequirement = "TRUST_PLAN_NOT_SATISFIED";

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_NoReceipt_PolicyRequiresMstReceiptOnEmptyDeny_Denies(PolicyFormat format)
    {
        // Build a plain X509-signed message — no MST receipt present. Use verify x509 (the
        // root we trust) and layer a trust-policy demanding mst-receipt-present/v1. The
        // any_counter_signature scope's on_empty:deny rule fires because there are no
        // counter-signatures to evaluate, surfacing a non-zero exit + trust-failure diagnostic.
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_NoReceipt_PolicyRequiresMstReceiptOnEmptyDeny_Denies));
        (string json, string rego) = PolicyDocumentBuilder.MstReceiptPresent();
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "mst-deny-missing");

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: $"mst deny / no-receipt / {format}",
            expectedStderrSubstring: TrustFailureFactRequirement);
    }

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_RealReceipt_PolicyRequiresWrongIssuerHost_Denies(PolicyFormat format)
    {
        // The bundled receipt was issued by esrp-cts-cp.confidential-ledger.azure.com. The
        // policy demands a Contains predicate against an unrelated host; no fact in the
        // produced set carries that value, so trust evaluation denies.
        const string UnrelatedHost = "issuer-not-in-this-receipt.example.com";

        string sigPath = SignedFixtureBuilder.GetMstReceiptFixturePath();
        string jwksPath = SignedFixtureBuilder.GetMstIssuerJwksPath();
        (string json, string rego) = PolicyDocumentBuilder.MstReceiptIssuerHost(UnrelatedHost);
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "mst-deny-wrong-issuer");

        CliResult result = CliRunner.Run(
            "verify", "scitt", sigPath,
            "--issuer-offline-keys", $"{SignedFixtureBuilder.MstIssuerHost}={jwksPath}",
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: $"mst deny / wrong-issuer-host / {format}",
            expectedStderrSubstring: TrustFailureFactRequirement);
    }
}
