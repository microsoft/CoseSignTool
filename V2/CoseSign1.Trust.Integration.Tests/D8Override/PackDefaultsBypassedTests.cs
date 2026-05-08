// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Tests.D8Override;

using CoseSign1.Trust.Integration.Infrastructure;

/// <summary>
/// D8 override semantics. The shipped contract: when <c>--trust-policy &lt;doc&gt;</c> is
/// supplied, pack-default trust requirements are bypassed entirely; the document is the sole
/// source of trust requirements (pack fact PRODUCERS stay registered so the document's
/// RequireFact references resolve at evaluation time). These tests pin the override
/// behaviour by invoking the SAME signature twice — once without the override, once with it
/// — and asserting the verdict flips in both directions.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class PackDefaultsBypassedTests
{
    private const string RevocationModeNone = "none";

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void OverrideWithStricterDoc_FlipsPassToDeny(PolicyFormat format)
    {
        // Build a trusted chain. Without --trust-policy, verify x509 succeeds because the
        // X509VerificationProvider's default trust plan (require chain trusted) is satisfied.
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(OverrideWithStricterDoc_FlipsPassToDeny));

        CliResult baseline = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone);

        CliAssertions.AssertVerifySucceeded(baseline, $"d8 stricter / baseline (no override) / {format}");

        // Now layer a STRICTER policy: demand identity is_allowed=false, which the produced
        // fact never satisfies. If pack defaults were AND-merged with the doc the test would
        // still pass (chain trusted is fine + doc inverted = ambiguous). The matrix locks D8:
        // the doc fully replaces the pack policy → the inverted predicate denies.
        (string json, string rego) = PolicyDocumentBuilder.X509IdentityIsAllowedFalse();
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "d8-stricter");

        CliResult overridden = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            overridden,
            scenario: $"d8 stricter / with override / {format}",
            expectedStderrSubstring: "TRUST_PLAN_NOT_SATISFIED");
    }

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void OverrideWithLooserDoc_FlipsDenyToPass(PolicyFormat format)
    {
        // Build a real chain but DO NOT register its root. Without --trust-policy, the X509
        // pack default policy demands chain-trusted=true and denies because the chain's root
        // is not in the trust set.
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(OverrideWithLooserDoc_FlipsDenyToPass));

        CliResult baseline = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-system-roots", "false",
            "--revocation-mode", RevocationModeNone);

        CliAssertions.AssertVerifyDenied(
            baseline,
            scenario: $"d8 looser / baseline (no override) / {format}",
            expectedStderrSubstring: "TRUST_PLAN_NOT_SATISFIED");

        // Layer a LOOSER policy: message scope allow_all. If pack defaults survived, the
        // chain-trusted rule would still deny. The matrix locks D8: doc REPLACES pack policy
        // → allow_all wins → exit 0.
        (string json, string rego) = PolicyDocumentBuilder.MessageAllowAll();
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "d8-looser");

        CliResult overridden = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-system-roots", "false",
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifySucceeded(overridden, $"d8 looser / with override / {format}");
    }
}
