// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Tests.X509;

using CoseSign1.Trust.Integration.Infrastructure;

/// <summary>
/// X.509 deny matrix: trusted-vs-untrusted chain pairings, identity allow-list deny, and EKU
/// requirement that the cert cannot satisfy. Each cell verifies the CLI reports a non-zero
/// exit and that the trust-failure surface points at the right fact.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class X509TrustDenyTests
{
    private const string RevocationModeNone = "none";
    private const string TrustFailureFactRequirement = "TRUST_PLAN_NOT_SATISFIED";

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_UntrustedChain_PolicyRequiresChainTrusted_Denies(PolicyFormat format)
    {
        // Arrange: build a real chain but DO NOT register its root with the verifier.
        // The chain validates cryptographically but x509-chain-trusted/v1 produces is_trusted=false
        // because the leaf doesn't chain up to a known anchor.
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_UntrustedChain_PolicyRequiresChainTrusted_Denies));
        (string json, string rego) = PolicyDocumentBuilder.X509ChainTrusted();
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "x509-deny-untrusted");

        // Act: omit --trust-roots; force --trust-system-roots false so the test root is
        // genuinely not trusted. Revocation off because the chain has no revocation
        // distribution points.
        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-system-roots", "false",
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: $"x509 deny / untrusted-chain / {format}",
            expectedStderrSubstring: TrustFailureFactRequirement);
    }

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_TrustedChain_PolicyAddsIdentityDenyList_Denies(PolicyFormat format)
    {
        // The X509 trust pack has identity pinning disabled by default, so the produced
        // X509SigningCertificateIdentityAllowedFact carries IsAllowed=true. A policy that
        // requires is_allowed=false therefore fails — the predicate inversion stands in for a
        // configured deny-list match.
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_TrustedChain_PolicyAddsIdentityDenyList_Denies));
        (string json, string rego) = PolicyDocumentBuilder.X509IdentityIsAllowedFalse();
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "x509-deny-identity");

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: $"x509 deny / identity-not-allowed / {format}",
            expectedStderrSubstring: TrustFailureFactRequirement);
    }

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_TrustedChain_PolicyRequiresEkuLeafLacks_Denies(PolicyFormat format)
    {
        // Leaf is built with TLS auth EKUs only. Demand code-signing (1.3.6.1.5.5.7.3.3) which
        // is absent — the resulting EKU fact set has no fact whose oid_value matches.
        const string LeafTlsAuthOid = "1.3.6.1.5.5.7.3.1";
        const string MissingCodeSigningOid = "1.3.6.1.5.5.7.3.3";

        using var fixture = SignedFixtureBuilder.CreateX509SignedWithLeafEkus(
            nameof(Verify_TrustedChain_PolicyRequiresEkuLeafLacks_Denies),
            LeafTlsAuthOid);
        (string json, string rego) = PolicyDocumentBuilder.X509EkuOid(MissingCodeSigningOid);
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "x509-deny-eku");

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: $"x509 deny / eku-mismatch / {format}",
            expectedStderrSubstring: TrustFailureFactRequirement);
    }
}
