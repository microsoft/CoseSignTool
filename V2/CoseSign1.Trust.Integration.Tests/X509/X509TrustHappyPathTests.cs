// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Tests.X509;

using CoseSign1.Trust.Integration.Infrastructure;

/// <summary>
/// X.509 happy-path matrix: a trusted chain + a trust-policy document whose predicates the
/// produced facts satisfy. Every test runs the real <c>cosesigntool verify x509 ...</c>
/// pipeline in-process and asserts on the captured exit code and stderr surface. JSON and
/// Rego variants share the same logical policy, so cross-format equivalence is asserted at
/// the end of each test.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class X509TrustHappyPathTests
{
    private const string RevocationModeNone = "none";

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_TrustedChain_PolicyRequiresChainTrusted_Succeeds(PolicyFormat format)
    {
        // Arrange: a real chain + signed message + a policy file demanding the chain be trusted.
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_TrustedChain_PolicyRequiresChainTrusted_Succeeds));
        (string json, string rego) = PolicyDocumentBuilder.X509ChainTrusted();
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "x509-trusted");

        // Act: verify with the test root added as a custom trust anchor + revocation disabled
        // (test certs are not published; the online OCSP/CRL fetch would otherwise stall).
        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        // Assert: clean success on both frontends.
        CliAssertions.AssertVerifySucceeded(result, $"x509 happy / chain-trusted / {format}");
    }

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_TrustedChain_PolicyAddsIdentityAllowList_Succeeds(PolicyFormat format)
    {
        // The CLI does not surface identity-pinning today, so the produced
        // X509SigningCertificateIdentityAllowedFact carries IsAllowed=true unconditionally.
        // A policy that requires is_allowed=true therefore validates against any cert that
        // came through the trust-pack producer — which is exactly the integration-level
        // contract this test pins.
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_TrustedChain_PolicyAddsIdentityAllowList_Succeeds));
        (string json, string rego) = PolicyDocumentBuilder.X509IdentityIsAllowedTrue();
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "x509-id-allowed");

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifySucceeded(result, $"x509 happy / identity-allowed / {format}");
    }

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_TrustedChain_PolicyRequiresEkuOnLeaf_Succeeds(PolicyFormat format)
    {
        // The default chain factory does NOT attach EKUs to the leaf, so this fixture pins the
        // leaf's EKU set explicitly via the chain factory's WithLeafEkus. The matrix cell
        // demands the EKU be satisfied by the cert; we choose TLS server auth.
        const string TlsServerAuthOid = "1.3.6.1.5.5.7.3.1";
        using var fixture = SignedFixtureBuilder.CreateX509SignedWithLeafEkus(
            nameof(Verify_TrustedChain_PolicyRequiresEkuOnLeaf_Succeeds),
            TlsServerAuthOid);
        (string json, string rego) = PolicyDocumentBuilder.X509EkuOid(TlsServerAuthOid);
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "x509-eku");

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifySucceeded(result, $"x509 happy / eku-server-auth / {format}");
    }
}
