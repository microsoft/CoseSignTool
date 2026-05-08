// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Tests.X509;

using CoseSign1.Trust.Integration.Infrastructure;

/// <summary>
/// Parametrised X.509 allow-list. The trust-policy document references a <c>$param</c>
/// placeholder for the expected leaf subject. The CLI's <c>--trust-policy-param
/// name=jsonValue</c> flag binds that placeholder; the matching binding succeeds, the
/// non-matching binding denies, and the unbound case is exercised by the anti-pattern suite.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class X509ParameterTests
{
    private const string RevocationModeNone = "none";
    private const string ParamName = "expected_subject";

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_ParametrisedSubject_MatchingBinding_Succeeds(PolicyFormat format)
    {
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_ParametrisedSubject_MatchingBinding_Succeeds));
        // Leaf subject is "CN=Test Leaf: <testname>"; we bind to the full DN string.
        string fullSubject = "CN=Test Leaf: " + nameof(Verify_ParametrisedSubject_MatchingBinding_Succeeds);
        (string json, string rego) = PolicyDocumentBuilder.X509SubjectEqualsParam(ParamName, defaultCn: "PLACEHOLDER");
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "x509-param-match");

        // --trust-policy-param expects name=jsonValue, so the value side is JSON-quoted.
        string paramArg = $"{ParamName}=\"{fullSubject}\"";

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath,
            "--trust-policy-param", paramArg);

        CliAssertions.AssertVerifySucceeded(result, $"x509 param / matching / {format}");
    }

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_ParametrisedSubject_MismatchingBinding_Denies(PolicyFormat format)
    {
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_ParametrisedSubject_MismatchingBinding_Denies));
        (string json, string rego) = PolicyDocumentBuilder.X509SubjectEqualsParam(ParamName, defaultCn: "PLACEHOLDER");
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "x509-param-miss");

        // Bind to a value that cannot match any real cert subject.
        string paramArg = $"{ParamName}=\"CN=NotInChain\"";

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath,
            "--trust-policy-param", paramArg);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: $"x509 param / mismatching / {format}",
            expectedStderrSubstring: "TRUST_PLAN_NOT_SATISFIED");
    }
}
