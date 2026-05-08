// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Tests.AntiPatterns;

using CoseSign1.Trust.Integration.Infrastructure;

/// <summary>
/// Anti-pattern: a document references <c>$param</c> with no in-document default and the
/// caller forgot to supply <c>--trust-policy-param</c>. The translator's Bind pass must
/// surface TPX400 before the verify pipeline runs.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class UnboundParameterTests
{
    private const string RevocationModeNone = "none";
    private const string ExpectedCode = "TPX400";
    private const string ParamName = "should_have_been_bound";

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_DocumentWithUnboundParam_AbortsWithUnboundParamDiagnostic(PolicyFormat format)
    {
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_DocumentWithUnboundParam_AbortsWithUnboundParamDiagnostic));
        (string json, string rego) = PolicyDocumentBuilder.MstReceiptIssuerHostUnboundParam(ParamName);
        string body = format == PolicyFormat.Json ? json : rego;
        string policyPath = PolicyDocumentBuilder.Write(format, body, "anti-unbound-param");

        // Deliberately omit --trust-policy-param so the binder can't resolve the placeholder.
        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: $"anti / unbound-param / {format}",
            expectedDiagnosticCode: ExpectedCode);
    }
}
