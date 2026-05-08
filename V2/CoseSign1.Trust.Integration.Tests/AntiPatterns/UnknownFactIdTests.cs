// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Tests.AntiPatterns;

using CoseSign1.Trust.Integration.Infrastructure;

/// <summary>
/// Anti-pattern: documents that reference a fact id absent from the registry surface TPX200
/// before the verify pipeline runs. Both frontends share the same capability-aware
/// translation pass so the diagnostic is identical across formats.
/// </summary>
[TestFixture]
[NonParallelizable]
public sealed class UnknownFactIdTests
{
    private const string RevocationModeNone = "none";
    private const string ExpectedCode = "TPX200";

    [TestCase(PolicyFormat.Json)]
    [TestCase(PolicyFormat.Rego)]
    public void Verify_UnknownFactId_AbortsWithRegistryDiagnostic(PolicyFormat format)
    {
        using var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(Verify_UnknownFactId_AbortsWithRegistryDiagnostic));
        const string body = """
        {
            "primary_signing_key": {
                "fact": "totally-not-a-real-fact-id/v1",
                "predicate": {"operator": "Equals", "path": "$.something", "value": true}
            }
        }
        """;
        string emitted = format == PolicyFormat.Json
            ? body
            : PolicyDocumentBuilder.WrapAsRego(body);
        string policyPath = PolicyDocumentBuilder.Write(format, emitted, "anti-unknown-fact");

        CliResult result = CliRunner.Run(
            "verify", "x509", fixture.SignaturePath,
            "--trust-roots", fixture.RootPemPath!,
            "--revocation-mode", RevocationModeNone,
            "--trust-policy", policyPath);

        CliAssertions.AssertVerifyDenied(
            result,
            scenario: $"anti / unknown-fact-id / {format}",
            expectedDiagnosticCode: ExpectedCode);
    }
}
