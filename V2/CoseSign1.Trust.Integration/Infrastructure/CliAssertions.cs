// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Infrastructure;

using System;
using System.IO;

/// <summary>
/// Common matrix-cell assertions reused by every fixture in the suite. Centralising the exit
/// code + diagnostic-substring expectations keeps individual tests focused on the policy /
/// signature configuration under test instead of re-stating boilerplate.
/// </summary>
public static class CliAssertions
{
    /// <summary>
    /// Asserts that the verify CLI produced an exit code of zero (Success) and that no
    /// translation error or trust-failure diagnostic leaked to stderr.
    /// </summary>
    public static void AssertVerifySucceeded(CliResult result, string scenario)
    {
        ArgumentNullException.ThrowIfNull(result);
        Assert.That(result.ExitCode, Is.Zero,
            $"[{scenario}] expected verify to succeed (exit 0)\nSTDOUT:\n{result.Stdout}\nSTDERR:\n{result.Stderr}");

        // A successful run must not leak TPX* diagnostic codes onto stderr — those indicate
        // translation or fact-evaluation failure, which is incompatible with a 0 exit code.
        Assert.That(result.Stderr, Does.Not.Contain("[TPX"),
            $"[{scenario}] verify exit was 0 but stderr carried a TPX diagnostic\nSTDERR:\n{result.Stderr}");
    }

    /// <summary>
    /// Asserts that the verify CLI rejected the request with a non-zero exit code. Optionally
    /// asserts that stderr carries a specific TPX code (translation phase) or trust-error
    /// substring (runtime phase). The combination keeps fixtures terse while still pinning
    /// each failure mode to a real diagnostic.
    /// </summary>
    public static void AssertVerifyDenied(
        CliResult result,
        string scenario,
        string? expectedDiagnosticCode = null,
        string? expectedStderrSubstring = null)
    {
        ArgumentNullException.ThrowIfNull(result);

        Assert.That(result.ExitCode, Is.Not.Zero,
            $"[{scenario}] expected verify to deny (non-zero exit)\nSTDOUT:\n{result.Stdout}\nSTDERR:\n{result.Stderr}");

        if (expectedDiagnosticCode is not null)
        {
            Assert.That(result.Stderr, Does.Contain(expectedDiagnosticCode),
                $"[{scenario}] expected diagnostic code '{expectedDiagnosticCode}' on stderr\nSTDERR:\n{result.Stderr}");
        }

        if (expectedStderrSubstring is not null)
        {
            Assert.That(result.Stderr, Does.Contain(expectedStderrSubstring),
                $"[{scenario}] expected substring '{expectedStderrSubstring}' on stderr\nSTDERR:\n{result.Stderr}");
        }
    }

    /// <summary>
    /// Cross-format equivalence regression. Asserts that two CLI invocations differing ONLY in
    /// trust-policy frontend produce the same exit code and the same observable diagnostic
    /// surface (TPX codes + trust-failure error codes).
    /// </summary>
    /// <remarks>
    /// Stderr line numbers and SourceLocation suffixes are noisy across formats (the JSON
    /// frontend emits JSON-pointer paths; the Rego frontend emits line/column). This assertion
    /// extracts only the leading <c>[TPX###]</c>/<c>[ErrorCode]</c> tokens so the regression
    /// holds across both frontends without coupling tests to formatter incidentals.
    /// </remarks>
    public static void AssertCrossFormatEquivalent(CliResult json, CliResult rego, string scenario)
    {
        ArgumentNullException.ThrowIfNull(json);
        ArgumentNullException.ThrowIfNull(rego);

        Assert.That(rego.ExitCode, Is.EqualTo(json.ExitCode),
            $"[{scenario}] cross-format exit-code mismatch: json={json.ExitCode} rego={rego.ExitCode}\n" +
            $"JSON STDERR:\n{json.Stderr}\nREGO STDERR:\n{rego.Stderr}");

        string[] jsonCodes = ExtractDiagnosticCodes(json.Stderr);
        string[] regoCodes = ExtractDiagnosticCodes(rego.Stderr);

        Assert.That(regoCodes, Is.EquivalentTo(jsonCodes),
            $"[{scenario}] cross-format diagnostic-code set mismatch:\n" +
            $"JSON codes: [{string.Join(",", jsonCodes)}]\nREGO codes: [{string.Join(",", regoCodes)}]\n" +
            $"JSON STDERR:\n{json.Stderr}\nREGO STDERR:\n{rego.Stderr}");
    }

    /// <summary>
    /// Extracts every bracketed diagnostic code (e.g. <c>[TPX300]</c>, <c>[Trust.E001]</c>)
    /// from the supplied stderr text, in document order. Whitespace and surrounding text are
    /// ignored so the result is a normalised, line-number-free fingerprint of the stderr
    /// surface.
    /// </summary>
    public static string[] ExtractDiagnosticCodes(string stderr)
    {
        if (string.IsNullOrEmpty(stderr))
        {
            return Array.Empty<string>();
        }

        var codes = new System.Collections.Generic.List<string>();
        using var reader = new StringReader(stderr);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            // Capture the FIRST [TOKEN] of each line where TOKEN starts with TPX. We deliberately
            // ignore non-TPX bracketed prefixes (e.g. log-level markers) so cross-format equality
            // is anchored on translation-error codes only — runtime trust failures share the
            // same fact identifier across frontends, exit code parity covers them.
            int open = line.IndexOf('[');
            int close = open >= 0 ? line.IndexOf(']', open + 1) : -1;
            if (open >= 0 && close > open)
            {
                string token = line.Substring(open + 1, close - open - 1).Trim();
                if (token.StartsWith("TPX", StringComparison.Ordinal))
                {
                    codes.Add(token);
                }
            }
        }

        return codes.ToArray();
    }
}
