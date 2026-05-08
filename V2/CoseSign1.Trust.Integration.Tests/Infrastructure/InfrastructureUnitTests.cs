// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Tests.Infrastructure;

using System;
using CoseSign1.Trust.Integration.Infrastructure;

/// <summary>
/// Targeted unit tests for the integration-test infrastructure helpers. The bulk of the
/// helpers' behaviour is exercised transitively by the matrix tests; this fixture pins the
/// edge cases (empty input, unknown enum values, repeated-dispose contracts) so future
/// refactors of the infrastructure don't silently regress without a directly-attributable
/// red test.
/// </summary>
[TestFixture]
public sealed class InfrastructureUnitTests
{
    [Test]
    public void ExtractDiagnosticCodes_NullOrEmpty_ReturnsEmptyArray()
    {
        Assert.That(CliAssertions.ExtractDiagnosticCodes(null!), Is.Empty);
        Assert.That(CliAssertions.ExtractDiagnosticCodes(string.Empty), Is.Empty);
    }

    [Test]
    public void ExtractDiagnosticCodes_StripsNonTpxBracketedTokens()
    {
        const string stderr = """
        [INFO] starting
        [TPX300] forbidden builtin
        [Trust.E007] unrelated
        [TPX001] malformed
        plain line without brackets
        """;

        string[] codes = CliAssertions.ExtractDiagnosticCodes(stderr);

        Assert.That(codes, Is.EquivalentTo(new[] { "TPX300", "TPX001" }));
    }

    [Test]
    public void Write_UnknownPolicyFormat_ThrowsArgumentOutOfRange()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            PolicyDocumentBuilder.Write((PolicyFormat)999, "{}", "bogus-format"));
    }

    [Test]
    public void Write_NullBody_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => PolicyDocumentBuilder.Write(PolicyFormat.Json, null!, "stem"));
    }

    [Test]
    public void Write_EmptyStem_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => PolicyDocumentBuilder.Write(PolicyFormat.Json, "{}", string.Empty));
    }

    [Test]
    public void WrapAsRego_NullJson_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => PolicyDocumentBuilder.WrapAsRego(null!));
    }

    [Test]
    public void SignedFixture_DoubleDispose_IsIdempotent()
    {
        // Reach the early-return path on the second Dispose call.
        var fixture = SignedFixtureBuilder.CreateX509Signed(nameof(SignedFixture_DoubleDispose_IsIdempotent));
        fixture.Dispose();
        Assert.DoesNotThrow(() => fixture.Dispose());
    }

    [Test]
    public void InMemoryCliConsole_DoubleDispose_IsIdempotent()
    {
        var console = new InMemoryCliConsole();
        console.Dispose();
        Assert.DoesNotThrow(() => console.Dispose());
    }

    [Test]
    public void InMemoryCliConsole_StdoutAndStderr_StartEmptyAndCaptureWrites()
    {
        using var console = new InMemoryCliConsole();
        Assert.That(console.GetStdout(), Is.Empty);
        Assert.That(console.GetStderr(), Is.Empty);

        console.StandardOutput.Write("hello-stdout");
        console.StandardError.Write("hello-stderr");

        Assert.That(console.GetStdout(), Is.EqualTo("hello-stdout"));
        Assert.That(console.GetStderr(), Is.EqualTo("hello-stderr"));
    }

    [Test]
    public void CliResult_RejectsNullStreams_GracefullyByCoercingToEmpty()
    {
        // The constructor coerces null stdout/stderr to empty strings so test assertions
        // never NPE when a caller forgets to capture one of the streams.
        var result = new CliResult(exitCode: 42, stdout: null!, stderr: null!);
        Assert.That(result.ExitCode, Is.EqualTo(42));
        Assert.That(result.Stdout, Is.Empty);
        Assert.That(result.Stderr, Is.Empty);
    }

    [Test]
    public void CliRunner_NullArgs_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CliRunner.Run(null!));
    }

    [Test]
    public void AssertVerifySucceeded_NullResult_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CliAssertions.AssertVerifySucceeded(null!, "any"));
    }

    [Test]
    public void AssertVerifyDenied_NullResult_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CliAssertions.AssertVerifyDenied(null!, "any"));
    }

    [Test]
    public void AssertCrossFormatEquivalent_NullEither_ThrowsArgumentNullException()
    {
        var ok = new CliResult(0, string.Empty, string.Empty);
        Assert.Throws<ArgumentNullException>(() => CliAssertions.AssertCrossFormatEquivalent(null!, ok, "any"));
        Assert.Throws<ArgumentNullException>(() => CliAssertions.AssertCrossFormatEquivalent(ok, null!, "any"));
    }
}
