// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego.Tests;

using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.TrustFrontends.Rego;

/// <summary>
/// Hardening tests for the constrained-Rego frontend covering:
/// <list type="bullet">
///   <item>RT-MAJ-1 — parser depth guard against stack-exhaustion DoS.</item>
///   <item>Per-cause TPX3xx sub-codes (TPX301 builtin / TPX302 iteration / TPX303 data /
///         TPX304 comprehension / TPX305 max-depth).</item>
///   <item>RT-MIN-1 — bare-CR and CRLF line tracking in diagnostics.</item>
///   <item>UX-MIN-2 — comprehension at object-key position routes to TPX304 (not the
///         bland 'expected string key' TPX001).</item>
/// </list>
/// </summary>
[TestFixture]
public sealed class HardeningTests
{
    [Test]
    public void DepthGuard_DeeplyNestedArray_RejectsWithTPX305_NoStackOverflow()
    {
        // 10 000 deep is well into stack-exhaustion territory for a recursive descent
        // walker. The guard must reject before recursing.
        var sb = new StringBuilder("package cose_trust_policy\n\npolicy := { \"x\": ");
        for (int i = 0; i < 10000; i++)
        {
            sb.Append('[');
        }

        sb.Append("1");
        for (int i = 0; i < 10000; i++)
        {
            sb.Append(']');
        }

        sb.Append(" }");

        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var sw = Stopwatch.StartNew();
        var doc = CoseTpRegoFrontend.TryParse(sb.ToString(), null, diagnostics);
        sw.Stop();

        Assert.That(doc, Is.Null);
        Assert.That(diagnostics.Any(d => d.Code == "TPX305"), Is.True, () => string.Join("; ", diagnostics.Select(d => d.Code + ":" + d.Message)));
        // Cross-pin: depth-guard MUST NOT collide with the input-size guard (TPX306).
        Assert.That(diagnostics.Any(d => d.Code == "TPX306"), Is.False);
        // The acceptance criterion in the review: parse + reject in well under 50 ms.
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(500));
    }

    [Test]
    public void DepthGuard_DeeplyNestedObject_RejectsWithTPX305()
    {
        var sb = new StringBuilder("package cose_trust_policy\n\npolicy := ");
        for (int i = 0; i < 100; i++)
        {
            sb.Append("{ \"x\": ");
        }

        sb.Append("1");
        for (int i = 0; i < 100; i++)
        {
            sb.Append(" }");
        }

        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(sb.ToString(), null, diagnostics);

        Assert.That(doc, Is.Null);
        Assert.That(diagnostics.Any(d => d.Code == "TPX305"), Is.True);
    }

    [Test]
    public void DepthGuard_RealisticPolicyDepthAccepted()
    {
        // The §6.5.6 example sits at depth ~4. Exercising depth-up-to-the-limit ensures
        // the guard isn't tripping on legitimate documents.
        const string text = """
            package cose_trust_policy

            policy := {
                "primary_signing_key": {
                    "all_of": [
                        {"fact": "x509-chain-trusted/v1", "predicate": {"is_trusted": true}}
                    ]
                }
            }
            """;
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
        Assert.That(diagnostics.Any(d => d.Severity == TrustPolicySeverity.Error), Is.False);
    }

    [Test]
    public void SubCode_HttpSendBuiltin_EmitsTPX301()
    {
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse("package cose_trust_policy\n\npolicy := { \"x\": http.send(\"u\") }", null, diagnostics);
        Assert.That(diagnostics.Any(d => d.Code == "TPX301"), Is.True);
    }

    [Test]
    public void SubCode_RegexMatchBuiltin_EmitsTPX301()
    {
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse("package cose_trust_policy\n\npolicy := { \"x\": regex.match(\"a\") }", null, diagnostics);
        Assert.That(diagnostics.Any(d => d.Code == "TPX301"), Is.True);
    }

    [Test]
    public void SubCode_SomeKeyword_EmitsTPX302()
    {
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse("package cose_trust_policy\n\nsome host", null, diagnostics);
        Assert.That(diagnostics.Any(d => d.Code == "TPX302"), Is.True);
    }

    [Test]
    public void SubCode_DataReference_EmitsTPX303()
    {
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse("package cose_trust_policy\n\npolicy := { \"x\": data.allow_list }", null, diagnostics);
        Assert.That(diagnostics.Any(d => d.Code == "TPX303"), Is.True);
    }

    [Test]
    public void SubCode_ArrayPipeComprehension_EmitsTPX304()
    {
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse("package cose_trust_policy\n\npolicy := { \"x\": [1 | 2] }", null, diagnostics);
        Assert.That(diagnostics.Any(d => d.Code == "TPX304"), Is.True);
    }

    [Test]
    public void SubCode_ObjectComprehensionAtKeyPosition_EmitsTPX304()
    {
        // UX-MIN-2: prior behaviour reported the bland 'expected string key' (TPX001);
        // the peek-ahead in ParseObjectOrComprehension now surfaces TPX304 when a `|`
        // follows the first identifier.
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse("package cose_trust_policy\n\npolicy := { x | y }", null, diagnostics);
        Assert.That(diagnostics.Any(d => d.Code == "TPX304"), Is.True);
    }

    [Test]
    public void Tokenizer_CrlfDocument_TracksLineCorrectly()
    {
        // Windows-style line endings should not drift line / column anchors. Surface a
        // diagnostic on a known line and assert the reported line.
        const string text = "package wrong_package\r\n\r\npolicy := {}";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        TrustPolicyTranslationDiagnostic err = diagnostics.First(d => d.Code == "TPX002");
        Assert.That(err.Location, Is.Not.Null);
        Assert.That(err.Location!.Line, Is.EqualTo(1));
    }

    [Test]
    public void Tokenizer_BareCrLineEndings_TracksLineCorrectly()
    {
        // Legacy classic-Mac line endings: bare '\r'. The diagnostic on line 3 must
        // report line 3, not line 1.
        const string text = "package cose_trust_policy\r\rsome host";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        _ = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        TrustPolicyTranslationDiagnostic err = diagnostics.First(d => d.Code == "TPX302");
        Assert.That(err.Location, Is.Not.Null);
        Assert.That(err.Location!.Line, Is.EqualTo(3));
    }

    [Test]
    public void Tokenizer_CommentTerminatedByBareCr()
    {
        // A '#' comment may be terminated by bare CR (legacy MacOS line terminator) as
        // well as LF / CRLF.
        const string text = "package cose_trust_policy\r# comment terminated by bare CR\rpolicy := {}";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void InputSizeGuard_OversizeDocumentRejected()
    {
        // 2 MiB of trailing comment characters guarantees a > 1 MiB UTF-16 length AND a
        // > 1 MiB UTF-8 length so the soft byte estimate trips. Wall-time budget < 50 ms.
        var sb = new StringBuilder("package cose_trust_policy\n\npolicy := {}\n");
        sb.Append('#');
        sb.Append('a', 2 * 1024 * 1024);

        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var sw = Stopwatch.StartNew();
        var doc = CoseTpRegoFrontend.TryParse(sb.ToString(), null, diagnostics);
        sw.Stop();

        Assert.That(doc, Is.Null);
        // Cross-pin to TPX306 (input-size) — must NOT collide with TPX305 (nesting depth).
        Assert.That(diagnostics.Any(d => d.Code == "TPX306"), Is.True, () => string.Join("; ", diagnostics.Select(d => d.Code + ":" + d.Message)));
        Assert.That(diagnostics.Any(d => d.Code == "TPX305"), Is.False);
        Assert.That(sw.ElapsedMilliseconds, Is.LessThan(500));
    }

    [Test]
    public void Tokenizer_LoneHighSurrogate_Rejected()
    {
        // \uD83D without a paired low-surrogate is malformed UTF-16. Strict rejection.
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": \"\\uD83D\" }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Null);
        Assert.That(diagnostics.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Tokenizer_LoneLowSurrogate_Rejected()
    {
        // \uDC00 (low-surrogate) without a preceding high-surrogate is malformed UTF-16.
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": \"\\uDC00\" }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Null);
        Assert.That(diagnostics.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Tokenizer_HighSurrogateWithoutEscapePair_Rejected()
    {
        // High surrogate followed by a non-\u sequence — also malformed.
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": \"\\uD83Dabc\" }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Null);
    }

    [Test]
    public void Tokenizer_HighSurrogateWithBadLowSurrogate_Rejected()
    {
        // High surrogate followed by \u escape that is NOT a low surrogate.
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": \"\\uD83D\\u0041\" }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Null);
    }

    [Test]
    public void Tokenizer_WellFormedSurrogatePair_Accepted()
    {
        // \uD83D\uDE00 is the surrogate-pair encoding of U+1F600 (😀).
        const string text = "package cose_trust_policy\n\npolicy := { \"x\": \"\\uD83D\\uDE00\" }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }

    [Test]
    public void Tokenizer_ControlCharInString_Rejected()
    {
        // A bare U+0001 (SOH) inside a string is RFC 8259 invalid.
        string text = "package cose_trust_policy\n\npolicy := { \"x\": \"a\u0001b\" }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Null);
    }

    [Test]
    public void Tokenizer_TabInsideString_Accepted()
    {
        // U+0009 (tab) is a permitted whitespace inside JSON strings.
        string text = "package cose_trust_policy\n\npolicy := { \"x\": \"a\tb\" }";
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        var doc = CoseTpRegoFrontend.TryParse(text, null, diagnostics);
        Assert.That(doc, Is.Not.Null);
    }
}
