// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego.Internal;

using System.Collections.Generic;
using System.Globalization;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;

/// <summary>
/// Recursive-descent parser for the cose-tp-rego/v1 constrained subset. Consumes the
/// <see cref="RegoToken"/> stream produced by <see cref="RegoTokenizer"/> and emits a closed
/// AST (<see cref="RegoValueNode"/>) plus a list of structured diagnostics. The parser does
/// not throw on user input; every error path yields a diagnostic.
/// </summary>
/// <remarks>
/// <para>
/// Grammar (verbatim from the README accept-list):
/// </para>
/// <code>
/// module       := package_decl import* rule
/// package_decl := 'package' ident ('.' ident)*
/// import       := 'import' ident ('.' ident)*           (only 'future.keywords.in' allowed)
/// rule         := 'policy' (':=' | '=') term
/// term         := object_literal | array_literal | string | number | bool | null
///               | '-' number | input_ref
/// input_ref    := 'input' '.' ident ('.' ident)*
/// object_literal := '{' (entry (',' entry)*)? ','? '}'
/// entry          := string ':' term
/// array_literal  := '[' (term (',' term)*)? ','? ']'
/// </code>
/// <para>
/// Forbidden constructs (<see cref="AssemblyStrings.CodeUntranslatableConstruct"/>) reject:
/// any reference to <c>data.*</c>, any function call (<c>http.send(...)</c>,
/// <c>regex.match(...)</c>, etc.), comprehensions (<c>{ x | y }</c>, <c>[x | y]</c>), the
/// keywords <c>some</c> / <c>every</c> / <c>with</c> / <c>default</c> / <c>not</c>, and any
/// <see cref="RegoTokenKind.UnsupportedSymbol"/>.
/// </para>
/// </remarks>
internal sealed class RegoParser
{
    private readonly List<RegoToken> Tokens;
    private readonly List<TrustPolicyTranslationDiagnostic> Diagnostics;
    private readonly string? DocumentSource;
    private int Index;
    private int NestingDepth;

    public RegoParser(List<RegoToken> tokens, List<TrustPolicyTranslationDiagnostic> diagnostics, string? documentSource)
    {
        Tokens = tokens;
        Diagnostics = diagnostics;
        DocumentSource = documentSource;
        Index = 0;
        NestingDepth = 0;
    }

    /// <summary>
    /// Parses the token stream. Returns the policy-rule body on success or <see langword="null"/>
    /// when the document is rejected; in both cases <see cref="Diagnostics"/> reflects the outcome.
    /// </summary>
    /// <returns>The parsed policy AST, or <see langword="null"/>.</returns>
    public RegoValueNode? Parse()
    {
        // 1. package
        if (!ParsePackageDeclaration())
        {
            return null;
        }

        // 2. imports (zero or more)
        while (PeekKeyword(AssemblyStrings.KeywordImport))
        {
            if (!ParseImport())
            {
                return null;
            }
        }

        // 3. exactly one `policy := <term>` rule
        RegoValueNode? policy = ParsePolicyRule();
        if (policy is null)
        {
            return null;
        }

        // 4. nothing else permitted (multiple rules / extra tokens reject).
        if (!ExpectEof())
        {
            return null;
        }

        return policy;
    }

    private bool ParsePackageDeclaration()
    {
        RegoToken first = Peek();
        if (!IsKeyword(first, AssemblyStrings.KeywordPackage))
        {
            EmitError(AssemblyStrings.CodeMissingPackage, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrPackageMissing, AssemblyStrings.RequiredPackage), first.Line, first.Column);
            return false;
        }

        Consume();
        // Accept either a single ident or a dotted path; concatenate with '.' so we can compare
        // against the required package name 'cose_trust_policy'.
        if (!TryReadDottedIdent(out string packageName, out int line, out int col))
        {
            EmitError(AssemblyStrings.CodeMissingPackage, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrPackageMissing, AssemblyStrings.RequiredPackage), line, col);
            return false;
        }

        if (!string.Equals(packageName, AssemblyStrings.RequiredPackage, System.StringComparison.Ordinal))
        {
            EmitError(AssemblyStrings.CodeMissingPackage, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrPackageMismatchFormat, packageName, AssemblyStrings.RequiredPackage), line, col);
            return false;
        }

        return true;
    }

    private bool ParseImport()
    {
        RegoToken kw = Consume();
        if (!TryReadDottedIdent(out string importName, out int line, out int col))
        {
            EmitError(AssemblyStrings.CodeForbiddenImport, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrForbiddenImportFormat, AssemblyStrings.ImportNameUnknown, AssemblyStrings.AllowedImportFutureKeywordsIn), kw.Line, kw.Column);
            return false;
        }

        if (!string.Equals(importName, AssemblyStrings.AllowedImportFutureKeywordsIn, System.StringComparison.Ordinal))
        {
            EmitError(AssemblyStrings.CodeForbiddenImport, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrForbiddenImportFormat, importName, AssemblyStrings.AllowedImportFutureKeywordsIn), line, col);
            return false;
        }

        return true;
    }

    private RegoValueNode? ParsePolicyRule()
    {
        RegoToken nameTok = Peek();
        if (nameTok.Kind != RegoTokenKind.Identifier)
        {
            EmitError(AssemblyStrings.CodeMissingPolicyRule, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrPolicyRuleMissingFormat, AssemblyStrings.PolicyRuleName), nameTok.Line, nameTok.Column);
            return null;
        }

        // A top-level `some x in coll`, `every`, `default`, `not`, or HTTP/regex/data
        // builtin call is unconstrained iteration / forbidden-builtin territory; surface as
        // TPX300 rather than the generic missing-policy-rule TPX003 so the diagnostic is
        // an accurate description of the offending construct (closes the
        // unconstrained-iteration / http-send fixture contracts).
        if (IsForbiddenIdentifier(nameTok.Text, out string forbiddenSuggestion, out string forbiddenCode))
        {
            EmitError(
                forbiddenCode,
                string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrForbiddenIdentifierFormat, nameTok.Text),
                nameTok.Line,
                nameTok.Column,
                forbiddenSuggestion);
            return null;
        }

        if (!string.Equals(nameTok.Text, AssemblyStrings.PolicyRuleName, System.StringComparison.Ordinal))
        {
            EmitError(AssemblyStrings.CodeMissingPolicyRule, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrPolicyRuleMissingFormat, AssemblyStrings.PolicyRuleName), nameTok.Line, nameTok.Column);
            return null;
        }

        Consume();

        RegoToken assign = Peek();
        if (assign.Kind != RegoTokenKind.Assign && assign.Kind != RegoTokenKind.Equals)
        {
            EmitError(AssemblyStrings.CodeMalformedRego, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnexpectedTokenFormat, RenderToken(assign), assign.Line, assign.Column, AssemblyStrings.ExpectedAssignOrEquals), assign.Line, assign.Column);
            return null;
        }

        Consume();

        // The policy value MUST be an object literal — that's the contract per §6.5.6 example.
        RegoToken next = Peek();
        if (next.Kind != RegoTokenKind.LeftBrace)
        {
            EmitError(AssemblyStrings.CodeMalformedRego, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrPolicyValueNotObjectFormat, AssemblyStrings.PolicyRuleName, RenderToken(next), next.Line, next.Column), next.Line, next.Column);
            return null;
        }

        return ParseTerm();
    }

    private bool ExpectEof()
    {
        RegoToken next = Peek();
        if (next.Kind == RegoTokenKind.EndOfFile)
        {
            return true;
        }

        // A non-EOF token after the policy rule is either a stray rule or extra junk.
        if (next.Kind == RegoTokenKind.Identifier)
        {
            EmitError(AssemblyStrings.CodeMultipleRules, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrMultipleRulesFormat, next.Text, AssemblyStrings.PolicyRuleName), next.Line, next.Column);
            return false;
        }

        EmitError(AssemblyStrings.CodeMalformedRego, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnexpectedTokenFormat, RenderToken(next), next.Line, next.Column, AssemblyStrings.TokenEofText), next.Line, next.Column);
        return false;
    }

    private RegoValueNode? ParseTerm()
    {
        RegoToken tok = Peek();
        switch (tok.Kind)
        {
            case RegoTokenKind.LeftBrace:
                return ParseObjectOrComprehension();
            case RegoTokenKind.LeftBracket:
                return ParseArrayOrComprehension();
            case RegoTokenKind.String:
                Consume();
                return new RegoScalarNode(RegoScalarKind.String, tok.Text, tok.Line, tok.Column);
            case RegoTokenKind.Number:
                Consume();
                return new RegoScalarNode(RegoScalarKind.Number, tok.Text, tok.Line, tok.Column);
            case RegoTokenKind.Minus:
                Consume();
                RegoToken numTok = Peek();
                if (numTok.Kind != RegoTokenKind.Number)
                {
                    EmitError(AssemblyStrings.CodeMalformedRego, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnexpectedTokenFormat, RenderToken(numTok), numTok.Line, numTok.Column, AssemblyStrings.ExpectedTokenNumber), numTok.Line, numTok.Column);
                    return null;
                }

                Consume();
                return new RegoScalarNode(RegoScalarKind.Number, AssemblyStrings.TokenMinus + numTok.Text, tok.Line, tok.Column);
            case RegoTokenKind.Identifier:
                return ParseIdentifierTerm(tok);
            case RegoTokenKind.UnsupportedSymbol:
                Consume();
                EmitError(AssemblyStrings.CodeComprehensionRejected, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnconstrainedIterationFormat, tok.Text), tok.Line, tok.Column);
                return null;
            default:
                Consume();
                EmitError(AssemblyStrings.CodeMalformedRego, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnexpectedTokenFormat, RenderToken(tok), tok.Line, tok.Column, AssemblyStrings.ExpectedTokenTerm), tok.Line, tok.Column);
                return null;
        }
    }

    private RegoValueNode? ParseIdentifierTerm(RegoToken tok)
    {
        // Boolean / null literals
        if (string.Equals(tok.Text, AssemblyStrings.KeywordTrue, System.StringComparison.Ordinal))
        {
            Consume();
            return new RegoScalarNode(RegoScalarKind.True, AssemblyStrings.KeywordTrue, tok.Line, tok.Column);
        }

        if (string.Equals(tok.Text, AssemblyStrings.KeywordFalse, System.StringComparison.Ordinal))
        {
            Consume();
            return new RegoScalarNode(RegoScalarKind.False, AssemblyStrings.KeywordFalse, tok.Line, tok.Column);
        }

        if (string.Equals(tok.Text, AssemblyStrings.KeywordNull, System.StringComparison.Ordinal))
        {
            Consume();
            return new RegoScalarNode(RegoScalarKind.Null, AssemblyStrings.KeywordNull, tok.Line, tok.Column);
        }

        // input.<name> reference
        if (string.Equals(tok.Text, AssemblyStrings.KeywordInput, System.StringComparison.Ordinal))
        {
            return ParseInputReference(tok);
        }

        // Forbidden identifiers — closed reject-list. Each surfaces a per-cause TPX3xx
        // sub-code (TPX301 builtin / TPX302 iteration / TPX303 data-ref) so blue-team
        // telemetry can attribute rejection rates to the offending construct class.
        if (IsForbiddenIdentifier(tok.Text, out string forbiddenSuggestion, out string code))
        {
            Consume();
            // If the next token is a '.', also consume the qualifier so the diagnostic message
            // can name the actual builtin (e.g. http.send not just http).
            string qualifier = string.Empty;
            if (Peek().Kind == RegoTokenKind.Dot)
            {
                Consume();
                if (Peek().Kind == RegoTokenKind.Identifier)
                {
                    qualifier = Consume().Text;
                }
            }

            string message = qualifier.Length > 0
                ? string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrForbiddenBuiltinFormat, tok.Text, qualifier)
                : string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrForbiddenIdentifierFormat, tok.Text);
            EmitError(code, message, tok.Line, tok.Column, forbiddenSuggestion);
            return null;
        }

        // Anything else — unknown identifier — reject.
        Consume();
        EmitError(AssemblyStrings.CodeUntranslatableConstruct, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrForbiddenIdentifierFormat, tok.Text), tok.Line, tok.Column);
        return null;
    }

    private RegoValueNode? ParseInputReference(RegoToken inputTok)
    {
        Consume(); // consume 'input'
        if (Peek().Kind != RegoTokenKind.Dot)
        {
            EmitError(AssemblyStrings.CodeMalformedRego, AssemblyStrings.ErrInputDotMissingIdentifier, inputTok.Line, inputTok.Column);
            return null;
        }

        Consume(); // consume '.'
        RegoToken nameTok = Peek();
        if (nameTok.Kind != RegoTokenKind.Identifier)
        {
            EmitError(AssemblyStrings.CodeMalformedRego, AssemblyStrings.ErrInputDotMissingIdentifier, nameTok.Line, nameTok.Column);
            return null;
        }

        Consume();
        // Concatenate dotted segments (e.g. input.trusted_log_hosts.primary). The parameter
        // name in the TrustPolicySpec is the dot-joined tail.
        var parts = new List<string> { nameTok.Text };
        while (Peek().Kind == RegoTokenKind.Dot)
        {
            Consume();
            RegoToken seg = Peek();
            if (seg.Kind != RegoTokenKind.Identifier)
            {
                EmitError(AssemblyStrings.CodeMalformedRego, AssemblyStrings.ErrInputDotMissingIdentifier, seg.Line, seg.Column);
                return null;
            }

            Consume();
            parts.Add(seg.Text);
        }

        return new RegoInputRefNode(string.Join(AssemblyStrings.DotChar, parts), inputTok.Line, inputTok.Column);
    }

    private RegoValueNode? ParseObjectOrComprehension()
    {
        RegoToken open = Consume(); // consume '{'
        if (++NestingDepth > AssemblyStrings.MaxNestingDepth)
        {
            // Reject before recursing further (RT-MAJ-1 / TPX305). The depth counter is
            // decremented in the success arms and kept incremented on rejection so a
            // parent recovery path also short-circuits.
            EmitError(
                AssemblyStrings.CodeMaxNestingDepthExceeded,
                string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrMaxNestingDepthExceededFormat, open.Line, open.Column, AssemblyStrings.MaxNestingDepth),
                open.Line,
                open.Column,
                AssemblyStrings.SuggestionFlattenNesting);
            return null;
        }

        var entries = new List<RegoObjectEntry>();
        var seenKeys = new HashSet<string>(System.StringComparer.Ordinal);

        // Empty object
        if (Peek().Kind == RegoTokenKind.RightBrace)
        {
            Consume();
            NestingDepth--;
            return new RegoObjectNode(entries, open.Line, open.Column);
        }

        while (true)
        {
            RegoToken keyTok = Peek();
            if (keyTok.Kind != RegoTokenKind.String)
            {
                // A comprehension `{ x | y }` would land here with x as an Identifier and a
                // following `|` UnsupportedSymbol. Peek ahead to surface the more accurate
                // TPX304 (comprehension rejected) when we can detect the comprehension shape
                // rather than the bland 'expected string key'. Improves UX-MIN-2.
                if (keyTok.Kind == RegoTokenKind.Identifier && PeekAfterIdentifierIsPipe())
                {
                    EmitError(AssemblyStrings.CodeComprehensionRejected, AssemblyStrings.ErrComprehensionRejected, keyTok.Line, keyTok.Column);
                    return null;
                }

                EmitError(AssemblyStrings.CodeMalformedRego, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnexpectedTokenFormat, RenderToken(keyTok), keyTok.Line, keyTok.Column, AssemblyStrings.ExpectedTokenStringKey), keyTok.Line, keyTok.Column);
                return null;
            }

            Consume();

            if (Peek().Kind != RegoTokenKind.Colon)
            {
                RegoToken bad = Peek();
                EmitError(AssemblyStrings.CodeMalformedRego, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnexpectedTokenFormat, RenderToken(bad), bad.Line, bad.Column, AssemblyStrings.ExpectedTokenColon), bad.Line, bad.Column);
                return null;
            }

            Consume();

            RegoValueNode? value = ParseTerm();
            if (value is null)
            {
                return null;
            }

            if (!seenKeys.Add(keyTok.Text))
            {
                EmitError(AssemblyStrings.CodeMalformedRego, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrDuplicateObjectKeyFormat, keyTok.Text, keyTok.Line, keyTok.Column), keyTok.Line, keyTok.Column);
                return null;
            }

            entries.Add(new RegoObjectEntry(keyTok.Text, value, keyTok.Line, keyTok.Column));

            RegoToken sep = Peek();
            if (sep.Kind == RegoTokenKind.Comma)
            {
                Consume();
                if (Peek().Kind == RegoTokenKind.RightBrace)
                {
                    Consume();
                    NestingDepth--;
                    return new RegoObjectNode(entries, open.Line, open.Column);
                }

                continue;
            }

            if (sep.Kind == RegoTokenKind.RightBrace)
            {
                Consume();
                NestingDepth--;
                return new RegoObjectNode(entries, open.Line, open.Column);
            }

            // A `|` would indicate a comprehension; the unsupported-symbol token would surface
            // here. Either way it's a TPX304.
            EmitError(AssemblyStrings.CodeComprehensionRejected, AssemblyStrings.ErrComprehensionRejected, sep.Line, sep.Column);
            return null;
        }
    }

    private bool PeekAfterIdentifierIsPipe()
    {
        // Look one token past the current one. A peek-ahead for the comprehension
        // detection in object position; lightweight (no extra tokenization).
        if (Index + 1 >= Tokens.Count)
        {
            return false;
        }

        RegoToken next = Tokens[Index + 1];
        return next.Kind == RegoTokenKind.UnsupportedSymbol && next.Text == AssemblyStrings.PipeChar;
    }

    private RegoValueNode? ParseArrayOrComprehension()
    {
        RegoToken open = Consume(); // consume '['
        if (++NestingDepth > AssemblyStrings.MaxNestingDepth)
        {
            EmitError(
                AssemblyStrings.CodeMaxNestingDepthExceeded,
                string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrMaxNestingDepthExceededFormat, open.Line, open.Column, AssemblyStrings.MaxNestingDepth),
                open.Line,
                open.Column,
                AssemblyStrings.SuggestionFlattenNesting);
            return null;
        }

        var items = new List<RegoValueNode>();

        if (Peek().Kind == RegoTokenKind.RightBracket)
        {
            Consume();
            NestingDepth--;
            return new RegoArrayNode(items, open.Line, open.Column);
        }

        while (true)
        {
            RegoValueNode? item = ParseTerm();
            if (item is null)
            {
                return null;
            }

            items.Add(item);

            RegoToken sep = Peek();
            if (sep.Kind == RegoTokenKind.Comma)
            {
                Consume();
                if (Peek().Kind == RegoTokenKind.RightBracket)
                {
                    Consume();
                    NestingDepth--;
                    return new RegoArrayNode(items, open.Line, open.Column);
                }

                continue;
            }

            if (sep.Kind == RegoTokenKind.RightBracket)
            {
                Consume();
                NestingDepth--;
                return new RegoArrayNode(items, open.Line, open.Column);
            }

            EmitError(AssemblyStrings.CodeComprehensionRejected, AssemblyStrings.ErrComprehensionRejected, sep.Line, sep.Column);
            return null;
        }
    }

    private bool TryReadDottedIdent(out string text, out int line, out int column)
    {
        RegoToken first = Peek();
        if (first.Kind != RegoTokenKind.Identifier)
        {
            text = string.Empty;
            line = first.Line;
            column = first.Column;
            return false;
        }

        Consume();
        var parts = new List<string> { first.Text };
        line = first.Line;
        column = first.Column;
        while (Peek().Kind == RegoTokenKind.Dot)
        {
            Consume();
            RegoToken seg = Peek();
            if (seg.Kind != RegoTokenKind.Identifier)
            {
                text = string.Join(AssemblyStrings.DotChar, parts);
                return true;
            }

            Consume();
            parts.Add(seg.Text);
        }

        text = string.Join(AssemblyStrings.DotChar, parts);
        return true;
    }

    private RegoToken Peek() => Tokens[Index];

    private RegoToken Consume()
    {
        RegoToken t = Tokens[Index];
        if (Index < Tokens.Count - 1)
        {
            Index++;
        }

        return t;
    }

    private bool PeekKeyword(string keyword)
    {
        RegoToken t = Peek();
        return t.Kind == RegoTokenKind.Identifier && string.Equals(t.Text, keyword, System.StringComparison.Ordinal);
    }

    private static bool IsKeyword(RegoToken t, string keyword) =>
        t.Kind == RegoTokenKind.Identifier && string.Equals(t.Text, keyword, System.StringComparison.Ordinal);

    private static bool IsForbiddenIdentifier(string text, out string suggestion, out string code)
    {
        // Closed reject-list; mirrors the README accept-list inversely. A new forbidden
        // identifier requires a code change here (and a fixture under untranslatable/).
        // Returns the per-cause sub-code so blue-team telemetry attributes rejection rates
        // accurately (TPX301 builtin / TPX302 iteration / TPX303 data-ref).
        switch (text)
        {
            case AssemblyStrings.ForbiddenNamespaceHttp:
            case AssemblyStrings.ForbiddenNamespaceRegex:
            case AssemblyStrings.ForbiddenNamespaceFile:
            case AssemblyStrings.ForbiddenNamespaceIo:
            case AssemblyStrings.ForbiddenNamespaceOs:
            case AssemblyStrings.ForbiddenNamespaceCrypto:
            case AssemblyStrings.ForbiddenNamespaceNet:
            case AssemblyStrings.ForbiddenNamespaceTime:
            case AssemblyStrings.ForbiddenNamespaceOpa:
                suggestion = AssemblyStrings.SuggestionRemoveSideEffectingBuiltin;
                code = AssemblyStrings.CodeForbiddenBuiltin;
                return true;
            case AssemblyStrings.ForbiddenIdentData:
                suggestion = AssemblyStrings.SuggestionUseInput;
                code = AssemblyStrings.CodeReservedDataReference;
                return true;
            case AssemblyStrings.ForbiddenIdentSome:
            case AssemblyStrings.ForbiddenIdentEvery:
            case AssemblyStrings.ForbiddenIdentWith:
            case AssemblyStrings.ForbiddenIdentDefault:
            case AssemblyStrings.ForbiddenIdentNot:
            case AssemblyStrings.ForbiddenIdentEval:
                suggestion = AssemblyStrings.SuggestionUseProperty;
                code = AssemblyStrings.CodeUnconstrainedIteration;
                return true;
            default:
                suggestion = string.Empty;
                code = AssemblyStrings.CodeUntranslatableConstruct;
                return false;
        }
    }

    private static string RenderToken(RegoToken t) => t.Kind switch
    {
        RegoTokenKind.EndOfFile => AssemblyStrings.TokenEofText,
        _ => t.Text,
    };

    private void EmitError(string code, string message, int line, int column, string? suggestion = null)
    {
        Diagnostics.Add(new TrustPolicyTranslationDiagnostic
        {
            Severity = TrustPolicySeverity.Error,
            Code = code,
            Message = message,
            Location = MakeLocation(line, column),
            Suggestion = suggestion,
        });
    }

    private SourceLocation MakeLocation(int line, int column)
    {
        // Embed both the document source identifier and the line:column anchor so editor
        // tooling can navigate to the offending site (§6.5.10 #7).
        string source = string.IsNullOrEmpty(DocumentSource)
            ? string.Format(CultureInfo.InvariantCulture, AssemblyStrings.LineColFormat, line, column)
            : string.Format(CultureInfo.InvariantCulture, AssemblyStrings.LocationFormat, DocumentSource, string.Format(CultureInfo.InvariantCulture, AssemblyStrings.LineColFormat, line, column));
        return new SourceLocation(source, line, column, 0);
    }
}
