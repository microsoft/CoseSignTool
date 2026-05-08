// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego.Internal;

using System.Collections.Generic;
using System.Globalization;
using System.Text;

/// <summary>
/// Hand-rolled tokenizer for the cose-tp-rego/v1 constrained subset. Recognises a closed
/// set of token kinds (<see cref="RegoTokenKind"/>) and emits structured diagnostics for
/// lexical errors (unterminated string, invalid escape, malformed number).
/// </summary>
/// <remarks>
/// <para>
/// The tokenizer is intentionally NOT a full Rego lexer. Anything outside the recognised
/// vocabulary (e.g. <c>|</c>, <c>;</c>, <c>!</c>, <c>?</c>, <c>==</c>, <c>!=</c>, <c>++</c>)
/// is emitted as <see cref="RegoTokenKind.UnsupportedSymbol"/> with the raw character so the
/// parser surfaces a TPX300 describing the offending construct. This keeps the reject-list
/// closed without needing a "what did the user mean" heuristic.
/// </para>
/// <para>
/// Line / column tracking is 1-based (matching most editors). Comments are <c># ... &lt;eol&gt;</c>
/// per Rego convention. String literals are double-quoted with the standard JSON escape set
/// — single-quoted strings and backtick strings are explicitly rejected to keep the lexical
/// surface aligned with the user-visible Rego documentation.
/// </para>
/// </remarks>
internal sealed class RegoTokenizer
{
    private readonly string Source;
    private int Position;
    private int Line;
    private int Column;
    private readonly List<RegoLexicalDiagnostic> LexicalErrors;

    public RegoTokenizer(string source)
    {
        Cose.Abstractions.Guard.ThrowIfNull(source);
        Source = source;
        Position = 0;
        Line = 1;
        Column = 1;
        LexicalErrors = new List<RegoLexicalDiagnostic>();
    }

    /// <summary>Gets the lexical errors collected during tokenization.</summary>
    public IReadOnlyList<RegoLexicalDiagnostic> Errors => LexicalErrors;

    /// <summary>Drives the tokenizer to completion and returns the token stream.</summary>
    /// <returns>The full token stream including the trailing <see cref="RegoTokenKind.EndOfFile"/> sentinel.</returns>
    public List<RegoToken> Tokenize()
    {
        var tokens = new List<RegoToken>();
        while (true)
        {
            SkipWhitespaceAndComments();
            if (Position >= Source.Length)
            {
                tokens.Add(new RegoToken(RegoTokenKind.EndOfFile, string.Empty, Line, Column));
                return tokens;
            }

            int startLine = Line;
            int startCol = Column;
            char c = Source[Position];

            if (IsIdentifierStart(c))
            {
                tokens.Add(ReadIdentifier(startLine, startCol));
                continue;
            }

            if (c == '"')
            {
                tokens.Add(ReadString(startLine, startCol));
                continue;
            }

            if (IsDigit(c))
            {
                tokens.Add(ReadNumber(startLine, startCol));
                continue;
            }

            // Punctuation / operators
            switch (c)
            {
                case '{': Advance(); tokens.Add(new RegoToken(RegoTokenKind.LeftBrace, AssemblyStrings.TokenLeftBrace, startLine, startCol)); continue;
                case '}': Advance(); tokens.Add(new RegoToken(RegoTokenKind.RightBrace, AssemblyStrings.TokenRightBrace, startLine, startCol)); continue;
                case '[': Advance(); tokens.Add(new RegoToken(RegoTokenKind.LeftBracket, AssemblyStrings.TokenLeftBracket, startLine, startCol)); continue;
                case ']': Advance(); tokens.Add(new RegoToken(RegoTokenKind.RightBracket, AssemblyStrings.TokenRightBracket, startLine, startCol)); continue;
                case '(': Advance(); tokens.Add(new RegoToken(RegoTokenKind.LeftParen, AssemblyStrings.TokenLeftParen, startLine, startCol)); continue;
                case ')': Advance(); tokens.Add(new RegoToken(RegoTokenKind.RightParen, AssemblyStrings.TokenRightParen, startLine, startCol)); continue;
                case ',': Advance(); tokens.Add(new RegoToken(RegoTokenKind.Comma, AssemblyStrings.TokenComma, startLine, startCol)); continue;
                case '.': Advance(); tokens.Add(new RegoToken(RegoTokenKind.Dot, AssemblyStrings.TokenDot, startLine, startCol)); continue;
                case '-': Advance(); tokens.Add(new RegoToken(RegoTokenKind.Minus, AssemblyStrings.TokenMinus, startLine, startCol)); continue;
                case ':':
                    if (Position + 1 < Source.Length && Source[Position + 1] == '=')
                    {
                        Advance(); Advance();
                        tokens.Add(new RegoToken(RegoTokenKind.Assign, AssemblyStrings.TokenAssign, startLine, startCol));
                    }
                    else
                    {
                        Advance();
                        tokens.Add(new RegoToken(RegoTokenKind.Colon, AssemblyStrings.TokenColon, startLine, startCol));
                    }

                    continue;
                case '=':
                    Advance();
                    tokens.Add(new RegoToken(RegoTokenKind.Equals, AssemblyStrings.TokenEquals, startLine, startCol));
                    continue;
                default:
                    Advance();
                    tokens.Add(new RegoToken(RegoTokenKind.UnsupportedSymbol, c.ToString(CultureInfo.InvariantCulture), startLine, startCol));
                    continue;
            }
        }
    }

    private void SkipWhitespaceAndComments()
    {
        while (Position < Source.Length)
        {
            char c = Source[Position];
            if (c == ' ' || c == '\t')
            {
                Advance();
                continue;
            }

            if (c == '\n')
            {
                Position++;
                Line++;
                Column = 1;
                continue;
            }

            if (c == '\r')
            {
                // Handle '\r\n', bare '\r' (legacy MacOS), and '\r…<not-LF>' uniformly:
                // each is one logical line terminator. Without this branch a Windows
                // CRLF document was indistinguishable from LF, but a bare-CR document
                // would drift line/column anchors in diagnostics (RT-MIN-1).
                Position++;
                if (Position < Source.Length && Source[Position] == '\n')
                {
                    Position++;
                }

                Line++;
                Column = 1;
                continue;
            }

            if (c == '#')
            {
                while (Position < Source.Length && Source[Position] != '\n' && Source[Position] != '\r')
                {
                    Position++;
                    Column++;
                }

                continue;
            }

            return;
        }
    }

    private RegoToken ReadIdentifier(int startLine, int startCol)
    {
        int start = Position;
        while (Position < Source.Length && IsIdentifierContinue(Source[Position]))
        {
            Advance();
        }

        string text = Source.Substring(start, Position - start);
        return new RegoToken(RegoTokenKind.Identifier, text, startLine, startCol);
    }

    private RegoToken ReadString(int startLine, int startCol)
    {
        // Skip opening quote
        Advance();
        var sb = new StringBuilder();
        while (Position < Source.Length)
        {
            char c = Source[Position];
            if (c == '"')
            {
                Advance();
                return new RegoToken(RegoTokenKind.String, sb.ToString(), startLine, startCol);
            }

            if (c == '\\')
            {
                Advance();
                if (Position >= Source.Length)
                {
                    LexicalErrors.Add(new RegoLexicalDiagnostic(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnterminatedString, startLine, startCol), startLine, startCol));
                    return new RegoToken(RegoTokenKind.String, sb.ToString(), startLine, startCol);
                }

                char esc = Source[Position];
                switch (esc)
                {
                    case '"': sb.Append('"'); Advance(); break;
                    case '\\': sb.Append('\\'); Advance(); break;
                    case '/': sb.Append('/'); Advance(); break;
                    case 'b': sb.Append('\b'); Advance(); break;
                    case 'f': sb.Append('\f'); Advance(); break;
                    case 'n': sb.Append('\n'); Advance(); break;
                    case 'r': sb.Append('\r'); Advance(); break;
                    case 't': sb.Append('\t'); Advance(); break;
                    case 'u':
                        Advance();
                        if (!TryReadUnicodeEscape(out char unicode))
                        {
                            LexicalErrors.Add(new RegoLexicalDiagnostic(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrInvalidEscapeFormat, AssemblyStrings.EscapeUnicodePrefix, Line, Column), Line, Column));
                            return new RegoToken(RegoTokenKind.String, sb.ToString(), startLine, startCol);
                        }

                        // Reject lone surrogates: a high surrogate (D800-DBFF) MUST be
                        // followed by a low-surrogate `\uDCxx` escape pair; a bare low
                        // surrogate (DC00-DFFF) is malformed UTF-16. Strict rejection
                        // preserves byte-equality with the JSON frontend's IR.
                        if (char.IsHighSurrogate(unicode))
                        {
                            if (Position + 2 > Source.Length || Source[Position] != '\\' || Source[Position + 1] != 'u')
                            {
                                LexicalErrors.Add(new RegoLexicalDiagnostic(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrLoneSurrogateFormat, (int)unicode, Line, Column), Line, Column));
                                return new RegoToken(RegoTokenKind.String, sb.ToString(), startLine, startCol);
                            }

                            // consume the '\u' for the trailing pair
                            Advance();
                            Advance();
                            if (!TryReadUnicodeEscape(out char low) || !char.IsLowSurrogate(low))
                            {
                                LexicalErrors.Add(new RegoLexicalDiagnostic(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrLoneSurrogateFormat, (int)unicode, Line, Column), Line, Column));
                                return new RegoToken(RegoTokenKind.String, sb.ToString(), startLine, startCol);
                            }

                            sb.Append(unicode);
                            sb.Append(low);
                            break;
                        }

                        if (char.IsLowSurrogate(unicode))
                        {
                            LexicalErrors.Add(new RegoLexicalDiagnostic(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrLoneSurrogateFormat, (int)unicode, Line, Column), Line, Column));
                            return new RegoToken(RegoTokenKind.String, sb.ToString(), startLine, startCol);
                        }

                        sb.Append(unicode);
                        break;
                    default:
                        LexicalErrors.Add(new RegoLexicalDiagnostic(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrInvalidEscapeFormat, esc, Line, Column), Line, Column));
                        Advance();
                        break;
                }

                continue;
            }

            if (c == '\n')
            {
                LexicalErrors.Add(new RegoLexicalDiagnostic(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnterminatedString, startLine, startCol), startLine, startCol));
                return new RegoToken(RegoTokenKind.String, sb.ToString(), startLine, startCol);
            }

            // Reject unescaped control characters (U+0000 — U+001F except \t/\n which are
            // handled above). RFC 8259 forbids them in JSON string contents and so does the
            // canonical IR.
            if (c < 0x20 && c != '\t')
            {
                LexicalErrors.Add(new RegoLexicalDiagnostic(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrControlCharFormat, (int)c, Line, Column), Line, Column));
                return new RegoToken(RegoTokenKind.String, sb.ToString(), startLine, startCol);
            }

            sb.Append(c);
            Advance();
        }

        LexicalErrors.Add(new RegoLexicalDiagnostic(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnterminatedString, startLine, startCol), startLine, startCol));
        return new RegoToken(RegoTokenKind.String, sb.ToString(), startLine, startCol);
    }

    private bool TryReadUnicodeEscape(out char result)
    {
        result = '\0';
        if (Position + 4 > Source.Length)
        {
            return false;
        }

        int codepoint = 0;
        for (int i = 0; i < 4; i++)
        {
            char c = Source[Position];
            int digit;
            if (c >= '0' && c <= '9')
            {
                digit = c - '0';
            }
            else if (c >= 'a' && c <= 'f')
            {
                digit = 10 + (c - 'a');
            }
            else if (c >= 'A' && c <= 'F')
            {
                digit = 10 + (c - 'A');
            }
            else
            {
                return false;
            }

            codepoint = (codepoint << 4) | digit;
            Advance();
        }

        result = (char)codepoint;
        return true;
    }

    private RegoToken ReadNumber(int startLine, int startCol)
    {
        int start = Position;
        while (Position < Source.Length && IsDigit(Source[Position]))
        {
            Advance();
        }

        // Optional fractional part — only when '.' is followed by another digit so we
        // don't accidentally swallow object-member access like `input.5` (handled in the
        // parser) or accidental `.` punctuation.
        if (Position < Source.Length && Source[Position] == '.' && Position + 1 < Source.Length && IsDigit(Source[Position + 1]))
        {
            Advance(); // consume '.'
            while (Position < Source.Length && IsDigit(Source[Position]))
            {
                Advance();
            }
        }

        // Optional exponent
        if (Position < Source.Length && (Source[Position] == 'e' || Source[Position] == 'E'))
        {
            Advance();
            if (Position < Source.Length && (Source[Position] == '+' || Source[Position] == '-'))
            {
                Advance();
            }

            int expStart = Position;
            while (Position < Source.Length && IsDigit(Source[Position]))
            {
                Advance();
            }

            if (Position == expStart)
            {
                LexicalErrors.Add(new RegoLexicalDiagnostic(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrInvalidNumberFormat, Source.Substring(start, Position - start), startLine, startCol), startLine, startCol));
            }
        }

        string text = Source.Substring(start, Position - start);
        return new RegoToken(RegoTokenKind.Number, text, startLine, startCol);
    }

    private void Advance()
    {
        if (Position < Source.Length)
        {
            Position++;
            Column++;
        }
    }

    private static bool IsIdentifierStart(char c) => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';

    private static bool IsIdentifierContinue(char c) => IsIdentifierStart(c) || IsDigit(c);

    private static bool IsDigit(char c) => c >= '0' && c <= '9';
}
