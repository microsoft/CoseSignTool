// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego.Internal;

/// <summary>
/// Token kinds emitted by <see cref="RegoTokenizer"/>. The set is intentionally minimal —
/// just the surface the constrained-subset parser distinguishes. Anything else (operators
/// like <c>==</c>, <c>!=</c>, <c>!</c>, <c>;</c>, <c>|</c>) lands in
/// <see cref="UnsupportedSymbol"/> so the parser surfaces a TPX300 with the offending text.
/// </summary>
internal enum RegoTokenKind
{
    /// <summary>End-of-input sentinel.</summary>
    EndOfFile,

    /// <summary>An identifier (alpha, alphanumeric, or <c>_</c>).</summary>
    Identifier,

    /// <summary>A double-quoted string literal (including escape decoding).</summary>
    String,

    /// <summary>An integer or decimal literal (no unary sign — leading <c>-</c> is its own token).</summary>
    Number,

    /// <summary><c>{</c>.</summary>
    LeftBrace,

    /// <summary><c>}</c>.</summary>
    RightBrace,

    /// <summary><c>[</c>.</summary>
    LeftBracket,

    /// <summary><c>]</c>.</summary>
    RightBracket,

    /// <summary><c>(</c>.</summary>
    LeftParen,

    /// <summary><c>)</c>.</summary>
    RightParen,

    /// <summary><c>,</c>.</summary>
    Comma,

    /// <summary><c>:</c>.</summary>
    Colon,

    /// <summary><c>.</c>.</summary>
    Dot,

    /// <summary><c>:=</c>.</summary>
    Assign,

    /// <summary><c>=</c> — accepted as an alias for <c>:=</c> at top-level (Rego compatibility).</summary>
    Equals,

    /// <summary><c>-</c> (used only as a unary numeric prefix; binary subtraction is rejected).</summary>
    Minus,

    /// <summary>
    /// A token the constrained subset does not recognise (e.g. <c>|</c>, <c>;</c>, <c>?</c>).
    /// The parser surfaces these as TPX300.
    /// </summary>
    UnsupportedSymbol,
}
