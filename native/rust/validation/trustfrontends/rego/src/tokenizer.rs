// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hand-rolled tokenizer for the cose-tp-rego/v1 constrained subset.
//!
//! Recognises a closed set of token kinds and emits structured diagnostics
//! for lexical errors (unterminated string, invalid escape, malformed
//! number, lone surrogate, unescaped control character).
//!
//! The tokenizer is intentionally NOT a full Rego lexer. Anything outside
//! the recognised vocabulary (e.g. `|`, `;`, `!`, `?`, `==`, `!=`, `++`)
//! is emitted as [`TokenKind::UnsupportedSymbol`] with the raw character so
//! the parser surfaces an accurate TPX300/TPX304 describing the offending
//! construct. This keeps the reject-list closed without needing a "what
//! did the user mean" heuristic.
//!
//! Line / column tracking is 1-based (matching most editors). Comments are
//! `# … <eol>` per Rego convention. String literals are double-quoted with
//! the standard JSON escape set.

use crate::strings::TOKEN_EOF_TEXT;

/// Token kinds emitted by [`Tokenizer`]. Closed enum — additions force a
/// matching parser change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TokenKind {
    EndOfFile,
    Identifier,
    String,
    Number,
    LeftBrace,
    RightBrace,
    LeftBracket,
    RightBracket,
    LeftParen,
    RightParen,
    Comma,
    Colon,
    Dot,
    Assign,
    Equals,
    Minus,
    UnsupportedSymbol,
}

/// One lexed token with its anchor in the source document.
#[derive(Clone, Debug)]
pub(crate) struct Token {
    pub kind: TokenKind,
    pub text: String,
    pub line: u32,
    pub column: u32,
}

/// Lexical diagnostic surfaced by [`Tokenizer`] while consuming the
/// document. Promoted to a [`cose_sign1_trust_policy_spec::TrustPolicyTranslationDiagnostic`]
/// at the frontend boundary.
#[derive(Clone, Debug)]
pub(crate) struct LexicalDiagnostic {
    pub message: String,
    pub line: u32,
    pub column: u32,
}

/// Hand-rolled tokenizer over a UTF-8 source string.
pub(crate) struct Tokenizer {
    chars: Vec<char>,
    position: usize,
    line: u32,
    column: u32,
    errors: Vec<LexicalDiagnostic>,
}

impl Tokenizer {
    /// Construct a tokenizer over `source`. Internally materialises the
    /// `char` view of the input so column/position tracking is in code
    /// points (matching editor expectations) rather than UTF-8 bytes.
    pub fn new(source: &str) -> Self {
        Self {
            chars: source.chars().collect(),
            position: 0,
            line: 1,
            column: 1,
            errors: Vec::new(),
        }
    }

    /// Drive the tokenizer to completion. Returns the full token stream
    /// (including the trailing [`TokenKind::EndOfFile`] sentinel) and any
    /// lexical errors collected along the way.
    pub fn tokenize(mut self) -> (Vec<Token>, Vec<LexicalDiagnostic>) {
        let mut tokens: Vec<Token> = Vec::new();
        loop {
            self.skip_whitespace_and_comments();
            if self.position >= self.chars.len() {
                tokens.push(Token {
                    kind: TokenKind::EndOfFile,
                    text: String::new(),
                    line: self.line,
                    column: self.column,
                });
                return (tokens, self.errors);
            }

            let start_line = self.line;
            let start_col = self.column;
            let c = self.chars[self.position];

            if Self::is_identifier_start(c) {
                tokens.push(self.read_identifier(start_line, start_col));
                continue;
            }

            if c == '"' {
                tokens.push(self.read_string(start_line, start_col));
                continue;
            }

            if c.is_ascii_digit() {
                tokens.push(self.read_number(start_line, start_col));
                continue;
            }

            // Punctuation / operators.
            match c {
                '{' => {
                    self.advance();
                    tokens.push(Token { kind: TokenKind::LeftBrace, text: "{".to_owned(), line: start_line, column: start_col });
                }
                '}' => {
                    self.advance();
                    tokens.push(Token { kind: TokenKind::RightBrace, text: "}".to_owned(), line: start_line, column: start_col });
                }
                '[' => {
                    self.advance();
                    tokens.push(Token { kind: TokenKind::LeftBracket, text: "[".to_owned(), line: start_line, column: start_col });
                }
                ']' => {
                    self.advance();
                    tokens.push(Token { kind: TokenKind::RightBracket, text: "]".to_owned(), line: start_line, column: start_col });
                }
                '(' => {
                    self.advance();
                    tokens.push(Token { kind: TokenKind::LeftParen, text: "(".to_owned(), line: start_line, column: start_col });
                }
                ')' => {
                    self.advance();
                    tokens.push(Token { kind: TokenKind::RightParen, text: ")".to_owned(), line: start_line, column: start_col });
                }
                ',' => {
                    self.advance();
                    tokens.push(Token { kind: TokenKind::Comma, text: ",".to_owned(), line: start_line, column: start_col });
                }
                '.' => {
                    self.advance();
                    tokens.push(Token { kind: TokenKind::Dot, text: ".".to_owned(), line: start_line, column: start_col });
                }
                '-' => {
                    self.advance();
                    tokens.push(Token { kind: TokenKind::Minus, text: "-".to_owned(), line: start_line, column: start_col });
                }
                ':' => {
                    if self.position + 1 < self.chars.len() && self.chars[self.position + 1] == '=' {
                        self.advance();
                        self.advance();
                        tokens.push(Token { kind: TokenKind::Assign, text: ":=".to_owned(), line: start_line, column: start_col });
                    } else {
                        self.advance();
                        tokens.push(Token { kind: TokenKind::Colon, text: ":".to_owned(), line: start_line, column: start_col });
                    }
                }
                '=' => {
                    self.advance();
                    tokens.push(Token { kind: TokenKind::Equals, text: "=".to_owned(), line: start_line, column: start_col });
                }
                other => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::UnsupportedSymbol,
                        text: other.to_string(),
                        line: start_line,
                        column: start_col,
                    });
                }
            }
        }
    }

    fn skip_whitespace_and_comments(&mut self) {
        while self.position < self.chars.len() {
            let c = self.chars[self.position];
            if c == ' ' || c == '\t' {
                self.advance();
                continue;
            }

            if c == '\n' {
                self.position += 1;
                self.line += 1;
                self.column = 1;
                continue;
            }

            if c == '\r' {
                // Handle '\r\n', bare '\r' (legacy Mac), and '\r…<not-LF>'
                // uniformly: each is one logical line terminator. Without
                // this branch, bare-CR documents would drift line/column
                // anchors in diagnostics.
                self.position += 1;
                if self.position < self.chars.len() && self.chars[self.position] == '\n' {
                    self.position += 1;
                }
                self.line += 1;
                self.column = 1;
                continue;
            }

            if c == '#' {
                while self.position < self.chars.len() {
                    let cc = self.chars[self.position];
                    if cc == '\n' || cc == '\r' {
                        break;
                    }
                    self.position += 1;
                    self.column += 1;
                }
                continue;
            }

            return;
        }
    }

    fn read_identifier(&mut self, start_line: u32, start_col: u32) -> Token {
        let start = self.position;
        while self.position < self.chars.len() && Self::is_identifier_continue(self.chars[self.position]) {
            self.advance();
        }
        let text: String = self.chars[start..self.position].iter().collect();
        Token { kind: TokenKind::Identifier, text, line: start_line, column: start_col }
    }

    fn read_string(&mut self, start_line: u32, start_col: u32) -> Token {
        // Consume opening quote.
        self.advance();
        let mut s = String::new();
        while self.position < self.chars.len() {
            let c = self.chars[self.position];
            if c == '"' {
                self.advance();
                return Token { kind: TokenKind::String, text: s, line: start_line, column: start_col };
            }

            if c == '\\' {
                self.advance();
                if self.position >= self.chars.len() {
                    self.push_err(format!("Unterminated string literal beginning at line {start_line}, column {start_col}."), start_line, start_col);
                    return Token { kind: TokenKind::String, text: s, line: start_line, column: start_col };
                }
                let esc = self.chars[self.position];
                match esc {
                    '"' => { s.push('"'); self.advance(); }
                    '\\' => { s.push('\\'); self.advance(); }
                    '/' => { s.push('/'); self.advance(); }
                    'b' => { s.push('\u{0008}'); self.advance(); }
                    'f' => { s.push('\u{000C}'); self.advance(); }
                    'n' => { s.push('\n'); self.advance(); }
                    'r' => { s.push('\r'); self.advance(); }
                    't' => { s.push('\t'); self.advance(); }
                    'u' => {
                        self.advance();
                        match self.try_read_unicode_escape() {
                            Some(unit) => {
                                // Handle surrogate pairs strictly per RFC 8259:
                                // a high surrogate (D800-DBFF) MUST be followed
                                // by a low-surrogate \uDCxx; a bare low surrogate
                                // is malformed UTF-16. Strict rejection preserves
                                // byte-equality with the JSON frontend's IR.
                                if (0xD800..=0xDBFF).contains(&unit) {
                                    let line_at = self.line;
                                    let col_at = self.column;
                                    let pair_ok = self.position + 1 < self.chars.len()
                                        && self.chars[self.position] == '\\'
                                        && self.chars[self.position + 1] == 'u';
                                    if !pair_ok {
                                        self.push_err(format!("Unicode escape '\\u{unit:04X}' at line {line_at}, column {col_at} produced an unpaired surrogate code unit. Strings in cose-tp-rego/v1 must encode well-formed UTF-16 so the canonical IR survives JSON round-trip."), line_at, col_at);
                                        return Token { kind: TokenKind::String, text: s, line: start_line, column: start_col };
                                    }
                                    self.advance();
                                    self.advance();
                                    let low = match self.try_read_unicode_escape() {
                                        Some(u) => u,
                                        None => {
                                            self.push_err(format!("Unicode escape '\\u{unit:04X}' at line {line_at}, column {col_at} produced an unpaired surrogate code unit. Strings in cose-tp-rego/v1 must encode well-formed UTF-16 so the canonical IR survives JSON round-trip."), line_at, col_at);
                                            return Token { kind: TokenKind::String, text: s, line: start_line, column: start_col };
                                        }
                                    };
                                    if !(0xDC00..=0xDFFF).contains(&low) {
                                        self.push_err(format!("Unicode escape '\\u{unit:04X}' at line {line_at}, column {col_at} produced an unpaired surrogate code unit. Strings in cose-tp-rego/v1 must encode well-formed UTF-16 so the canonical IR survives JSON round-trip."), line_at, col_at);
                                        return Token { kind: TokenKind::String, text: s, line: start_line, column: start_col };
                                    }
                                    let high = unit as u32;
                                    let low = low as u32;
                                    let combined = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
                                    match char::from_u32(combined) {
                                        Some(ch) => s.push(ch),
                                        None => {
                                            self.push_err(format!("Unicode escape '\\u{unit:04X}' at line {line_at}, column {col_at} produced an unpaired surrogate code unit. Strings in cose-tp-rego/v1 must encode well-formed UTF-16 so the canonical IR survives JSON round-trip."), line_at, col_at);
                                            return Token { kind: TokenKind::String, text: s, line: start_line, column: start_col };
                                        }
                                    }
                                } else if (0xDC00..=0xDFFF).contains(&unit) {
                                    let line_at = self.line;
                                    let col_at = self.column;
                                    self.push_err(format!("Unicode escape '\\u{unit:04X}' at line {line_at}, column {col_at} produced an unpaired surrogate code unit. Strings in cose-tp-rego/v1 must encode well-formed UTF-16 so the canonical IR survives JSON round-trip."), line_at, col_at);
                                    return Token { kind: TokenKind::String, text: s, line: start_line, column: start_col };
                                } else {
                                    if let Some(ch) = char::from_u32(unit as u32) {
                                        s.push(ch);
                                    }
                                }
                            }
                            None => {
                                let line_at = self.line;
                                let col_at = self.column;
                                self.push_err(format!("Invalid string escape '\\u' at line {line_at}, column {col_at}."), line_at, col_at);
                                return Token { kind: TokenKind::String, text: s, line: start_line, column: start_col };
                            }
                        }
                    }
                    other => {
                        let line_at = self.line;
                        let col_at = self.column;
                        self.push_err(format!("Invalid string escape '\\{other}' at line {line_at}, column {col_at}."), line_at, col_at);
                        self.advance();
                    }
                }
                continue;
            }

            if c == '\n' {
                self.push_err(format!("Unterminated string literal beginning at line {start_line}, column {start_col}."), start_line, start_col);
                return Token { kind: TokenKind::String, text: s, line: start_line, column: start_col };
            }

            // Reject unescaped control characters (U+0000 — U+001F except \t,
            // which is permitted by RFC 8259 in the same lenient mode JSON
            // strings allow). The JSON frontend's IR cannot represent
            // unescaped controls, so byte-equality with the cose-tp-json/v1
            // path requires rejecting them up-front.
            let cu = c as u32;
            if cu < 0x20 && c != '\t' {
                let line_at = self.line;
                let col_at = self.column;
                self.push_err(format!("Unescaped control character U+{cu:04X} at line {line_at}, column {col_at} is rejected; encode as '\\u{cu:04X}' if the value is intentional."), line_at, col_at);
                return Token { kind: TokenKind::String, text: s, line: start_line, column: start_col };
            }

            s.push(c);
            self.advance();
        }

        self.push_err(format!("Unterminated string literal beginning at line {start_line}, column {start_col}."), start_line, start_col);
        Token { kind: TokenKind::String, text: s, line: start_line, column: start_col }
    }

    fn try_read_unicode_escape(&mut self) -> Option<u16> {
        if self.position + 4 > self.chars.len() {
            return None;
        }
        let mut codepoint: u32 = 0;
        for _ in 0..4 {
            let c = self.chars[self.position];
            let digit = match c {
                '0'..='9' => (c as u32) - ('0' as u32),
                'a'..='f' => 10 + (c as u32) - ('a' as u32),
                'A'..='F' => 10 + (c as u32) - ('A' as u32),
                _ => return None,
            };
            codepoint = (codepoint << 4) | digit;
            self.advance();
        }
        Some(codepoint as u16)
    }

    fn read_number(&mut self, start_line: u32, start_col: u32) -> Token {
        let start = self.position;
        while self.position < self.chars.len() && self.chars[self.position].is_ascii_digit() {
            self.advance();
        }

        // Optional fractional part — only when '.' is followed by another digit.
        if self.position < self.chars.len()
            && self.chars[self.position] == '.'
            && self.position + 1 < self.chars.len()
            && self.chars[self.position + 1].is_ascii_digit()
        {
            self.advance();
            while self.position < self.chars.len() && self.chars[self.position].is_ascii_digit() {
                self.advance();
            }
        }

        // Optional exponent.
        if self.position < self.chars.len() {
            let c = self.chars[self.position];
            if c == 'e' || c == 'E' {
                self.advance();
                if self.position < self.chars.len() {
                    let sign = self.chars[self.position];
                    if sign == '+' || sign == '-' {
                        self.advance();
                    }
                }
                let exp_start = self.position;
                while self.position < self.chars.len() && self.chars[self.position].is_ascii_digit() {
                    self.advance();
                }
                if self.position == exp_start {
                    let text: String = self.chars[start..self.position].iter().collect();
                    self.push_err(format!("Invalid numeric literal '{text}' at line {start_line}, column {start_col}."), start_line, start_col);
                }
            }
        }

        let text: String = self.chars[start..self.position].iter().collect();
        Token { kind: TokenKind::Number, text, line: start_line, column: start_col }
    }

    fn advance(&mut self) {
        if self.position < self.chars.len() {
            self.position += 1;
            self.column += 1;
        }
    }

    fn push_err(&mut self, message: String, line: u32, column: u32) {
        self.errors.push(LexicalDiagnostic { message, line, column });
    }

    fn is_identifier_start(c: char) -> bool {
        c.is_ascii_alphabetic() || c == '_'
    }

    fn is_identifier_continue(c: char) -> bool {
        Self::is_identifier_start(c) || c.is_ascii_digit()
    }
}

/// Render an EOF token's user-visible text. Exposed so the parser can
/// produce identical "unexpected end-of-input" messages to the .NET
/// reference implementation.
pub(crate) const fn token_eof_text() -> &'static str {
    TOKEN_EOF_TEXT
}
