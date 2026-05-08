// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Recursive-descent parser for the cose-tp-rego/v1 constrained subset.
//!
//! Consumes the [`crate::tokenizer::Token`] stream produced by
//! [`crate::tokenizer::Tokenizer`] and emits a closed AST
//! ([`crate::ast::RegoValueNode`]) plus a list of structured diagnostics.
//! The parser does not panic on user input; every error path yields a
//! diagnostic.
//!
//! Grammar (verbatim from the README accept-list):
//!
//! ```text
//! module       := package_decl import* rule
//! package_decl := 'package' ident ('.' ident)*
//! import       := 'import' ident ('.' ident)*           (only 'future.keywords.in' allowed)
//! rule         := 'policy' (':=' | '=') term
//! term         := object_literal | array_literal | string | number | bool | null
//!               | '-' number | input_ref
//! input_ref    := 'input' '.' ident ('.' ident)*
//! object_literal := '{' (entry (',' entry)*)? ','? '}'
//! entry          := string ':' term
//! array_literal  := '[' (term (',' term)*)? ','? ']'
//! ```
//!
//! Forbidden constructs (TPX300/301/302/303/304/305) are surfaced with the
//! per-cause sub-code from [`crate::codes`] so blue-team telemetry can
//! attribute rejection rates to the offending construct class without
//! parsing the human-readable message.

use crate::ast::{RegoObjectEntry, RegoScalarKind, RegoValueNode};
use crate::codes::{
    TPX_002_MISSING_PACKAGE, TPX_003_MISSING_POLICY_RULE, TPX_004_FORBIDDEN_IMPORT,
    TPX_005_MULTIPLE_RULES, TPX_300_UNTRANSLATABLE_CONSTRUCT, TPX_301_FORBIDDEN_BUILTIN,
    TPX_302_UNCONSTRAINED_ITERATION, TPX_303_RESERVED_DATA_REFERENCE,
    TPX_304_COMPREHENSION_REJECTED, TPX_305_MAX_NESTING_DEPTH_EXCEEDED,
};
use crate::strings::*;
use crate::tokenizer::{Token, TokenKind};
use cose_sign1_trust_policy_spec::{
    SourceLocation, TrustPolicySeverity, TrustPolicyTranslationDiagnostic,
};

/// Result of a forbidden-identifier classification: the diagnostic code +
/// remediation suggestion to emit.
struct Forbidden {
    code: &'static str,
    suggestion: &'static str,
}

/// Recursive-descent parser. Produced from a [`Vec<Token>`].
pub(crate) struct Parser {
    tokens: Vec<Token>,
    diagnostics: Vec<TrustPolicyTranslationDiagnostic>,
    index: usize,
    nesting_depth: usize,
}

impl Parser {
    /// Construct a parser over the materialised token stream produced by
    /// [`crate::tokenizer::Tokenizer::tokenize`].
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            diagnostics: Vec::new(),
            index: 0,
            nesting_depth: 0,
        }
    }

    /// Drive the parser to completion. Returns the policy-rule body on
    /// success or `None` when the document is rejected; in both cases
    /// [`Self::take_diagnostics`] reflects the outcome.
    pub fn parse(&mut self) -> Option<RegoValueNode> {
        if !self.parse_package_declaration() {
            return None;
        }

        // Imports are an open zero-or-more list; each must match the
        // allow-list (`future.keywords.in`).
        while self.peek_keyword(KEYWORD_IMPORT) {
            if !self.parse_import() {
                return None;
            }
        }

        let policy = self.parse_policy_rule()?;
        if !self.expect_eof() {
            return None;
        }
        Some(policy)
    }

    /// Consume the parser, returning the accumulated diagnostics.
    pub fn take_diagnostics(self) -> Vec<TrustPolicyTranslationDiagnostic> {
        self.diagnostics
    }

    fn parse_package_declaration(&mut self) -> bool {
        let first = self.peek().clone();
        if !is_keyword(&first, KEYWORD_PACKAGE) {
            self.emit(
                TPX_002_MISSING_PACKAGE,
                format!("Document is missing the required 'package {REQUIRED_PACKAGE}' declaration."),
                first.line,
                first.column,
                None,
            );
            return false;
        }
        self.consume();

        let (package_name, line, col) = match self.try_read_dotted_ident() {
            Some(t) => t,
            None => {
                let p = self.peek().clone();
                self.emit(
                    TPX_002_MISSING_PACKAGE,
                    format!("Document is missing the required 'package {REQUIRED_PACKAGE}' declaration."),
                    p.line,
                    p.column,
                    None,
                );
                return false;
            }
        };

        if package_name != REQUIRED_PACKAGE {
            self.emit(
                TPX_002_MISSING_PACKAGE,
                format!("Document declares 'package {package_name}' but the cose-tp-rego/v1 frontend requires 'package {REQUIRED_PACKAGE}'."),
                line,
                col,
                None,
            );
            return false;
        }
        true
    }

    fn parse_import(&mut self) -> bool {
        let kw = self.consume().clone();
        let (import_name, line, col) = match self.try_read_dotted_ident() {
            Some(t) => t,
            None => {
                self.emit(
                    TPX_004_FORBIDDEN_IMPORT,
                    format!("Import '<unknown>' is not in the cose-tp-rego/v1 import allow-list. Permitted imports: '{ALLOWED_IMPORT_FUTURE_KEYWORDS_IN}'."),
                    kw.line,
                    kw.column,
                    None,
                );
                return false;
            }
        };

        if import_name != ALLOWED_IMPORT_FUTURE_KEYWORDS_IN {
            self.emit(
                TPX_004_FORBIDDEN_IMPORT,
                format!("Import '{import_name}' is not in the cose-tp-rego/v1 import allow-list. Permitted imports: '{ALLOWED_IMPORT_FUTURE_KEYWORDS_IN}'."),
                line,
                col,
                None,
            );
            return false;
        }
        true
    }

    fn parse_policy_rule(&mut self) -> Option<RegoValueNode> {
        let name = self.peek().clone();
        if name.kind != TokenKind::Identifier {
            self.emit(
                TPX_003_MISSING_POLICY_RULE,
                format!("Document is missing the required '{POLICY_RULE_NAME} := <object>' rule."),
                name.line,
                name.column,
                None,
            );
            return None;
        }

        // A top-level `some x in coll`, `every`, `default`, `not`, or
        // HTTP/regex/data builtin call is unconstrained-iteration /
        // forbidden-builtin territory; surface as the per-cause sub-code
        // rather than the bland TPX003 missing-policy-rule. Closes the
        // unconstrained-iteration / http-send fixture contracts.
        if let Some(forbidden) = is_forbidden_identifier(&name.text) {
            self.emit(
                forbidden.code,
                format!("Identifier '{}' is not in the cose-tp-rego/v1 accept-list. Allowed top-level forms: object literals, array literals, string / number / boolean / null literals, and 'input.<name>' references.", name.text),
                name.line,
                name.column,
                Some(forbidden.suggestion.to_owned()),
            );
            return None;
        }

        if name.text != POLICY_RULE_NAME {
            self.emit(
                TPX_003_MISSING_POLICY_RULE,
                format!("Document is missing the required '{POLICY_RULE_NAME} := <object>' rule."),
                name.line,
                name.column,
                None,
            );
            return None;
        }

        self.consume();

        let assign = self.peek().clone();
        if !matches!(assign.kind, TokenKind::Assign | TokenKind::Equals) {
            self.emit(
                TPX_001(),
                format!("Unexpected token '{}' at line {}, column {}; expected ':=' or '='.", render_token(&assign), assign.line, assign.column),
                assign.line,
                assign.column,
                None,
            );
            return None;
        }
        self.consume();

        let next = self.peek().clone();
        if next.kind != TokenKind::LeftBrace {
            self.emit(
                TPX_001(),
                format!("The '{POLICY_RULE_NAME}' rule must be assigned an object literal; got token '{}' at line {}, column {}.", render_token(&next), next.line, next.column),
                next.line,
                next.column,
                None,
            );
            return None;
        }

        self.parse_term()
    }

    fn expect_eof(&mut self) -> bool {
        let next = self.peek().clone();
        if next.kind == TokenKind::EndOfFile {
            return true;
        }

        if next.kind == TokenKind::Identifier {
            self.emit(
                TPX_005_MULTIPLE_RULES,
                format!("Document defines multiple rules ({}). The cose-tp-rego/v1 subset accepts exactly one '{POLICY_RULE_NAME} := ...' rule per package.", next.text),
                next.line,
                next.column,
                None,
            );
            return false;
        }

        self.emit(
            TPX_001(),
            format!("Unexpected token '{}' at line {}, column {}; expected {}.", render_token(&next), next.line, next.column, crate::tokenizer::token_eof_text()),
            next.line,
            next.column,
            None,
        );
        false
    }

    fn parse_term(&mut self) -> Option<RegoValueNode> {
        let tok = self.peek().clone();
        match tok.kind {
            TokenKind::LeftBrace => self.parse_object_or_comprehension(),
            TokenKind::LeftBracket => self.parse_array_or_comprehension(),
            TokenKind::String => {
                self.consume();
                Some(RegoValueNode::Scalar(RegoScalarKind::String, tok.text))
            }
            TokenKind::Number => {
                self.consume();
                Some(RegoValueNode::Scalar(RegoScalarKind::Number, tok.text))
            }
            TokenKind::Minus => {
                self.consume();
                let num_tok = self.peek().clone();
                if num_tok.kind != TokenKind::Number {
                    self.emit(
                        TPX_001(),
                        format!("Unexpected token '{}' at line {}, column {}; expected number.", render_token(&num_tok), num_tok.line, num_tok.column),
                        num_tok.line,
                        num_tok.column,
                        None,
                    );
                    return None;
                }
                self.consume();
                Some(RegoValueNode::Scalar(RegoScalarKind::Number, format!("-{}", num_tok.text)))
            }
            TokenKind::Identifier => self.parse_identifier_term(&tok),
            TokenKind::UnsupportedSymbol => {
                self.consume();
                self.emit(
                    TPX_304_COMPREHENSION_REJECTED,
                    format!("Construct '{}' is rejected by cose-tp-rego/v1: unconstrained iteration / quantification is forbidden by the constrained-subset contract.", tok.text),
                    tok.line,
                    tok.column,
                    None,
                );
                None
            }
            _ => {
                self.consume();
                self.emit(
                    TPX_001(),
                    format!("Unexpected token '{}' at line {}, column {}; expected term.", render_token(&tok), tok.line, tok.column),
                    tok.line,
                    tok.column,
                    None,
                );
                None
            }
        }
    }

    fn parse_identifier_term(&mut self, tok: &Token) -> Option<RegoValueNode> {
        match tok.text.as_str() {
            KEYWORD_TRUE => {
                self.consume();
                Some(RegoValueNode::Scalar(RegoScalarKind::True, KEYWORD_TRUE.to_owned()))
            }
            KEYWORD_FALSE => {
                self.consume();
                Some(RegoValueNode::Scalar(RegoScalarKind::False, KEYWORD_FALSE.to_owned()))
            }
            KEYWORD_NULL => {
                self.consume();
                Some(RegoValueNode::Scalar(RegoScalarKind::Null, KEYWORD_NULL.to_owned()))
            }
            KEYWORD_INPUT => self.parse_input_reference(tok),
            _ => {
                if let Some(forbidden) = is_forbidden_identifier(&tok.text) {
                    self.consume();
                    // If the next token is '.', also consume the qualifier
                    // so the diagnostic message can name the actual builtin
                    // (e.g. http.send not just http).
                    let mut qualifier = String::new();
                    if self.peek().kind == TokenKind::Dot {
                        self.consume();
                        if self.peek().kind == TokenKind::Identifier {
                            qualifier = self.consume().text.clone();
                        }
                    }
                    let message = if !qualifier.is_empty() {
                        format!("Built-in '{}.{qualifier}' is not permitted in cose-tp-rego/v1; the frontend rejects HTTP / regex / filesystem / network / cryptography / time / OPA / OS / IO / 'data' references to keep policies side-effect-free.", tok.text)
                    } else {
                        format!("Identifier '{}' is not in the cose-tp-rego/v1 accept-list. Allowed top-level forms: object literals, array literals, string / number / boolean / null literals, and 'input.<name>' references.", tok.text)
                    };
                    self.emit(forbidden.code, message, tok.line, tok.column, Some(forbidden.suggestion.to_owned()));
                    return None;
                }
                self.consume();
                self.emit(
                    TPX_300_UNTRANSLATABLE_CONSTRUCT,
                    format!("Identifier '{}' is not in the cose-tp-rego/v1 accept-list. Allowed top-level forms: object literals, array literals, string / number / boolean / null literals, and 'input.<name>' references.", tok.text),
                    tok.line,
                    tok.column,
                    None,
                );
                None
            }
        }
    }

    fn parse_input_reference(&mut self, input_tok: &Token) -> Option<RegoValueNode> {
        self.consume(); // consume 'input'
        if self.peek().kind != TokenKind::Dot {
            self.emit(
                TPX_001(),
                "'input' must be followed by '.<name>' to reference a parameter.".to_owned(),
                input_tok.line,
                input_tok.column,
                None,
            );
            return None;
        }
        self.consume(); // consume '.'

        let name_tok = self.peek().clone();
        if name_tok.kind != TokenKind::Identifier {
            self.emit(
                TPX_001(),
                "'input' must be followed by '.<name>' to reference a parameter.".to_owned(),
                name_tok.line,
                name_tok.column,
                None,
            );
            return None;
        }
        self.consume();

        let mut parts: Vec<String> = vec![name_tok.text];
        while self.peek().kind == TokenKind::Dot {
            self.consume();
            let seg = self.peek().clone();
            if seg.kind != TokenKind::Identifier {
                self.emit(
                    TPX_001(),
                    "'input' must be followed by '.<name>' to reference a parameter.".to_owned(),
                    seg.line,
                    seg.column,
                    None,
                );
                return None;
            }
            self.consume();
            parts.push(seg.text);
        }

        Some(RegoValueNode::InputRef(parts.join(".")))
    }

    fn parse_object_or_comprehension(&mut self) -> Option<RegoValueNode> {
        let open = self.consume().clone(); // consume '{'
        self.nesting_depth += 1;
        if self.nesting_depth > MAX_NESTING_DEPTH {
            self.emit(
                TPX_305_MAX_NESTING_DEPTH_EXCEEDED,
                format!("Nesting depth at line {}, column {} exceeded the cose-tp-rego/v1 maximum of {MAX_NESTING_DEPTH}; reject as a defense-in-depth measure against stack-exhaustion DoS.", open.line, open.column),
                open.line,
                open.column,
                Some(SUGGESTION_FLATTEN_NESTING.to_owned()),
            );
            return None;
        }

        let mut entries: Vec<RegoObjectEntry> = Vec::new();
        let mut seen_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        if self.peek().kind == TokenKind::RightBrace {
            self.consume();
            self.nesting_depth -= 1;
            return Some(RegoValueNode::Object(entries));
        }

        loop {
            let key_tok = self.peek().clone();
            if key_tok.kind != TokenKind::String {
                // A comprehension `{ x | y }` lands here with x as an
                // Identifier and a following `|` UnsupportedSymbol. Peek
                // ahead so we can surface the more accurate TPX304 rather
                // than the bland 'expected string key'.
                if key_tok.kind == TokenKind::Identifier && self.peek_after_identifier_is_pipe() {
                    self.emit(
                        TPX_304_COMPREHENSION_REJECTED,
                        "Comprehension expressions ('|') are rejected by cose-tp-rego/v1; the constrained subset only accepts literal arrays / objects.".to_owned(),
                        key_tok.line,
                        key_tok.column,
                        None,
                    );
                    return None;
                }
                self.emit(
                    TPX_001(),
                    format!("Unexpected token '{}' at line {}, column {}; expected string key.", render_token(&key_tok), key_tok.line, key_tok.column),
                    key_tok.line,
                    key_tok.column,
                    None,
                );
                return None;
            }
            self.consume();

            if self.peek().kind != TokenKind::Colon {
                let bad = self.peek().clone();
                self.emit(
                    TPX_001(),
                    format!("Unexpected token '{}' at line {}, column {}; expected ':'.", render_token(&bad), bad.line, bad.column),
                    bad.line,
                    bad.column,
                    None,
                );
                return None;
            }
            self.consume();

            let value = self.parse_term()?;

            if !seen_keys.insert(key_tok.text.clone()) {
                self.emit(
                    TPX_001(),
                    format!("Duplicate object key '{}' at line {}, column {}.", key_tok.text, key_tok.line, key_tok.column),
                    key_tok.line,
                    key_tok.column,
                    None,
                );
                return None;
            }
            entries.push(RegoObjectEntry { key: key_tok.text, value });

            let sep = self.peek().clone();
            if sep.kind == TokenKind::Comma {
                self.consume();
                if self.peek().kind == TokenKind::RightBrace {
                    self.consume();
                    self.nesting_depth -= 1;
                    return Some(RegoValueNode::Object(entries));
                }
                continue;
            }
            if sep.kind == TokenKind::RightBrace {
                self.consume();
                self.nesting_depth -= 1;
                return Some(RegoValueNode::Object(entries));
            }
            // A `|` would indicate a comprehension; the unsupported-symbol
            // token would surface here. Either way it's TPX304.
            self.emit(
                TPX_304_COMPREHENSION_REJECTED,
                "Comprehension expressions ('|') are rejected by cose-tp-rego/v1; the constrained subset only accepts literal arrays / objects.".to_owned(),
                sep.line,
                sep.column,
                None,
            );
            return None;
        }
    }

    fn peek_after_identifier_is_pipe(&self) -> bool {
        if self.index + 1 >= self.tokens.len() {
            return false;
        }
        let next = &self.tokens[self.index + 1];
        next.kind == TokenKind::UnsupportedSymbol && next.text == PIPE_CHAR
    }

    fn parse_array_or_comprehension(&mut self) -> Option<RegoValueNode> {
        let open = self.consume().clone();
        self.nesting_depth += 1;
        if self.nesting_depth > MAX_NESTING_DEPTH {
            self.emit(
                TPX_305_MAX_NESTING_DEPTH_EXCEEDED,
                format!("Nesting depth at line {}, column {} exceeded the cose-tp-rego/v1 maximum of {MAX_NESTING_DEPTH}; reject as a defense-in-depth measure against stack-exhaustion DoS.", open.line, open.column),
                open.line,
                open.column,
                Some(SUGGESTION_FLATTEN_NESTING.to_owned()),
            );
            return None;
        }

        let mut items: Vec<RegoValueNode> = Vec::new();

        if self.peek().kind == TokenKind::RightBracket {
            self.consume();
            self.nesting_depth -= 1;
            return Some(RegoValueNode::Array(items));
        }

        loop {
            let item = self.parse_term()?;
            items.push(item);

            let sep = self.peek().clone();
            if sep.kind == TokenKind::Comma {
                self.consume();
                if self.peek().kind == TokenKind::RightBracket {
                    self.consume();
                    self.nesting_depth -= 1;
                    return Some(RegoValueNode::Array(items));
                }
                continue;
            }
            if sep.kind == TokenKind::RightBracket {
                self.consume();
                self.nesting_depth -= 1;
                return Some(RegoValueNode::Array(items));
            }
            self.emit(
                TPX_304_COMPREHENSION_REJECTED,
                "Comprehension expressions ('|') are rejected by cose-tp-rego/v1; the constrained subset only accepts literal arrays / objects.".to_owned(),
                sep.line,
                sep.column,
                None,
            );
            return None;
        }
    }

    fn try_read_dotted_ident(&mut self) -> Option<(String, u32, u32)> {
        let first = self.peek().clone();
        if first.kind != TokenKind::Identifier {
            return None;
        }
        self.consume();
        let mut parts: Vec<String> = vec![first.text];
        while self.peek().kind == TokenKind::Dot {
            self.consume();
            let seg = self.peek().clone();
            if seg.kind != TokenKind::Identifier {
                return Some((parts.join("."), first.line, first.column));
            }
            self.consume();
            parts.push(seg.text);
        }
        Some((parts.join("."), first.line, first.column))
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.index]
    }

    fn consume(&mut self) -> &Token {
        let i = self.index;
        if self.index < self.tokens.len() - 1 {
            self.index += 1;
        }
        &self.tokens[i]
    }

    fn peek_keyword(&self, keyword: &str) -> bool {
        let t = self.peek();
        t.kind == TokenKind::Identifier && t.text == keyword
    }

    fn emit(&mut self, code: &str, message: String, line: u32, column: u32, suggestion: Option<String>) {
        let mut diag = TrustPolicyTranslationDiagnostic::new(
            TrustPolicySeverity::Error,
            code,
            message,
            Some(self.make_location(line, column)),
            None,
        );
        if let Some(s) = suggestion {
            diag = diag.with_suggestion(s);
        }
        self.diagnostics.push(diag);
    }

    fn make_location(&self, line: u32, column: u32) -> SourceLocation {
        SourceLocation::at(line, column)
    }
}

fn is_keyword(t: &Token, keyword: &str) -> bool {
    t.kind == TokenKind::Identifier && t.text == keyword
}

fn is_forbidden_identifier(text: &str) -> Option<Forbidden> {
    match text {
        FORBIDDEN_NAMESPACE_HTTP
        | FORBIDDEN_NAMESPACE_REGEX
        | FORBIDDEN_NAMESPACE_FILE
        | FORBIDDEN_NAMESPACE_IO
        | FORBIDDEN_NAMESPACE_OS
        | FORBIDDEN_NAMESPACE_CRYPTO
        | FORBIDDEN_NAMESPACE_NET
        | FORBIDDEN_NAMESPACE_TIME
        | FORBIDDEN_NAMESPACE_OPA => Some(Forbidden {
            code: TPX_301_FORBIDDEN_BUILTIN,
            suggestion: SUGGESTION_REMOVE_SIDE_EFFECTING_BUILTIN,
        }),
        FORBIDDEN_IDENT_DATA => Some(Forbidden {
            code: TPX_303_RESERVED_DATA_REFERENCE,
            suggestion: SUGGESTION_USE_INPUT,
        }),
        FORBIDDEN_IDENT_SOME
        | FORBIDDEN_IDENT_EVERY
        | FORBIDDEN_IDENT_WITH
        | FORBIDDEN_IDENT_DEFAULT
        | FORBIDDEN_IDENT_NOT
        | FORBIDDEN_IDENT_EVAL => Some(Forbidden {
            code: TPX_302_UNCONSTRAINED_ITERATION,
            suggestion: SUGGESTION_USE_PROPERTY,
        }),
        _ => None,
    }
}

fn render_token(t: &Token) -> String {
    match t.kind {
        TokenKind::EndOfFile => crate::tokenizer::token_eof_text().to_owned(),
        _ => t.text.clone(),
    }
}

#[allow(non_snake_case)]
fn TPX_001() -> &'static str {
    crate::codes::TPX_001_MALFORMED_REGO
}
