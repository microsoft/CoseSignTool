// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego;

using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Centralised string-literal pool for the cose-tp-rego/v1 frontend. Every user-visible
/// literal lives here so contract-text changes happen in one place and the repo's
/// StringLiteralAnalyzer can flag drift.
/// </summary>
[ExcludeFromCodeCoverage]
internal static class AssemblyStrings
{
    // Frontend identity
    public const string FrontendId = "cose-tp-rego/v1";
    public const string MediaTypeRego = "application/x-cose-trust-policy+rego";
    public const string FileExtension = ".coseTrustPolicy.rego";

    // Rego subset — required boilerplate
    public const string RequiredPackage = "cose_trust_policy";
    public const string PolicyRuleName = "policy";
    public const string KeywordPackage = "package";
    public const string KeywordImport = "import";
    public const string KeywordTrue = "true";
    public const string KeywordFalse = "false";
    public const string KeywordNull = "null";
    public const string KeywordInput = "input";
    public const string AllowedImportFutureKeywordsIn = "future.keywords.in";

    // Forbidden tokens — the closed reject-list. Every entry surfaces a TPX300 with a
    // specific suggestion.
    public const string ForbiddenIdentSome = "some";
    public const string ForbiddenIdentEvery = "every";
    public const string ForbiddenIdentWith = "with";
    public const string ForbiddenIdentDefault = "default";
    public const string ForbiddenIdentNot = "not";
    public const string ForbiddenIdentData = "data";
    public const string ForbiddenIdentEval = "eval";
    public const string ForbiddenNamespaceHttp = "http";
    public const string ForbiddenNamespaceRegex = "regex";
    public const string ForbiddenNamespaceFile = "file";
    public const string ForbiddenNamespaceIo = "io";
    public const string ForbiddenNamespaceOs = "os";
    public const string ForbiddenNamespaceCrypto = "crypto";
    public const string ForbiddenNamespaceNet = "net";
    public const string ForbiddenNamespaceTime = "time";
    public const string ForbiddenNamespaceOpa = "opa";

    // Diagnostic codes (extend the TPX namespace; consistent with cose-tp-json/v1 wherever
    // the same condition is reported).
    public const string CodeMalformedRego = "TPX001";          // parse / syntax error
    public const string CodeMissingPackage = "TPX002";         // missing or wrong `package` declaration
    public const string CodeMissingPolicyRule = "TPX003";      // no `policy := ...` rule
    public const string CodeForbiddenImport = "TPX004";        // unsupported `import`
    public const string CodeMultipleRules = "TPX005";          // more than one rule per package
    public const string CodeUntranslatableConstruct = "TPX300"; // constrained-subset reject
    public const string CodeForbiddenBuiltin = "TPX300";        // shares the translation-error band
    public const string CodeUnconstrainedIteration = "TPX300";
    public const string CodeReservedDataReference = "TPX300";

    // Diagnostic message formats
    public const string ErrParseFormat = "Malformed Rego document at line {0}, column {1}: {2}";
    public const string ErrUnexpectedTokenFormat = "Unexpected token '{0}' at line {1}, column {2}; expected {3}.";
    public const string ErrUnexpectedEndOfFile = "Unexpected end of input at line {0}, column {1}; expected {2}.";
    public const string ErrUnterminatedString = "Unterminated string literal beginning at line {0}, column {1}.";
    public const string ErrInvalidNumberFormat = "Invalid numeric literal '{0}' at line {1}, column {2}.";
    public const string ErrInvalidEscapeFormat = "Invalid string escape '\\{0}' at line {1}, column {2}.";
    public const string ErrPackageMissing = "Document is missing the required 'package {0}' declaration.";
    public const string ErrPackageMismatchFormat = "Document declares 'package {0}' but the cose-tp-rego/v1 frontend requires 'package {1}'.";
    public const string ErrPolicyRuleMissingFormat = "Document is missing the required '{0} := <object>' rule.";
    public const string ErrMultipleRulesFormat = "Document defines multiple rules ({0}). The cose-tp-rego/v1 subset accepts exactly one '{1} := ...' rule per package.";
    public const string ErrForbiddenImportFormat = "Import '{0}' is not in the cose-tp-rego/v1 import allow-list. Permitted imports: '{1}'.";
    public const string ErrForbiddenBuiltinFormat = "Built-in '{0}.{1}' is not permitted in cose-tp-rego/v1; the frontend rejects HTTP / regex / filesystem / network / cryptography / time / OPA / OS / IO / 'data' references to keep policies side-effect-free.";
    public const string ErrForbiddenIdentifierFormat = "Identifier '{0}' is not in the cose-tp-rego/v1 accept-list. Allowed top-level forms: object literals, array literals, string / number / boolean / null literals, and 'input.<name>' references.";
    public const string ErrUnconstrainedIterationFormat = "Construct '{0}' is rejected by cose-tp-rego/v1: unconstrained iteration / quantification is forbidden by the constrained-subset contract.";
    public const string ErrComprehensionRejected = "Comprehension expressions ('|') are rejected by cose-tp-rego/v1; the constrained subset only accepts literal arrays / objects.";
    public const string ErrDataReferenceRejected = "References to 'data.<...>' are rejected by cose-tp-rego/v1; the constrained subset only accepts 'input.<...>' parameter references.";
    public const string ErrPolicyValueNotObjectFormat = "The '{0}' rule must be assigned an object literal; got token '{1}' at line {2}, column {3}.";
    public const string ErrInputDotMissingIdentifier = "'input' must be followed by '.<name>' to reference a parameter.";
    public const string ErrDuplicateObjectKeyFormat = "Duplicate object key '{0}' at line {1}, column {2}.";

    // Property names produced by the Rego→JSON lowerer (must match the JSON frontend's
    // canonical schema vocabulary so byte-equality holds with cose-tp-json/v1 fixtures).
    public const string PropertyParam = "$param";
    public const string PropertyParamDefault = "default";

    // Source-pointer rendering
    public const string LocationFormat = "{0}:{1}";
    public const string LineColFormat = "line {0}, column {1}";

    // Parse-position formatting (used by parser fail tests + diagnostics).
    public const string TokenEofText = "<end-of-input>";

    // Coverage justifications
    public const string JustifyDefensiveAllowedByGrammar = "Defensive arm; the closed grammar of the cose-tp-rego/v1 parser keeps this branch unreachable in the public flow.";
    public const string JustifyDefensiveSchemaBackedByJson = "Defensive arm; lowering produces a JsonObject that is shape-validated by the JSON frontend's schema, so this code path is exercised by the JSON frontend's own tests.";

    // Argument names embedded in ArgumentNullException messages.
    public const string ArgDocumentText = "documentText";
    public const string ArgDocument = "document";
    public const string ArgCtx = "ctx";

    // ---- Joining + format helpers ----
    public const string Comma = ",";
    public const string CommaSpace = ", ";
    public const string DotChar = ".";

    // Punctuation literals (the StringLiteralAnalyzer rejects unsourced literals even for
    // single-character operator tokens — mirrors the JSON frontend's pattern).
    public const string TokenLeftBrace = "{";
    public const string TokenRightBrace = "}";
    public const string TokenLeftBracket = "[";
    public const string TokenRightBracket = "]";
    public const string TokenLeftParen = "(";
    public const string TokenRightParen = ")";
    public const string TokenComma = ",";
    public const string TokenDot = ".";
    public const string TokenMinus = "-";
    public const string TokenColon = ":";
    public const string TokenAssign = ":=";
    public const string TokenEquals = "=";
    public const string EscapeUnicodePrefix = "u";

    // Parser-expected-token tags emitted into ErrUnexpectedTokenFormat.
    public const string ExpectedAssignOrEquals = "':=' or '='";
    public const string ExpectedTokenNumber = "number";
    public const string ExpectedTokenTerm = "term";
    public const string ExpectedTokenStringKey = "string key";
    public const string ExpectedTokenColon = "':'";
    public const string ImportNameUnknown = "<unknown>";

    // Suggestion prefix for diagnostics that ship a remediation hint.
    public const string SuggestionUseInput = "Replace 'data.<name>' with 'input.<name>' so the value is supplied via the host's parameter binder (D5).";
    public const string SuggestionRemoveImport = "Remove the import or use 'import future.keywords.in' (the only currently-allowed import).";
    public const string SuggestionUseLiteralArray = "Express the value as a literal array (e.g. [\"a\", \"b\"]) or as an 'input.<name>' parameter reference.";
    public const string SuggestionUseProperty = "Use the JSON property-shorthand or path/operator predicate forms (see cose-tp-json/v1 §6.5.5).";
}
