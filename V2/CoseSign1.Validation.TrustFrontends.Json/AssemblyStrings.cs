// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json;

using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Centralised string-literal pool for the cose-tp-json/v1 frontend. Every user-visible literal
/// lives here so contract-text changes happen in one place and the StringLiteralAnalyzer can
/// flag drift.
/// </summary>
[ExcludeFromCodeCoverage]
internal static class AssemblyStrings
{
    // Frontend identity
    public const string FrontendId = "cose-tp-json/v1";
    public const string MediaTypeJson = "application/x-cose-trust-policy+json";
    public const string MediaTypeJsonc = "application/x-cose-trust-policy+json5";
    public const string FileExtension = ".coseTrustPolicy.json";
    public const string SchemaResourceName = "CoseSign1.Validation.TrustFrontends.Json.Schema.cose-tp.v1.json";

    // Canonical schema URL — D7 pin-to-main policy.
    public const string SchemaUrl = "https://raw.githubusercontent.com/microsoft/CoseSignTool/main/V2/schemas/cose-tp/v1.json";

    // Document discriminator + property keys
    public const string PropertyFrontend = "frontend";
    public const string PropertySchema = "$schema";
    public const string PropertyCombinator = "combinator";
    public const string PropertyMessage = "message";
    public const string PropertyPrimarySigningKey = "primary_signing_key";
    public const string PropertyAnyCounterSignature = "any_counter_signature";
    public const string PropertyOnEmpty = "on_empty";
    public const string PropertyAllOf = "all_of";
    public const string PropertyAnyOf = "any_of";
    public const string PropertyNot = "not";
    public const string PropertyImplies = "implies";
    public const string PropertyAntecedent = "antecedent";
    public const string PropertyConsequent = "consequent";
    public const string PropertyAllowAll = "allow_all";
    public const string PropertyDenyAll = "deny_all";
    public const string PropertyFact = "fact";
    public const string PropertyPredicate = "predicate";
    public const string PropertyFailureMessage = "failure_message";
    public const string PropertyOperator = "operator";
    public const string PropertyPath = "path";
    public const string PropertyValue = "value";
    public const string PropertyReason = "reason";
    public const string PropertyParam = "$param";
    public const string PropertyParamDefault = "default";

    public const string CombinatorAnd = "and";
    public const string CombinatorOr = "or";
    public const string OnEmptyAllow = "allow";
    public const string OnEmptyDeny = "deny";

    // Diagnostic codes (extends the TPX namespace; in addition to TPX200/TPX400 already declared
    // in the Spec project's TrustPolicyDiagnosticCodes).
    public const string CodeMalformedJson = "TPX001";
    public const string CodeSchemaValidation = "TPX100";
    public const string CodeFrontendMismatch = "TPX101";
    public const string CodePredicateSchemaMismatch = "TPX201";
    public const string CodeUnknownOperator = "TPX300";
    public const string CodeUntranslatableNode = "TPX301";
    public const string CodeReservedKeyMisuse = "TPX302";
    public const string CodeTypeMismatchAfterBind = "TPX401";

    // Default failure messages (when the document omits failure_message)
    public const string DefaultFailureMessageFormat = "Fact requirement on '{0}' was not satisfied.";

    // Diagnostic message formats
    public const string ErrMalformedJsonFormat = "Malformed JSON document: {0}";
    public const string ErrFrontendMismatchFormat = "Document declares frontend '{0}' but this translator handles '{1}'.";
    public const string ErrUnknownFactIdFormat = "Document references unknown fact id '{0}'. Available fact ids: {1}.";
    public const string ErrUnknownOperatorFormat = "Operator '{0}' is not recognised. Allowed operators: {1}.";
    public const string ErrSchemaValidationFormat = "Schema validation failed at '{0}': {1}";
    public const string ErrPredicateSchemaMismatchFormat = "Predicate for fact '{0}' does not match the fact's published predicate schema at '{1}': {2}";
    public const string ErrEmptyFailureMessageFormat = "Fact requirement on '{0}' has empty failure_message.";
    public const string ErrTypeMismatchAfterBindFormat = "Parameter binding produced a structurally invalid spec: {0}";
    public const string ErrReservedKeyFormat = "Property name '{0}' is reserved and may not be used as a fact-property assertion key.";
    public const string ErrCacheCapacityFormat = "Cache capacity must be greater than zero, was {0}.";
    public const string ErrUnsupportedDocumentNullSpec = "Document parsed to a null JSON value; the root must be an object.";
    public const string ErrUntranslatableNodeFormat = "Document node at '{0}' could not be translated; expected one of: fact, all_of, any_of, not, implies, allow_all, deny_all.";

    // Source-pointer strings
    public const string SourcePointerRoot = "$";
    public const string SourcePointerSep = ".";
    public const string ParamRoot = "$param";

    // Argument-validation
    public const string ErrArgumentDocumentTextNull = "documentText must not be null.";
    public const string ErrArgumentTranslatorNull = "translator must not be null.";

    // Joining
    public const string CommaSpace = ", ";

    // Composite formatting strings (kept here so consuming code never embeds inline literals).
    public const string KeySegmentSeparator = ":";
    public const string PointerArrayIndexFormat = "{0}[{1}]";
    public const string LocationWithSourceFormat = "{0}#{1}";
    public const string CapsAllowUnknownPrefix = "u:";
    public const string CapsKnownPrefix = "k:";
    public const string CapsEntrySeparator = ";";
    public const string CapsKeyValueSeparator = "=";
    public const string EmptyParamObject = "{}";
    public const string NullValueLiteral = "null";

    // Coverage justification
    public const string JustifyDefensive = "Defensive arm; the closed grammar from the JSON Schema validator + the closed TrustPolicySpec discriminated union make this branch unreachable in the public flow.";
}
