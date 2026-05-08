// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec;

using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Shared string-literal pool. Every user-visible string literal in this assembly is declared
/// here so the repo's <c>StringLiteralAnalyzer</c> can tell at a glance which strings are part
/// of the contract — and so localisation / format-string changes can be made in one place.
/// </summary>
[ExcludeFromCodeCoverage]
internal static class ClassStrings
{
    // ---------------- JSON discriminator + property names (canonical wire schema) ----------------

    public const string DiscriminatorPropertyName = "type";
    public const string PredicateDiscriminatorPropertyName = "predicate_type";

    public const string DiscriminatorMessage = "message";
    public const string DiscriminatorPrimarySigningKey = "primary_signing_key";
    public const string DiscriminatorAnyCounterSignature = "any_counter_signature";
    public const string DiscriminatorRequireFact = "require_fact";
    public const string DiscriminatorAnd = "and";
    public const string DiscriminatorOr = "or";
    public const string DiscriminatorNot = "not";
    public const string DiscriminatorImplies = "implies";
    public const string DiscriminatorAllowAll = "allow_all";
    public const string DiscriminatorDenyAll = "deny_all";

    public const string DiscriminatorPathOperator = "path_operator";
    public const string DiscriminatorPropertyAssertion = "property_assertion";

    public const string PropertyLocation = "location";
    public const string PropertyInner = "inner";
    public const string PropertyFact = "fact";
    public const string PropertyPredicate = "predicate";
    public const string PropertyFailureMessage = "failure_message";
    public const string PropertyOperands = "operands";
    public const string PropertyOperand = "operand";
    public const string PropertyAntecedent = "antecedent";
    public const string PropertyConsequent = "consequent";
    public const string PropertyOnEmpty = "on_empty";
    public const string PropertyReason = "reason";
    public const string PropertyPath = "path";
    public const string PropertyOperator = "operator";
    public const string PropertyValue = "value";
    public const string PropertyAssertions = "assertions";
    public const string PropertySource = "source";
    public const string PropertyLine = "line";
    public const string PropertyColumn = "column";
    public const string PropertyLength = "length";

    // ---------------- Parameter-ref reserved keys (D5) ----------------

    public const string ParameterMarker = "$param";
    public const string ParameterDefaultProperty = "default";

    // ---------------- Diagnostic codes (D6 — TrustPolicyDiagnosticCodes consumes these) ----------------

    public const string CodePrefix = "TPX";
    public const string CodeUnknownFactId = "TPX200";
    public const string CodeUnknownFactProperty = "TPX201";
    public const string CodeUnsupportedPredicateOperator = "TPX202";
    public const string CodeUnsupportedPredicatePath = "TPX203";
    public const string CodeFactScopeMismatch = "TPX204";
    public const string CodeUnboundParameter = "TPX400";
    public const string CodeFactRegistryDuplicate = "TPX300";

    // ---------------- Argument-validation messages ----------------

    public const string ErrAndOperandsNull = "AndSpec operands must not contain null entries.";
    public const string ErrOrOperandsNull = "OrSpec operands must not contain null entries.";
    public const string ErrFactIdNullOrWhitespace = "Fact id must not be null or whitespace.";
    public const string ErrFactClrTypeNull = "Fact CLR type must not be null.";
    public const string ErrTrustFactIdDuplicateFormat = "[TPX300] Duplicate [TrustFactId] '{0}' on types '{1}' and '{2}'. Fact ids must be unique across all assemblies scanned by AttributeDrivenFactRegistry.";
    public const string ErrAttributeDrivenScanAssembliesNull = "Assembly enumeration must not contain null entries.";
    public const string AttributeDrivenAssemblyPrefix = "CoseSign1.";
    public const string ObsoleteStaticFactRegistry = "Use AttributeDrivenFactRegistry.FromLoadedAssemblies(). Will be removed in Phase 4 if no consumers remain.";
    public const string JustifySafeGetTypesCatch = "ReflectionTypeLoadException requires a partially-loadable assembly which cannot be synthesised in a normal NUnit run; the recovery arm is exercised by integration when a host loads a malformed plugin.";
    public const string ErrDuplicateFactIdFormat = "Duplicate fact id '{0}'.";
    public const string ErrDuplicateFactClrTypeFormat = "Fact CLR type '{0}' is already registered as '{1}'.";
    public const string ErrCanonicalJsonNullSpec = "Trust-policy spec JSON deserialized to null.";
    public const string ErrPredicateAssertionsStartObject = "Expected start of object for predicate assertions map.";
    public const string ErrPredicateAssertionsPropertyName = "Expected property name in predicate assertions map.";
    public const string ErrPredicateAssertionsEof = "Unexpected end of input while reading predicate assertions map.";
    public const string ErrCanonicalJsonReparseNull = "Canonical JSON unexpectedly parsed to null.";
    public const string ErrParameterBindNullSpec = "ParameterRef.Bind returned null for a non-null spec.";

    // ---------------- Compilation diagnostics (format strings) ----------------

    public const string ErrUnboundParameterFormat = "Parameter '{0}' is referenced by the trust-policy spec but no binding was supplied and no default is declared.";
    public const string ErrUnknownPredicateNodeFormat = "Unrecognised predicate spec type '{0}'.";
    public const string ErrUnknownSpecNodeFormat = "Unrecognised TrustPolicySpec node type '{0}'.";
    public const string ErrPathPredicateBoundFormat = "Predicate value for fact '{0}' contains an unbound ParameterRef. Bind parameters before compiling.";
    public const string ErrPathPredicateNonNullValueFormat = "Operator '{0}' on fact '{1}' requires a non-null predicate value.";
    public const string ErrPropertyAssertionWhitespaceFormat = "Property-assertion predicate for fact '{0}' contains a null/whitespace property name.";
    public const string ErrPropertyAssertionUnboundFormat = "Property-assertion predicate for fact '{0}' has an unbound ParameterRef on key '{1}'.";
    public const string ErrPathEmptyFormat = "Predicate path on fact '{0}' is empty.";
    public const string ErrPathNoRootFormat = "Predicate path '{0}' on fact '{1}' must start with '$' (the fact root).";
    public const string ErrPathEmptyAccessorFormat = "Predicate path '{0}' on fact '{1}' has an empty property accessor.";
    public const string ErrPathUnterminatedIndexFormat = "Predicate path '{0}' on fact '{1}' has an unterminated index accessor.";
    public const string ErrPathBadIndexFormat = "Predicate path '{0}' on fact '{1}' contains an invalid array index '{2}'.";
    public const string ErrPathUnsupportedCharFormat = "Predicate path '{0}' on fact '{1}' contains the unsupported character '{2}'. Only '$', '.<property>', and '[<index>]' are allowed.";
    public const string ErrUnknownFactIdFormat = "Unknown fact id '{0}'. Available ids: {1}.";
    public const string ErrFactPropertyMissingFormat = "Predicate references property '{0}' which does not exist on fact '{1}' (CLR type '{2}'). Available: {3}.";
    public const string ErrUnknownNodeInScopeFormat = "Unrecognised spec node '{0}' inside scoped context.";
    public const string ErrFactScopeMismatchFormat = "Fact '{0}' (CLR type '{1}') does not match the requirement scope '{2}'.";

    public const string ErrRequireFactOutsideScope = "RequireFactSpec must be wrapped in a *RequirementSpec — fact requirements have no meaning outside a subject scope.";
    public const string ErrRequirementInScope = "Requirement specs (Message / PrimarySigningKey / AnyCounterSignature) cannot be nested inside another requirement scope. Compose at the top level via And / Or / Not / Implies of separate requirement specs.";

    // ---------------- Default denial reasons ----------------

    public const string ReasonNoTrustSourcesSatisfied = "No trust sources were satisfied";

    // ---------------- README / package metadata ----------------

    public const string PackageDescription = "Serializable IR (TrustPolicySpec) for CoseSign1 trust policies.";

    // ---------------- Phase 1 fact-id catalog (StaticFactRegistry) ----------------
    //
    // Every concrete fact CLR type currently shipped in V2 has an entry here. Phase 3 replaces
    // this table with an attribute-driven registry; until then, new facts MUST be added here so
    // the spec compiler can resolve them.

    public const string FactContentType = "content-type/v1";
    public const string FactCounterSignatureSubject = "counter-signature-subject/v1";
    public const string FactDetachedPayloadPresent = "detached-payload-present/v1";
    public const string FactUnknownCounterSignatureBytes = "unknown-counter-signature-bytes/v1";
    public const string FactCertificateSigningKeyTrust = "certificate-signing-key-trust/v1";
    public const string FactX509ChainElementIdentity = "x509-chain-element-identity/v1";
    public const string FactX509ChainTrusted = "x509-chain-trusted/v1";
    public const string FactX509CertBasicConstraints = "x509-cert-basic-constraints/v1";
    public const string FactX509CertEku = "x509-cert-eku/v1";
    public const string FactX509CertIdentityAllowed = "x509-cert-identity-allowed/v1";
    public const string FactX509CertIdentity = "x509-cert-identity/v1";
    public const string FactX509CertKeyUsage = "x509-cert-key-usage/v1";
    public const string FactX509X5ChainCertIdentity = "x509-x5chain-cert-identity/v1";
    public const string FactMstReceiptIssuerHost = "mst-receipt-issuer-host/v1";
    public const string FactMstReceiptPresent = "mst-receipt-present/v1";
    public const string FactMstReceiptTrusted = "mst-receipt-trusted/v1";

    // ---------------- Misc ----------------

    public const string JoinSeparator = ", ";

    public const string ErrCanonicalDepthExceeded = "Canonical JSON serialization exceeded the configured maximum depth. The spec is too deeply nested or has a recursive cycle.";
    public const string ErrBindingDepthExceeded = "Parameter binding exceeded the configured maximum depth. The spec is too deeply nested or has a recursive cycle.";

    // ---------------- Coverage-suppression justifications ----------------

    public const string JustifyDefensiveSpec = "Defensive arm for future TrustPolicySpec / FactPredicateSpec subtypes; the closed discriminated union makes it unreachable today.";
    public const string JustifyDefensiveOperator = "Defensive — switch covers every PredicateOperator enum value explicitly.";
    public const string JustifyDefensiveScope = "Defensive — closed discriminated union covers every TrustPolicySpec subtype reachable in scoped context.";
    public const string JustifyDefensivePropertyKey = "Defensive — TrustPolicySpecCompiler.ValidatePropertyAccess catches whitespace keys before reaching PredicateLowerer.Compile in the public flow.";
}
