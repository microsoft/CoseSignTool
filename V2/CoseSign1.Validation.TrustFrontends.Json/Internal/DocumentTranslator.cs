// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json.Internal;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;
using CoseSign1.Validation.Trust.Rules;

/// <summary>
/// Walks a schema-validated <see cref="JsonNode"/> document and produces a
/// <see cref="TrustPolicySpec"/> tree.
/// </summary>
/// <remarks>
/// <para>
/// The walk runs after JSON-Schema validation has already proved structural conformance, so
/// most "unexpected shape" branches are defensive. Capability gating (D4) is evaluated here:
/// fact references are checked against <see cref="FactCapabilities.AvailableFactIds"/> and,
/// when published, predicate JSON Schemas are evaluated.
/// </para>
/// <para>
/// Every diagnostic carries a JSON-pointer instance location in <see cref="SourceLocation.Source"/>
/// so authors / IDE tooling can navigate back to the offending node.
/// </para>
/// </remarks>
internal sealed class DocumentTranslator
{
    private readonly TrustPolicyTranslationContext Context;
    private readonly string? DocumentSource;
    private readonly List<TrustPolicyTranslationDiagnostic> Diagnostics;

    public DocumentTranslator(
        TrustPolicyTranslationContext context,
        string? documentSource,
        List<TrustPolicyTranslationDiagnostic> diagnostics)
    {
        Context = context;
        DocumentSource = documentSource;
        Diagnostics = diagnostics;
    }

    /// <summary>Walks the validated root object and returns the produced spec.</summary>
    /// <param name="root">The root JSON object of a schema-validated document.</param>
    /// <returns>The produced <see cref="TrustPolicySpec"/> tree.</returns>
    public TrustPolicySpec WalkRoot(JsonObject root)
    {
        // Defensive: a "frontend" key whose value disagrees with this translator surfaces TPX101.
        if (root.TryGetPropertyValue(AssemblyStrings.PropertyFrontend, out JsonNode? frontendNode)
            && frontendNode is JsonValue fv
            && fv.TryGetValue(out string? frontendValue)
            && !string.Equals(frontendValue, AssemblyStrings.FrontendId, StringComparison.Ordinal))
        {
            Diagnostics.Add(new TrustPolicyTranslationDiagnostic
            {
                Severity = TrustPolicySeverity.Error,
                Code = AssemblyStrings.CodeFrontendMismatch,
                Message = string.Format(
                    CultureInfo.InvariantCulture,
                    AssemblyStrings.ErrFrontendMismatchFormat,
                    frontendValue,
                    AssemblyStrings.FrontendId),
                Location = MakeLocation(JoinPointer(AssemblyStrings.SourcePointerRoot, AssemblyStrings.PropertyFrontend)),
            });
        }

        string topCombinator = AssemblyStrings.CombinatorAnd;
        if (root.TryGetPropertyValue(AssemblyStrings.PropertyCombinator, out JsonNode? cn)
            && cn is JsonValue cv
            && cv.TryGetValue(out string? combinatorValue)
            && !string.IsNullOrEmpty(combinatorValue))
        {
            topCombinator = combinatorValue;
        }

        var scopes = new List<TrustPolicySpec>(capacity: 3);

        if (root.TryGetPropertyValue(AssemblyStrings.PropertyMessage, out JsonNode? messageNode)
            && messageNode is JsonObject messageObject)
        {
            string pointer = JoinPointer(AssemblyStrings.SourcePointerRoot, AssemblyStrings.PropertyMessage);
            TrustPolicySpec inner = WalkExpression(messageObject, pointer);
            scopes.Add(new MessageRequirementSpec(inner));
        }

        if (root.TryGetPropertyValue(AssemblyStrings.PropertyPrimarySigningKey, out JsonNode? psk)
            && psk is JsonObject pskObj)
        {
            string pointer = JoinPointer(AssemblyStrings.SourcePointerRoot, AssemblyStrings.PropertyPrimarySigningKey);
            TrustPolicySpec inner = WalkExpression(pskObj, pointer);
            scopes.Add(new PrimarySigningKeyRequirementSpec(inner));
        }

        if (root.TryGetPropertyValue(AssemblyStrings.PropertyAnyCounterSignature, out JsonNode? acs)
            && acs is JsonObject acsObj)
        {
            string pointer = JoinPointer(AssemblyStrings.SourcePointerRoot, AssemblyStrings.PropertyAnyCounterSignature);
            scopes.Add(WalkAnyCounterSignatureScope(acsObj, pointer));
        }

        if (scopes.Count == 0)
        {
            // Schema enforces anyOf the three scope keys — so an empty list is unreachable in
            // public flow; produce a safe placeholder so downstream code never sees a null spec.
            return new MessageRequirementSpec(new AllowAllSpec());
        }

        if (scopes.Count == 1)
        {
            return scopes[0];
        }

        // top combinator routes 2+ scopes
        return string.Equals(topCombinator, AssemblyStrings.CombinatorOr, StringComparison.Ordinal)
            ? new OrSpec(scopes)
            : new AndSpec(scopes);
    }

    private TrustPolicySpec WalkAnyCounterSignatureScope(JsonObject obj, string pointer)
    {
        OnEmptyBehavior onEmpty = OnEmptyBehavior.Deny;
        if (obj.TryGetPropertyValue(AssemblyStrings.PropertyOnEmpty, out JsonNode? oe)
            && oe is JsonValue oev
            && oev.TryGetValue(out string? oeValue)
            && string.Equals(oeValue, AssemblyStrings.OnEmptyAllow, StringComparison.Ordinal))
        {
            onEmpty = OnEmptyBehavior.Allow;
        }

        // Build a sibling JsonObject without the "on_empty" key so WalkExpression sees a clean
        // expression node. Cheaper than mutating the input (which is shared with the cache).
        var inner = new JsonObject();
        foreach (KeyValuePair<string, JsonNode?> kvp in obj)
        {
            if (kvp.Key == AssemblyStrings.PropertyOnEmpty)
            {
                continue;
            }

            inner[kvp.Key] = kvp.Value?.DeepClone();
        }

        TrustPolicySpec body = WalkExpression(inner, pointer);
        return new AnyCounterSignatureRequirementSpec(body, onEmpty);
    }

    private TrustPolicySpec WalkExpression(JsonObject obj, string pointer)
    {
        // Schema discriminator: exactly one of {fact, all_of, any_of, not, implies, allow_all, deny_all}
        // is present in a valid expression node.
        if (obj.ContainsKey(AssemblyStrings.PropertyFact))
        {
            return WalkRequireFact(obj, pointer);
        }

        if (obj.TryGetPropertyValue(AssemblyStrings.PropertyAllOf, out JsonNode? all)
            && all is JsonArray allArr)
        {
            return WalkAllOf(allArr, JoinPointer(pointer, AssemblyStrings.PropertyAllOf));
        }

        if (obj.TryGetPropertyValue(AssemblyStrings.PropertyAnyOf, out JsonNode? any)
            && any is JsonArray anyArr)
        {
            return WalkAnyOf(anyArr, JoinPointer(pointer, AssemblyStrings.PropertyAnyOf));
        }

        if (obj.TryGetPropertyValue(AssemblyStrings.PropertyNot, out JsonNode? not)
            && not is JsonObject notObj)
        {
            string innerPointer = JoinPointer(pointer, AssemblyStrings.PropertyNot);
            string? reason = null;
            if (obj.TryGetPropertyValue(AssemblyStrings.PropertyReason, out JsonNode? rn)
                && rn is JsonValue rv
                && rv.TryGetValue(out string? rs)
                && !string.IsNullOrWhiteSpace(rs))
            {
                reason = rs;
            }

            return new NotSpec(WalkExpression(notObj, innerPointer), reason);
        }

        if (obj.TryGetPropertyValue(AssemblyStrings.PropertyImplies, out JsonNode? impl)
            && impl is JsonObject implObj)
        {
            string implPointer = JoinPointer(pointer, AssemblyStrings.PropertyImplies);
            JsonObject antObj = (JsonObject)implObj[AssemblyStrings.PropertyAntecedent]!;
            JsonObject consObj = (JsonObject)implObj[AssemblyStrings.PropertyConsequent]!;
            return new ImpliesSpec(
                WalkExpression(antObj, JoinPointer(implPointer, AssemblyStrings.PropertyAntecedent)),
                WalkExpression(consObj, JoinPointer(implPointer, AssemblyStrings.PropertyConsequent)));
        }

        if (obj.ContainsKey(AssemblyStrings.PropertyAllowAll))
        {
            return new AllowAllSpec();
        }

        if (obj.TryGetPropertyValue(AssemblyStrings.PropertyDenyAll, out JsonNode? deny)
            && deny is JsonValue denyVal
            && denyVal.TryGetValue(out string? denyReason)
            && !string.IsNullOrWhiteSpace(denyReason))
        {
            return new DenyAllSpec(denyReason);
        }

        // Defensive — schema validation should have caught this.
        Diagnostics.Add(new TrustPolicyTranslationDiagnostic
        {
            Severity = TrustPolicySeverity.Error,
            Code = AssemblyStrings.CodeUntranslatableNode,
            Message = string.Format(
                CultureInfo.InvariantCulture,
                AssemblyStrings.ErrUntranslatableNodeFormat,
                pointer),
            Location = MakeLocation(pointer),
        });

        return new DenyAllSpec(AssemblyStrings.CodeUntranslatableNode);
    }

    private TrustPolicySpec WalkAllOf(JsonArray arr, string pointer)
    {
        var operands = new List<TrustPolicySpec>(arr.Count);
        for (int i = 0; i < arr.Count; i++)
        {
            if (arr[i] is JsonObject child)
            {
                operands.Add(WalkExpression(child, FormatIndexPointer(pointer, i)));
            }
        }

        return new AndSpec(operands);
    }

    private TrustPolicySpec WalkAnyOf(JsonArray arr, string pointer)
    {
        var operands = new List<TrustPolicySpec>(arr.Count);
        for (int i = 0; i < arr.Count; i++)
        {
            if (arr[i] is JsonObject child)
            {
                operands.Add(WalkExpression(child, FormatIndexPointer(pointer, i)));
            }
        }

        return new OrSpec(operands);
    }

    private static string FormatIndexPointer(string pointer, int index) =>
        string.Format(CultureInfo.InvariantCulture, AssemblyStrings.PointerArrayIndexFormat, pointer, index);

    private TrustPolicySpec WalkRequireFact(JsonObject obj, string pointer)
    {
        string factId = obj[AssemblyStrings.PropertyFact]!.GetValue<string>();
        JsonNode predicateNode = obj[AssemblyStrings.PropertyPredicate]!;

        string failureMessage = ReadFailureMessage(obj, factId, pointer);

        // Capability gating (D4): unknown fact id when the host advertised capabilities and
        // didn't opt in to AllowUnknownFacts.
        FactCapabilities? caps = Context.AvailableFacts;
        if (caps is not null && !Context.AllowUnknownFacts && !caps.AvailableFactIds.Contains(factId))
        {
            Diagnostics.Add(new TrustPolicyTranslationDiagnostic
            {
                Severity = TrustPolicySeverity.Error,
                Code = TrustPolicyDiagnosticCodes.UnknownFactId,
                Message = string.Format(
                    CultureInfo.InvariantCulture,
                    AssemblyStrings.ErrUnknownFactIdFormat,
                    factId,
                    string.Join(AssemblyStrings.CommaSpace, caps.AvailableFactIds.OrderBy(s => s, StringComparer.Ordinal))),
                Location = MakeLocation(JoinPointer(pointer, AssemblyStrings.PropertyFact)),
            });

            // Substitute a deny placeholder so downstream walking proceeds; the result will be
            // discarded because of the error diagnostic.
            return new DenyAllSpec(failureMessage);
        }

        // Predicate-schema gating (D4): when the capabilities expose a per-fact schema, validate
        // the user's predicate against it. Failures surface as TPX201.
        if (caps?.PredicateSchemas is { } schemas
            && schemas.TryGetValue(factId, out JsonNode? schemaNode)
            && schemaNode is not null)
        {
            string predicatePointer = JoinPointer(pointer, AssemblyStrings.PropertyPredicate);
            SchemaValidationDiagnostics.ValidatePredicateAgainstSchema(
                predicateNode,
                schemaNode,
                factId,
                predicatePointer,
                DocumentSource,
                Diagnostics);
        }

        FactPredicateSpec predicateSpec = WalkPredicate(predicateNode, JoinPointer(pointer, AssemblyStrings.PropertyPredicate));

        return new RequireFactSpec(factId, predicateSpec, failureMessage);
    }

    private string ReadFailureMessage(JsonObject obj, string factId, string pointer)
    {
        if (obj.TryGetPropertyValue(AssemblyStrings.PropertyFailureMessage, out JsonNode? fm)
            && fm is JsonValue fmValue
            && fmValue.TryGetValue(out string? fmText)
            && !string.IsNullOrWhiteSpace(fmText))
        {
            return fmText;
        }

        // Synthesise a stable default. We DON'T emit a warning here — schema marks
        // failure_message as optional so absence is canonical, not a problem.
        _ = pointer; // pointer suppressed; default messages don't carry a source link.
        return string.Format(
            CultureInfo.InvariantCulture,
            AssemblyStrings.DefaultFailureMessageFormat,
            factId);
    }

    private FactPredicateSpec WalkPredicate(JsonNode? predicateNode, string pointer)
    {
        if (predicateNode is not JsonObject predicate)
        {
            // Defensive: schema should reject non-object predicates.
            Diagnostics.Add(new TrustPolicyTranslationDiagnostic
            {
                Severity = TrustPolicySeverity.Error,
                Code = AssemblyStrings.CodeUntranslatableNode,
                Message = string.Format(
                    CultureInfo.InvariantCulture,
                    AssemblyStrings.ErrUntranslatableNodeFormat,
                    pointer),
                Location = MakeLocation(pointer),
            });
            return new PathOperatorPredicateSpec(AssemblyStrings.SourcePointerRoot, PredicateOperator.Exists, null);
        }

        // Path/operator form is identified by presence of "operator". Predicate-shape selection
        // is the schema's responsibility — we trust that here.
        if (predicate.ContainsKey(AssemblyStrings.PropertyOperator)
            && predicate.ContainsKey(AssemblyStrings.PropertyPath))
        {
            string opText = predicate[AssemblyStrings.PropertyOperator]!.GetValue<string>();
            string path = predicate[AssemblyStrings.PropertyPath]!.GetValue<string>();
            JsonNode? value = predicate.TryGetPropertyValue(AssemblyStrings.PropertyValue, out JsonNode? vn)
                ? vn?.DeepClone()
                : null;

            if (!Enum.TryParse(opText, ignoreCase: true, out PredicateOperator op))
            {
                Diagnostics.Add(new TrustPolicyTranslationDiagnostic
                {
                    Severity = TrustPolicySeverity.Error,
                    Code = AssemblyStrings.CodeUnknownOperator,
                    Message = string.Format(
                        CultureInfo.InvariantCulture,
                        AssemblyStrings.ErrUnknownOperatorFormat,
                        opText,
                        string.Join(AssemblyStrings.CommaSpace, Enum.GetNames<PredicateOperator>())),
                    Location = MakeLocation(JoinPointer(pointer, AssemblyStrings.PropertyOperator)),
                });

                op = PredicateOperator.Exists;
            }

            return new PathOperatorPredicateSpec(path, op, value);
        }

        // Property-assertion form. Each non-reserved key becomes an assertion entry.
        var assertions = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, JsonNode?> kvp in predicate)
        {
            assertions[kvp.Key] = kvp.Value?.DeepClone();
        }

        return new PropertyAssertionPredicateSpec(assertions);
    }

    private static string JoinPointer(string parent, string child) => string.Concat(parent, AssemblyStrings.SourcePointerSep, child);

    private SourceLocation MakeLocation(string pointer)
    {
        string source = string.IsNullOrEmpty(DocumentSource)
            ? pointer
            : string.Format(CultureInfo.InvariantCulture, AssemblyStrings.LocationWithSourceFormat, DocumentSource, pointer);
        return new SourceLocation(source, 0, 0, 0);
    }
}
