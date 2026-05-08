// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego.Internal;

using System.Globalization;
using System.Text.Json.Nodes;

/// <summary>
/// Lowers a parsed <see cref="RegoValueNode"/> tree into a <see cref="JsonNode"/> that matches
/// the canonical <c>cose-tp-json/v1</c> document shape. The JSON frontend's schema validator
/// + walker is reused on the lowered tree, so byte-equality with the JSON frontend's
/// canonical IR is a property of construction, not of duplicated logic.
/// </summary>
/// <remarks>
/// <para>
/// The only Rego→JSON projection that doesn't fall out of "literal-to-literal" is the
/// <see cref="RegoInputRefNode"/> case: an <c>input.&lt;name&gt;</c> reference becomes the
/// <c>{"$param": "&lt;name&gt;"}</c> object the JSON frontend recognises (per D5). This is a
/// faithful translation: both frontends produce the same <c>ParameterRef</c> in the IR, so
/// the post-translate Bind pass behaves identically.
/// </para>
/// </remarks>
internal static class RegoLowerer
{
    /// <summary>Lowers <paramref name="node"/> to a <see cref="JsonNode"/>.</summary>
    /// <param name="node">The AST root.</param>
    /// <returns>The lowered <see cref="JsonNode"/> tree.</returns>
    public static JsonNode? Lower(RegoValueNode node)
    {
        switch (node)
        {
            case RegoObjectNode obj:
                return LowerObject(obj);
            case RegoArrayNode arr:
                return LowerArray(arr);
            case RegoScalarNode scalar:
                return LowerScalar(scalar);
            case RegoInputRefNode input:
                return LowerInputRef(input);
            default:
                return UnreachableNonClosedNode();
        }
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = AssemblyStrings.JustifyDefensiveAllowedByGrammar)]
    private static JsonNode UnreachableNonClosedNode() => new JsonObject();

    private static JsonObject LowerObject(RegoObjectNode obj)
    {
        var result = new JsonObject();
        foreach (RegoObjectEntry entry in obj.Entries)
        {
            result[entry.Key] = Lower(entry.Value);
        }

        return result;
    }

    private static JsonArray LowerArray(RegoArrayNode arr)
    {
        var result = new JsonArray();
        foreach (RegoValueNode item in arr.Items)
        {
            result.Add(Lower(item));
        }

        return result;
    }

    private static JsonNode? LowerScalar(RegoScalarNode scalar)
    {
        switch (scalar.Kind)
        {
            case RegoScalarKind.String:
                return JsonValue.Create(scalar.Text);
            case RegoScalarKind.True:
                return JsonValue.Create(true);
            case RegoScalarKind.False:
                return JsonValue.Create(false);
            case RegoScalarKind.Null:
                return null;
            case RegoScalarKind.Number:
                return LowerNumber(scalar.Text);
            default:
                return UnreachableScalarKind();
        }
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = AssemblyStrings.JustifyDefensiveAllowedByGrammar)]
    private static JsonNode UnreachableScalarKind() => JsonValue.Create(0)!;

    private static JsonNode LowerNumber(string text)
    {
        // Prefer integer projection to keep the canonical JSON output byte-equal with the
        // cose-tp-json/v1 fixtures (which use integer literals where possible).
        if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out long l))
        {
            return JsonValue.Create(l);
        }

        if (decimal.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out decimal d))
        {
            return JsonValue.Create(d);
        }

        if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out double dbl))
        {
            return JsonValue.Create(dbl);
        }

        return UnreachableUnparseableNumber();
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = AssemblyStrings.JustifyDefensiveAllowedByGrammar)]
    private static JsonNode UnreachableUnparseableNumber() => JsonValue.Create(0)!;

    private static JsonObject LowerInputRef(RegoInputRefNode input)
    {
        // The JSON frontend recognises {"$param": "<name>"} as a parameter reference (D5).
        // We project Rego's input.<name> to exactly that shape so the post-translate Bind
        // pass is identical between frontends.
        return new JsonObject
        {
            [AssemblyStrings.PropertyParam] = JsonValue.Create(input.ParameterName),
        };
    }
}
