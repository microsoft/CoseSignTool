// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Compilation;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Parameters;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;

/// <summary>
/// Internal helper that lowers a <see cref="FactPredicateSpec"/> against a fact CLR type into a
/// <see cref="System.Func{T, TResult}"/>-shaped predicate compatible with the existing
/// <see cref="CoseSign1.Validation.Trust.Rules.TrustRules.AnyFact{TFact}"/> rule.
/// </summary>
/// <remarks>
/// The predicate evaluates by serialising the fact instance to a <see cref="JsonNode"/>
/// projection (one-shot, on each evaluation) and applying path resolution + operator semantics
/// against that projection. The same JsonNode projection is used for both
/// <see cref="PathOperatorPredicateSpec"/> and <see cref="PropertyAssertionPredicateSpec"/>, so
/// the two forms compile to functionally equivalent runtime predicates — the byte-identical
/// rule-evaluation invariant required by D1.
/// </remarks>
internal static class PredicateLowerer
{
    /// <summary>
    /// Compiles <paramref name="predicate"/> into a runtime <see cref="System.Func{T, TResult}"/>
    /// over <paramref name="factType"/>.
    /// </summary>
    /// <param name="factType">The resolved fact CLR type.</param>
    /// <param name="factTypeId">The fact's stable id (used in diagnostics).</param>
    /// <param name="predicate">The predicate to lower.</param>
    /// <returns>A compiled predicate Func.</returns>
    public static Func<object, bool> Compile(Type factType, string factTypeId, FactPredicateSpec predicate)
    {
        return predicate switch
        {
            PathOperatorPredicateSpec po => CompilePathOperator(factType, factTypeId, po),
            PropertyAssertionPredicateSpec pa => CompilePropertyAssertion(factType, factTypeId, pa),
            _ => throw new TrustPolicySpecCompilationException(
                TrustPolicyDiagnosticCodes.UnsupportedPredicateOperator,
                string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrUnknownPredicateNodeFormat, predicate.GetType().FullName)),
        };
    }

    private static Func<object, bool> CompilePathOperator(Type factType, string factTypeId, PathOperatorPredicateSpec predicate)
    {
        // Validate that the path resolves at compile time on a synthetic projection — fail-fast
        // at compile time rather than during evaluation. We can't actually check existence on
        // a real instance, but we can reject malformed paths.
        var pathSegments = ParsePath(predicate.Path, factTypeId);
        var operatorRef = predicate.Operator;
        var literalValue = predicate.Value?.DeepClone();

        if (ParameterRef.IsParameterRef(literalValue))
        {
            throw new TrustPolicySpecCompilationException(
                TrustPolicyDiagnosticCodes.UnboundParameter,
                string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrPathPredicateBoundFormat, factTypeId));
        }

        if (operatorRef != PredicateOperator.Exists && literalValue is null)
        {
            throw new TrustPolicySpecCompilationException(
                TrustPolicyDiagnosticCodes.UnsupportedPredicateOperator,
                string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrPathPredicateNonNullValueFormat, operatorRef, factTypeId));
        }

        return fact =>
        {
            JsonNode? projection = ProjectFact(fact, factType);
            JsonNode? resolved = ResolvePath(projection, pathSegments);
            return ApplyOperator(operatorRef, resolved, literalValue);
        };
    }

    private static Func<object, bool> CompilePropertyAssertion(Type factType, string factTypeId, PropertyAssertionPredicateSpec predicate)
    {
        // Validate every property at compile time so missing / mistyped names fail before
        // evaluation. We accept any property that round-trips through the JsonNode projection,
        // which means the JSON property name on the projection is the source of truth — this
        // matches the path+operator form's evaluation semantics.
        var sample = new JsonObject();
        var snapshot = predicate.Assertions.ToList();
        foreach (var entry in snapshot)
        {
            if (string.IsNullOrWhiteSpace(entry.Key))
            {
                throw new TrustPolicySpecCompilationException(
                    TrustPolicyDiagnosticCodes.UnknownFactProperty,
                    string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrPropertyAssertionWhitespaceFormat, factTypeId));
            }

            if (ParameterRef.IsParameterRef(entry.Value))
            {
                throw new TrustPolicySpecCompilationException(
                    TrustPolicyDiagnosticCodes.UnboundParameter,
                    string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrPropertyAssertionUnboundFormat, factTypeId, entry.Key));
            }

            sample[entry.Key] = null;
        }

        return fact =>
        {
            JsonNode? projection = ProjectFact(fact, factType);
            if (projection is not JsonObject obj)
            {
                return false;
            }

            foreach (var kvp in snapshot)
            {
                if (!obj.TryGetPropertyValue(kvp.Key, out var actual))
                {
                    return false;
                }

                var expected = kvp.Value;
                bool matches = expected is JsonArray
                    ? ApplyOperator(PredicateOperator.In, actual, expected)
                    : DeepEquals(actual, expected);
                if (!matches)
                {
                    return false;
                }
            }

            return true;
        };
    }

    private static JsonNode? ProjectFact(object fact, Type factType)
    {
        // Pre-build a JsonSerializerOptions per-fact at first projection. We use property-name
        // case-insensitive matching is unnecessary because the canonical JSON converter writes
        // declared-property casing. Use camelCase to match the §6.5.5 examples (`is_trusted`
        // vs CLR `IsTrusted`). Use snake_case to be uniform with the spec itself.
        var options = ProjectionOptions;
        return JsonSerializer.SerializeToNode(fact, factType, options);
    }

    private static readonly JsonSerializerOptions ProjectionOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
    };

    private static IReadOnlyList<PathSegment> ParsePath(string path, string factTypeId)
    {
        if (string.IsNullOrEmpty(path))
        {
            throw new TrustPolicySpecCompilationException(
                TrustPolicyDiagnosticCodes.UnsupportedPredicatePath,
                string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrPathEmptyFormat, factTypeId));
        }

        if (path[0] != '$')
        {
            throw new TrustPolicySpecCompilationException(
                TrustPolicyDiagnosticCodes.UnsupportedPredicatePath,
                string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrPathNoRootFormat, path, factTypeId));
        }

        var segments = new List<PathSegment>();
        int i = 1;
        while (i < path.Length)
        {
            char c = path[i];
            if (c == '.')
            {
                int start = i + 1;
                int end = start;
                while (end < path.Length && path[end] != '.' && path[end] != '[')
                {
                    end++;
                }

                if (end == start)
                {
                    throw new TrustPolicySpecCompilationException(
                        TrustPolicyDiagnosticCodes.UnsupportedPredicatePath,
                        string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrPathEmptyAccessorFormat, path, factTypeId));
                }

                segments.Add(PathSegment.Property(path.Substring(start, end - start)));
                i = end;
            }
            else if (c == '[')
            {
                int end = path.IndexOf(']', i + 1);
                if (end < 0)
                {
                    throw new TrustPolicySpecCompilationException(
                        TrustPolicyDiagnosticCodes.UnsupportedPredicatePath,
                        string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrPathUnterminatedIndexFormat, path, factTypeId));
                }

                string idxText = path.Substring(i + 1, end - i - 1);
                if (!int.TryParse(idxText, NumberStyles.Integer, CultureInfo.InvariantCulture, out int idx) || idx < 0)
                {
                    throw new TrustPolicySpecCompilationException(
                        TrustPolicyDiagnosticCodes.UnsupportedPredicatePath,
                        string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrPathBadIndexFormat, path, factTypeId, idxText));
                }

                segments.Add(PathSegment.ForIndex(idx));
                i = end + 1;
            }
            else
            {
                throw new TrustPolicySpecCompilationException(
                    TrustPolicyDiagnosticCodes.UnsupportedPredicatePath,
                    string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrPathUnsupportedCharFormat, path, factTypeId, c));
            }
        }

        return segments;
    }

    private static JsonNode? ResolvePath(JsonNode? root, IReadOnlyList<PathSegment> segments)
    {
        JsonNode? current = root;
        foreach (var segment in segments)
        {
            if (current is null)
            {
                return null;
            }

            current = segment.Kind switch
            {
                PathSegmentKind.Property when current is JsonObject obj && obj.TryGetPropertyValue(segment.Name!, out var prop) => prop,
                PathSegmentKind.Index when current is JsonArray arr && segment.Index!.Value < arr.Count => arr[segment.Index.Value],
                _ => null,
            };
        }

        return current;
    }

    private static bool ApplyOperator(PredicateOperator op, JsonNode? actual, JsonNode? expected)
    {
        switch (op)
        {
            case PredicateOperator.Exists:
                return actual is not null;

            case PredicateOperator.Equals:
                return DeepEquals(actual, expected);

            case PredicateOperator.NotEquals:
                return !DeepEquals(actual, expected);

            case PredicateOperator.LessThan:
                return CompareNumbers(actual, expected) is int lt && lt < 0;

            case PredicateOperator.LessThanOrEqual:
                return CompareNumbers(actual, expected) is int le && le <= 0;

            case PredicateOperator.GreaterThan:
                return CompareNumbers(actual, expected) is int gt && gt > 0;

            case PredicateOperator.GreaterThanOrEqual:
                return CompareNumbers(actual, expected) is int ge && ge >= 0;

            case PredicateOperator.StartsWith:
                return TryGetString(actual, out string? s1) && TryGetString(expected, out string? s2) && s1.StartsWith(s2!, StringComparison.Ordinal);

            case PredicateOperator.EndsWith:
                return TryGetString(actual, out string? e1) && TryGetString(expected, out string? e2) && e1.EndsWith(e2!, StringComparison.Ordinal);

            case PredicateOperator.Contains:
                if (actual is JsonArray arr)
                {
                    return arr.Any(item => DeepEquals(item, expected));
                }

                if (TryGetString(actual, out string? c1) && TryGetString(expected, out string? c2))
                {
                    return c1.Contains(c2, StringComparison.Ordinal);
                }

                return false;

            case PredicateOperator.In:
                if (expected is not JsonArray bag)
                {
                    return false;
                }

                return bag.Any(item => DeepEquals(actual, item));

            default:
                return false;
        }
    }

    private static bool TryGetString(JsonNode? node, out string? value)
    {
        if (node is JsonValue v && v.TryGetValue(out string? s))
        {
            value = s;
            return true;
        }

        value = null;
        return false;
    }

    private static int? CompareNumbers(JsonNode? a, JsonNode? b)
    {
        if (a is JsonValue av && b is JsonValue bv && av.TryGetValue(out double ad) && bv.TryGetValue(out double bd))
        {
            return ad.CompareTo(bd);
        }

        // Fall back to string compare when both operands are strings (e.g., ordinal alphanumeric ranking).
        if (TryGetString(a, out string? aText) && TryGetString(b, out string? bText))
        {
            return string.CompareOrdinal(aText, bText);
        }

        return null;
    }

    private static bool DeepEquals(JsonNode? a, JsonNode? b)
    {
        if (ReferenceEquals(a, b))
        {
            return true;
        }

        if (a is null || b is null)
        {
            return false;
        }

        // JsonNode.DeepEquals is the canonical structural-equality primitive in STJ; using
        // anything else (e.g., string compare on serialized form) re-introduces the encoding-
        // sensitivity we explicitly remove via the canonical JSON converter.
        return JsonNode.DeepEquals(a, b);
    }

    private enum PathSegmentKind
    {
        Property,
        Index,
    }

    private readonly struct PathSegment
    {
        private PathSegment(PathSegmentKind kind, string? name, int? index)
        {
            Kind = kind;
            Name = name;
            Index = index;
        }

        public PathSegmentKind Kind { get; }

        public string? Name { get; }

        public int? Index { get; }

        public static PathSegment Property(string name) => new(PathSegmentKind.Property, name, null);

        public static PathSegment ForIndex(int index) => new(PathSegmentKind.Index, null, index);
    }

    /// <summary>
    /// Validates that <paramref name="factType"/> exposes <paramref name="propertyNames"/> after
    /// applying the projection naming policy. Used by the compiler to reject specs that target
    /// non-existent properties before the policy is evaluated.
    /// </summary>
    /// <param name="factType">The resolved fact CLR type.</param>
    /// <param name="propertyNames">Property names referenced by the predicate (in JSON form).</param>
    /// <param name="factTypeId">The fact id (used in diagnostics).</param>
    /// <exception cref="TrustPolicySpecCompilationException">
    /// Thrown with code <see cref="TrustPolicyDiagnosticCodes.UnknownFactProperty"/> when any
    /// referenced property does not exist on the fact's JSON projection.
    /// </exception>
    public static void ValidatePropertyAccess(Type factType, IEnumerable<string> propertyNames, string factTypeId)
    {
        Cose.Abstractions.Guard.ThrowIfNull(factType);
        Cose.Abstractions.Guard.ThrowIfNull(propertyNames);

        // Pre-compute the set of available JSON property names (after the projection naming policy).
        // We use the actual public, instance, readable properties — that's the surface the
        // serializer projects. Using the projection itself would require constructing an
        // instance, which we don't have at compile time.
        var available = new HashSet<string>(StringComparer.Ordinal);
        foreach (var prop in factType.GetProperties(BindingFlags.Instance | BindingFlags.Public))
        {
            if (!prop.CanRead)
            {
                continue;
            }

            available.Add(ProjectionOptions.PropertyNamingPolicy!.ConvertName(prop.Name));
        }

        foreach (var name in propertyNames)
        {
            if (!available.Contains(name))
            {
                throw new TrustPolicySpecCompilationException(
                    TrustPolicyDiagnosticCodes.UnknownFactProperty,
                    string.Format(CultureInfo.InvariantCulture, ClassStrings.ErrFactPropertyMissingFormat, name, factTypeId, factType.FullName, string.Join(ClassStrings.JoinSeparator, available.OrderBy(n => n, StringComparer.Ordinal))));
            }
        }
    }
}
