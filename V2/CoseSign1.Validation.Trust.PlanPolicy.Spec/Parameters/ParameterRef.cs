// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Parameters;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;

/// <summary>
/// Placeholder appearing in any <see cref="JsonNode"/>-typed value position in the spec.
/// <see cref="Bind"/> rewrites every occurrence into the corresponding parameter value supplied
/// by the host before <see cref="Compilation.TrustPolicySpecCompiler.Compile"/> runs.
/// </summary>
/// <remarks>
/// <para>
/// Wire shape: <c>{"$param": "<i>name</i>", "default": <i>value</i>}</c>. The <c>default</c> key
/// is optional. Both keys are case-sensitive and exact-match — the translator MUST reject any
/// shape that contains <c>$param</c> alongside other unrecognised keys (handled in Phase 2; the
/// Phase 1 binder is permissive on Bind direction and strict on emission).
/// </para>
/// <para>
/// Per design decision D5, parameter substitution happens after parsing — never as a string
/// macro pre-pass — so source locations are preserved through binding.
/// </para>
/// </remarks>
public sealed record ParameterRef
{
    /// <summary>The reserved property name marking a JSON object as a <see cref="ParameterRef"/>.</summary>
    public const string ParameterMarker = ClassStrings.ParameterMarker;

    /// <summary>The reserved property name carrying the optional default value.</summary>
    public const string DefaultProperty = ClassStrings.ParameterDefaultProperty;

    /// <summary>
    /// Initializes a new instance of the <see cref="ParameterRef"/> class.
    /// </summary>
    /// <param name="name">The parameter name; never null or whitespace.</param>
    /// <param name="default">An optional default applied when <see cref="Bind"/> sees no binding for <paramref name="name"/>.</param>
    /// <param name="location">Optional source location preserved through binding.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="name"/> is null, empty, or whitespace.</exception>
    public ParameterRef(string name, JsonNode? @default = null, SourceLocation? location = null)
    {
        Cose.Abstractions.Guard.ThrowIfNullOrWhiteSpace(name);

        Name = name;
        Default = @default;
        Location = location;
    }

    /// <summary>Gets the parameter name.</summary>
    public string Name { get; }

    /// <summary>Gets the optional default value (a deep-cloned <see cref="JsonNode"/>).</summary>
    public JsonNode? Default { get; }

    /// <summary>Gets the optional source location.</summary>
    public SourceLocation? Location { get; }

    /// <summary>
    /// Tests whether <paramref name="node"/> is the wire shape of a <see cref="ParameterRef"/>.
    /// </summary>
    /// <param name="node">The node to inspect.</param>
    /// <returns><see langword="true"/> when the node is a JSON object whose first own key is the parameter marker.</returns>
    public static bool IsParameterRef(JsonNode? node) =>
        node is JsonObject obj && obj.ContainsKey(ParameterMarker);

    /// <summary>
    /// Parses <paramref name="node"/> as a <see cref="ParameterRef"/> if it is the wire shape.
    /// </summary>
    /// <param name="node">The candidate node.</param>
    /// <param name="result">When this method returns true, the parsed parameter reference.</param>
    /// <returns><see langword="true"/> when <paramref name="node"/> matches the parameter-ref shape.</returns>
    public static bool TryParse(JsonNode? node, out ParameterRef? result)
    {
        result = null;
        if (node is not JsonObject obj || !obj.TryGetPropertyValue(ParameterMarker, out var nameNode))
        {
            return false;
        }

        if (nameNode is not JsonValue nameValue || !nameValue.TryGetValue(out string? name) || string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        JsonNode? defaultNode = null;
        if (obj.TryGetPropertyValue(DefaultProperty, out var defNode) && defNode is not null)
        {
            defaultNode = defNode.DeepClone();
        }

        result = new ParameterRef(name, defaultNode);
        return true;
    }

    /// <summary>
    /// Renders this <see cref="ParameterRef"/> to its canonical wire shape.
    /// </summary>
    /// <returns>A new <see cref="JsonObject"/> carrying the marker and optional default.</returns>
    public JsonObject ToJsonNode()
    {
        var obj = new JsonObject
        {
            [ParameterMarker] = JsonValue.Create(Name),
        };

        if (Default is not null)
        {
            obj[DefaultProperty] = Default.DeepClone();
        }

        return obj;
    }

    /// <summary>
    /// Substitutes every parameter-ref occurrence reachable from <paramref name="root"/> with the
    /// corresponding entry in <paramref name="bindings"/> or its default.
    /// </summary>
    /// <param name="root">The root node to walk; may be null.</param>
    /// <param name="bindings">The host-supplied bindings.</param>
    /// <returns>A new node with all parameter refs resolved, or <see langword="null"/> if <paramref name="root"/> is null.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="bindings"/> is null.</exception>
    /// <exception cref="TrustPolicySpecCompilationException">
    /// Thrown with code <see cref="TrustPolicyDiagnosticCodes.UnboundParameter"/> when a parameter
    /// has no binding and no default.
    /// </exception>
    public static JsonNode? Bind(JsonNode? root, IReadOnlyDictionary<string, JsonNode?> bindings)
    {
        Cose.Abstractions.Guard.ThrowIfNull(bindings);

        if (root is null)
        {
            return null;
        }

        if (TryParse(root, out var paramRef) && paramRef is not null)
        {
            if (bindings.TryGetValue(paramRef.Name, out var bound))
            {
                return bound?.DeepClone();
            }

            if (paramRef.Default is not null)
            {
                return paramRef.Default.DeepClone();
            }

            throw new TrustPolicySpecCompilationException(
                TrustPolicyDiagnosticCodes.UnboundParameter,
                string.Format(
                    System.Globalization.CultureInfo.InvariantCulture,
                    ClassStrings.ErrUnboundParameterFormat,
                    paramRef.Name));
        }

        return root switch
        {
            JsonObject obj => BindObject(obj, bindings),
            JsonArray arr => BindArray(arr, bindings),
            _ => root.DeepClone(),
        };
    }

    private static JsonObject BindObject(JsonObject obj, IReadOnlyDictionary<string, JsonNode?> bindings)
    {
        var result = new JsonObject();
        foreach (var kvp in obj)
        {
            result[kvp.Key] = Bind(kvp.Value, bindings);
        }

        return result;
    }

    private static JsonArray BindArray(JsonArray arr, IReadOnlyDictionary<string, JsonNode?> bindings)
    {
        var bound = arr.Select(item => Bind(item, bindings)).ToArray();
        return new JsonArray(bound);
    }
}
