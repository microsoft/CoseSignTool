// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec;

using System;
using System.Collections.Generic;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Json;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Parameters;

/// <summary>
/// Convenience methods on <see cref="TrustPolicySpec"/> for callers that prefer a fluent style.
/// All operations are delegated to <see cref="TrustPolicySpecSerializer"/> /
/// <see cref="ParameterRef.Bind"/> so semantics are uniform.
/// </summary>
public static class TrustPolicySpecExtensions
{
    /// <summary>
    /// Serializes <paramref name="spec"/> to the canonical JSON string projection.
    /// </summary>
    /// <param name="spec">The spec to serialize.</param>
    /// <returns>UTF-8 JSON string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="spec"/> is null.</exception>
    public static string ToCanonicalJson(this TrustPolicySpec spec)
    {
        Cose.Abstractions.Guard.ThrowIfNull(spec);
        return TrustPolicySpecSerializer.ToCanonicalJson(spec);
    }

    /// <summary>
    /// Returns the SHA-256 content-hash bytes used as the translator-cache key (D9).
    /// </summary>
    /// <param name="spec">The spec to hash.</param>
    /// <returns>32-byte SHA-256 digest of <see cref="TrustPolicySpecSerializer.ToCanonicalJsonBytes"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="spec"/> is null.</exception>
    public static byte[] CanonicalContentHash(this TrustPolicySpec spec)
    {
        Cose.Abstractions.Guard.ThrowIfNull(spec);

        byte[] bytes = TrustPolicySpecSerializer.ToCanonicalJsonBytes(spec);
        return System.Security.Cryptography.SHA256.HashData(bytes);
    }

    /// <summary>
    /// Returns a deep clone of <paramref name="spec"/> with every <see cref="ParameterRef"/>
    /// occurrence replaced by the supplied binding (or its declared default).
    /// </summary>
    /// <param name="spec">The parameterised spec.</param>
    /// <param name="parameters">Host-supplied parameter bindings.</param>
    /// <returns>A new spec with parameters bound.</returns>
    /// <exception cref="ArgumentNullException">Thrown when either argument is null.</exception>
    /// <exception cref="System.InvalidOperationException">Thrown when canonical-JSON re-projection produces unexpected nulls — indicates a bug in the spec serializer or a corrupted spec instance.</exception>
    /// <exception cref="Diagnostics.TrustPolicySpecCompilationException">
    /// Thrown when a referenced parameter has neither a binding nor a default.
    /// </exception>
    public static TrustPolicySpec Bind(this TrustPolicySpec spec, IReadOnlyDictionary<string, System.Text.Json.Nodes.JsonNode?> parameters)
    {
        Cose.Abstractions.Guard.ThrowIfNull(spec);
        Cose.Abstractions.Guard.ThrowIfNull(parameters);

        // Round-trip via canonical JSON so the binder doesn't have to walk every concrete record
        // type explicitly. Only JsonNode-typed value positions can carry a parameter ref by
        // construction, so JsonNode-level rewriting is sufficient and structurally exhaustive.
        string json = TrustPolicySpecSerializer.ToCanonicalJson(spec);
        var node = System.Text.Json.Nodes.JsonNode.Parse(json)
            ?? throw new InvalidOperationException(ClassStrings.ErrCanonicalJsonReparseNull);

        var bound = ParameterRef.Bind(node, parameters)
            ?? throw new InvalidOperationException(ClassStrings.ErrParameterBindNullSpec);

        return TrustPolicySpecSerializer.FromCanonicalJson(bound.ToJsonString(TrustPolicySpecSerializer.Options));
    }
}
