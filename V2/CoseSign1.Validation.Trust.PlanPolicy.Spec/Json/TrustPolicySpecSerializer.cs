// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Json;

using System;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;

/// <summary>
/// Canonical <see cref="JsonSerializerOptions"/> for round-tripping a <see cref="TrustPolicySpec"/>
/// to and from the byte-identical canonical JSON projection that backs D9's content-hash cache key.
/// </summary>
/// <remarks>
/// <para>
/// Property ordering on the records themselves comes from <see cref="JsonPropertyOrderAttribute"/>
/// declarations. Map keys (in property-assertion predicates) and arbitrary object keys reachable
/// through <see cref="JsonNode"/> are sorted by the Canonical converters in this namespace.
/// Number formats use <see cref="JsonNumberHandling.Strict"/> to keep numeric round-trips stable.
/// </para>
/// <para>
/// The output is compact (no indentation, no extra whitespace) and uses
/// <see cref="JavaScriptEncoder.UnsafeRelaxedJsonEscaping"/> so non-ASCII property values do
/// not pick up <c>\uXXXX</c> escapes that would otherwise differ from Rego/CEL frontends'
/// canonical projections.
/// </para>
/// </remarks>
public static class TrustPolicySpecSerializer
{
    /// <summary>
    /// Gets the canonical, immutable <see cref="JsonSerializerOptions"/> instance used by
    /// <see cref="ToCanonicalJson"/>, <see cref="ToCanonicalJsonBytes"/>, and <see cref="FromCanonicalJson"/>.
    /// </summary>
    public static JsonSerializerOptions Options { get; } = BuildOptions();

    /// <summary>
    /// Serializes <paramref name="spec"/> to the canonical JSON string projection.
    /// </summary>
    /// <param name="spec">The spec to serialize.</param>
    /// <returns>A UTF-8 JSON string (no BOM, compact, sorted maps).</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="spec"/> is null.</exception>
    public static string ToCanonicalJson(TrustPolicySpec spec)
    {
        Cose.Abstractions.Guard.ThrowIfNull(spec);

        return JsonSerializer.Serialize(spec, Options);
    }

    /// <summary>
    /// Serializes <paramref name="spec"/> to canonical UTF-8 bytes; the bytes are the input to
    /// the SHA-256 content-hash key in the translator cache.
    /// </summary>
    /// <param name="spec">The spec to serialize.</param>
    /// <returns>UTF-8 encoded bytes.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="spec"/> is null.</exception>
    public static byte[] ToCanonicalJsonBytes(TrustPolicySpec spec)
    {
        Cose.Abstractions.Guard.ThrowIfNull(spec);

        return JsonSerializer.SerializeToUtf8Bytes(spec, Options);
    }

    /// <summary>
    /// Deserializes a canonical-form JSON string into a <see cref="TrustPolicySpec"/>.
    /// </summary>
    /// <param name="json">The canonical JSON.</param>
    /// <returns>The parsed spec.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="json"/> is null.</exception>
    /// <exception cref="JsonException">Thrown when the JSON does not match the spec schema or carries an unknown discriminator.</exception>
    public static TrustPolicySpec FromCanonicalJson(string json)
    {
        Cose.Abstractions.Guard.ThrowIfNull(json);

        TrustPolicySpec? result = JsonSerializer.Deserialize<TrustPolicySpec>(json, Options);
        if (result is null)
        {
            throw new JsonException(ClassStrings.ErrCanonicalJsonNullSpec);
        }

        return result;
    }

    private static JsonSerializerOptions BuildOptions()
    {
        var options = new JsonSerializerOptions
        {
            // Compact, deterministic output. Indentation introduces whitespace differences
            // that would defeat the byte-identical round-trip contract.
            WriteIndented = false,

            // Strict number handling keeps the JSON projection stable for numeric facts. Without
            // this, '1' and '1.0' would round-trip differently between platforms.
            NumberHandling = JsonNumberHandling.Strict,

            // Allow trailing commas only on read so hand-edited examples don't fail the binder;
            // canonical writes never emit trailing commas.
            AllowTrailingCommas = true,

            // Bound deserialization recursion. The default of 64 is generous — trust-policy specs
            // are typically 4–6 levels deep; values above this depth are almost certainly an
            // attacker probing the parser for stack-exhaustion (DoS via deeply nested arrays /
            // objects). The limit applies to inbound JSON in FromCanonicalJson; the outbound
            // canonical writer enforces its own depth budget independently.
            MaxDepth = MaxSerializationDepth,

            // UnsafeRelaxedJsonEscaping is used so non-ASCII fact-id components and host strings
            // serialize identically across frontends (the JSON spec allows raw codepoints; STJ's
            // default escapes them, which would diverge from the Rego/CEL projections).
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };

        // Enum values serialize as snake_case strings so the canonical JSON matches §6.5.5 examples
        // (e.g. "primary_signing_key", "any_counter_signature", "starts_with").
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower));
        options.Converters.Add(new CanonicalJsonNodeConverter(MaxSerializationDepth));
        options.Converters.Add(new CanonicalPredicateAssertionsConverter());

        return options;
    }

    /// <summary>
    /// Maximum recursion depth for canonical JSON serialisation. Bounds the writer against
    /// stack-exhaustion when fed a programmatically-constructed deeply nested
    /// <see cref="JsonNode"/>; the matching <see cref="JsonSerializerOptions.MaxDepth"/> bounds
    /// the reader.
    /// </summary>
    public const int MaxSerializationDepth = 64;
}
