// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Json;

using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;

/// <summary>
/// Custom converter for <see cref="PropertyAssertionPredicateSpec.Assertions"/> so that the
/// dictionary serializes with lexicographically ordered keys. Without this, dictionary insertion
/// order leaks into the canonical-JSON projection — breaking the byte-identical round-trip
/// invariant when a spec is constructed in code with a non-sorted dictionary.
/// </summary>
internal sealed class CanonicalPredicateAssertionsConverter : JsonConverter<IReadOnlyDictionary<string, JsonNode?>>
{
    public override IReadOnlyDictionary<string, JsonNode?> Read(
        ref Utf8JsonReader reader,
        System.Type typeToConvert,
        JsonSerializerOptions options)
    {
        var dict = new SortedDictionary<string, JsonNode?>(System.StringComparer.Ordinal);
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException(ClassStrings.ErrPredicateAssertionsStartObject);
        }

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                return dict;
            }

            if (reader.TokenType != JsonTokenType.PropertyName)
            {
                throw new JsonException(ClassStrings.ErrPredicateAssertionsPropertyName);
            }

            string key = reader.GetString()!;
            reader.Read();
            JsonNode? value = JsonNode.Parse(ref reader);
            dict[key] = value;
        }

        throw new JsonException(ClassStrings.ErrPredicateAssertionsEof);
    }

    public override void Write(
        Utf8JsonWriter writer,
        IReadOnlyDictionary<string, JsonNode?> value,
        JsonSerializerOptions options)
    {
        Cose.Abstractions.Guard.ThrowIfNull(value);

        writer.WriteStartObject();
        var sorted = new List<KeyValuePair<string, JsonNode?>>(value);
        sorted.Sort(static (a, b) => System.StringComparer.Ordinal.Compare(a.Key, b.Key));
        var nodeConverter = (JsonConverter<JsonNode?>)options.GetConverter(typeof(JsonNode));
        foreach (var kvp in sorted)
        {
            writer.WritePropertyName(kvp.Key);
            nodeConverter.Write(writer, kvp.Value, options);
        }

        writer.WriteEndObject();
    }
}
