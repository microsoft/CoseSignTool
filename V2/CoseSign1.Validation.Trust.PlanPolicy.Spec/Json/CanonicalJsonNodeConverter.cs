// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Json;

using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

/// <summary>
/// Custom converter that re-orders <see cref="JsonObject"/> keys lexicographically (Ordinal)
/// during serialization, so that the canonical-JSON projection of a spec is order-independent
/// of the order in which the spec was constructed or deserialized.
/// </summary>
/// <remarks>
/// <para>
/// This is the basis for D9's content-hash key: two specs that are structurally equal must
/// produce byte-identical JSON; the hash of that JSON is the cache key.
/// </para>
/// <para>
/// The converter only applies to <see cref="JsonNode"/> values reachable from the public spec
/// types (predicate values, parameter defaults, property-assertion entries). It does NOT
/// re-order properties on the spec records themselves — those are stable via
/// <see cref="JsonPropertyOrderAttribute"/>.
/// </para>
/// </remarks>
internal sealed class CanonicalJsonNodeConverter : JsonConverter<JsonNode?>
{
    private readonly int MaxDepth;

    public CanonicalJsonNodeConverter(int maxDepth = 64)
    {
        MaxDepth = maxDepth;
    }

    public override JsonNode? Read(ref Utf8JsonReader reader, System.Type typeToConvert, JsonSerializerOptions options)
    {
        return JsonNode.Parse(ref reader);
    }

    public override void Write(Utf8JsonWriter writer, JsonNode? value, JsonSerializerOptions options)
    {
        if (value is null)
        {
            writer.WriteNullValue();
            return;
        }

        WriteCanonical(writer, value, MaxDepth);
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonNode node, int remainingDepth)
    {
        if (remainingDepth <= 0)
        {
            // Defensive — JsonSerializerOptions.MaxDepth bounds the matching reader, but a
            // programmatically constructed JsonNode can still nest beyond the writer's safe
            // recursion budget. Surface the failure as a typed exception rather than a stack
            // overflow.
            throw new JsonException(ClassStrings.ErrCanonicalDepthExceeded);
        }

        switch (node)
        {
            case JsonObject obj:
                writer.WriteStartObject();

                // Snapshot to a list so enumeration is stable even if the underlying object
                // mutates between sort and write (defensive only — JsonObject is not normally
                // shared across threads at this layer).
                var entries = obj.ToList();
                entries.Sort(static (a, b) => System.StringComparer.Ordinal.Compare(a.Key, b.Key));
                foreach (var kvp in entries)
                {
                    writer.WritePropertyName(kvp.Key);
                    if (kvp.Value is null)
                    {
                        writer.WriteNullValue();
                    }
                    else
                    {
                        WriteCanonical(writer, kvp.Value, remainingDepth - 1);
                    }
                }

                writer.WriteEndObject();
                break;

            case JsonArray arr:
                writer.WriteStartArray();
                foreach (var item in arr)
                {
                    if (item is null)
                    {
                        writer.WriteNullValue();
                    }
                    else
                    {
                        WriteCanonical(writer, item, remainingDepth - 1);
                    }
                }

                writer.WriteEndArray();
                break;

            default:
                node.WriteTo(writer);
                break;
        }
    }
}
