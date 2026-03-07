// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST;

using System;
using System.Collections.Generic;
using System.Formats.Cbor;

/// <summary>
/// Represents parsed CBOR problem details from RFC 9290 (Concise Problem Details).
/// </summary>
/// <remarks>
/// RFC 9290 defines standard fields for problem details in CBOR format,
/// returned by Azure Code Transparency Service with Content-Type:
/// <c>application/concise-problem-details+cbor</c>.
///
/// Standard CBOR integer keys:
/// <list type="table">
///   <item><term>-1</term><description>type (URI reference)</description></item>
///   <item><term>-2</term><description>title (human-readable summary)</description></item>
///   <item><term>-3</term><description>status (HTTP status code)</description></item>
///   <item><term>-4</term><description>detail (human-readable explanation)</description></item>
///   <item><term>-5</term><description>instance (URI reference for the occurrence)</description></item>
/// </list>
///
/// String keys (<c>"type"</c>, <c>"title"</c>, etc.) are also accepted for interoperability.
/// </remarks>
public class CborProblemDetails
{
    /// <summary>
    /// Gets or sets the problem type URI reference (CBOR key: -1 or "type").
    /// </summary>
    public string? Type { get; set; }

    /// <summary>
    /// Gets or sets a short human-readable summary of the problem (CBOR key: -2 or "title").
    /// </summary>
    public string? Title { get; set; }

    /// <summary>
    /// Gets or sets the HTTP status code (CBOR key: -3 or "status").
    /// </summary>
    public int? Status { get; set; }

    /// <summary>
    /// Gets or sets a human-readable explanation of the problem (CBOR key: -4 or "detail").
    /// </summary>
    public string? Detail { get; set; }

    /// <summary>
    /// Gets or sets a URI reference for the specific occurrence (CBOR key: -5 or "instance").
    /// </summary>
    public string? Instance { get; set; }

    /// <summary>
    /// Gets or sets additional extension fields not covered by the standard keys.
    /// </summary>
    public Dictionary<string, object?>? Extensions { get; set; }

    /// <summary>
    /// Parses CBOR-encoded problem details (RFC 9290) from a byte array.
    /// </summary>
    /// <param name="cborBytes">The CBOR-encoded problem details.</param>
    /// <returns>The parsed problem details, or <c>null</c> if parsing fails.</returns>
    public static CborProblemDetails? TryParse(byte[] cborBytes)
    {
        if (cborBytes == null || cborBytes.Length == 0)
        {
            return null;
        }

        try
        {
            var reader = new CborReader(cborBytes);
            return ParseFromReader(reader);
        }
        catch (CborContentException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// Parses CBOR problem details from a <see cref="CborReader"/> positioned at a map.
    /// </summary>
    private static CborProblemDetails? ParseFromReader(CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.StartMap)
        {
            return null;
        }

        var details = new CborProblemDetails();
        var extensions = new Dictionary<string, object?>();

        reader.ReadStartMap();

        while (reader.PeekState() != CborReaderState.EndMap)
        {
            var keyState = reader.PeekState();

            if (keyState == CborReaderState.NegativeInteger || keyState == CborReaderState.UnsignedInteger)
            {
                int key = reader.ReadInt32();
                switch (key)
                {
                    case -1: details.Type = ReadStringValue(reader); break;
                    case -2: details.Title = ReadStringValue(reader); break;
                    case -3: details.Status = ReadIntValue(reader); break;
                    case -4: details.Detail = ReadStringValue(reader); break;
                    case -5: details.Instance = ReadStringValue(reader); break;
                    default: extensions[$"key_{key}"] = ReadAnyValue(reader); break;
                }
            }
            else if (keyState == CborReaderState.TextString)
            {
                string key = reader.ReadTextString();
                switch (key.ToLowerInvariant())
                {
                    case "type": details.Type = ReadStringValue(reader); break;
                    case "title": details.Title = ReadStringValue(reader); break;
                    case "status": details.Status = ReadIntValue(reader); break;
                    case "detail": details.Detail = ReadStringValue(reader); break;
                    case "instance": details.Instance = ReadStringValue(reader); break;
                    default: extensions[key] = ReadAnyValue(reader); break;
                }
            }
            else
            {
                reader.SkipValue();
                reader.SkipValue();
            }
        }

        reader.ReadEndMap();

        if (extensions.Count > 0)
        {
            details.Extensions = extensions;
        }

        return details;
    }

    private static string? ReadStringValue(CborReader reader)
    {
        if (reader.PeekState() == CborReaderState.TextString)
        {
            return reader.ReadTextString();
        }

        if (reader.PeekState() == CborReaderState.Null) { reader.ReadNull(); return null; }
        reader.SkipValue();
        return null;
    }

    private static int? ReadIntValue(CborReader reader)
    {
        var state = reader.PeekState();
        if (state == CborReaderState.UnsignedInteger || state == CborReaderState.NegativeInteger)
        {
            return reader.ReadInt32();
        }

        if (state == CborReaderState.Null) { reader.ReadNull(); return null; }
        reader.SkipValue();
        return null;
    }

    private static object? ReadAnyValue(CborReader reader)
    {
        return reader.PeekState() switch
        {
            CborReaderState.TextString => reader.ReadTextString(),
            CborReaderState.ByteString => reader.ReadByteString(),
            CborReaderState.UnsignedInteger => reader.ReadInt64(),
            CborReaderState.NegativeInteger => reader.ReadInt64(),
            CborReaderState.Boolean => reader.ReadBoolean(),
            CborReaderState.Null => ReadNull(reader),
            CborReaderState.SinglePrecisionFloat => reader.ReadSingle(),
            CborReaderState.DoublePrecisionFloat => reader.ReadDouble(),
            CborReaderState.HalfPrecisionFloat => reader.ReadDouble(),
            _ => Skip(reader),
        };
    }

    private static object? ReadNull(CborReader reader) { reader.ReadNull(); return null; }
    private static object? Skip(CborReader reader) { reader.SkipValue(); return null; }

    /// <summary>
    /// Returns a human-readable summary of the problem details.
    /// </summary>
    public override string ToString()
    {
        var parts = new List<string>();
        if (!string.IsNullOrEmpty(Title))
        {
            parts.Add($"Title: {Title}");
        }

        if (Status.HasValue)
        {
            parts.Add($"Status: {Status}");
        }

        if (!string.IsNullOrEmpty(Detail))
        {
            parts.Add($"Detail: {Detail}");
        }

        if (!string.IsNullOrEmpty(Type))
        {
            parts.Add($"Type: {Type}");
        }

        if (!string.IsNullOrEmpty(Instance))
        {
            parts.Add($"Instance: {Instance}");
        }

        return parts.Count > 0 ? string.Join(", ", parts) : "No details available";
    }
}