// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Helpers;

using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using CoseSign1.Headers;
using CoseSign1.Headers.Extensions;
using Microsoft.Extensions.Configuration;

/// <summary>
/// Shared helper for adding custom COSE headers whose values are raw CBOR supplied as base64.
/// </summary>
/// <remarks>
/// <para>
/// The int and string header options carry values the tool encodes on the caller's behalf, which
/// cannot express an already-encoded CBOR structure. This helper accepts the encoded bytes directly,
/// so a producer that owns its own CBOR representation — for example an existing vendor signature
/// blob being carried alongside the COSE signature — can place it in a dedicated header without
/// CoseSignTool needing to understand its schema.
/// </para>
/// <para>
/// Values are base64 so they survive a command line intact. Each decoded value must be exactly one
/// well-formed CBOR data item; anything else is rejected during parsing rather than producing a
/// signature with an undecodable header.
/// </para>
/// </remarks>
public static class CborHeaderHelper
{
    /// <summary>
    /// Header options that can be used in command definitions.
    /// </summary>
    public static readonly Dictionary<string, string> HeaderOptions = new()
    {
        { "cbor-protected-headers", "Comma-separated list of protected headers whose CBOR values are base64 encoded (format: label=base64)" },
        { "cbor-unprotected-headers", "Comma-separated list of unprotected headers whose CBOR values are base64 encoded (format: label=base64)" }
    };

    /// <summary>
    /// Creates a header extender that adds the supplied CBOR-valued headers.
    /// </summary>
    /// <param name="protectedHeaders">Protected header specifications in <c>label=base64</c> form.</param>
    /// <param name="unProtectedHeaders">Unprotected header specifications in <c>label=base64</c> form.</param>
    /// <returns>A <see cref="CoseHeaderExtender"/>, or null when no headers were supplied.</returns>
    /// <exception cref="ArgumentException">Thrown when a specification is malformed, the value is not valid base64, or the decoded value is not a single well-formed CBOR data item.</exception>
    /// <example>
    /// <code>
    /// // Adds protected header 4242 carrying a CBOR byte string.
    /// CborHeaderHelper.CreateHeaderExtender(new[] { "4242=RAECAwQ=" }, null);
    /// </code>
    /// </example>
    public static CoseHeaderExtender? CreateHeaderExtender(
        IEnumerable<string>? protectedHeaders,
        IEnumerable<string>? unProtectedHeaders)
    {
        CoseHeaderMap? protectedMap = BuildHeaderMap(protectedHeaders);
        CoseHeaderMap? unProtectedMap = BuildHeaderMap(unProtectedHeaders);

        if (protectedMap is null && unProtectedMap is null)
        {
            return null;
        }

        return new CoseHeaderExtender(
            (existingProtectedHeaderMap) => protectedMap?.MergeHeaderMap(existingProtectedHeaderMap) ?? existingProtectedHeaderMap,
            (existingUnprotectedHeaderMap) => unProtectedMap?.MergeHeaderMap(existingUnprotectedHeaderMap) ?? existingUnprotectedHeaderMap);
    }

    /// <summary>
    /// Creates a header extender from the <c>cbor-protected-headers</c> and <c>cbor-unprotected-headers</c> configuration values.
    /// </summary>
    /// <param name="configuration">The configuration containing the header specifications.</param>
    /// <returns>A <see cref="CoseHeaderExtender"/>, or null when no headers were supplied.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configuration"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when a specification is malformed or its value is not valid CBOR.</exception>
    public static CoseHeaderExtender? CreateHeaderExtender(IConfiguration configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        return CreateHeaderExtender(
            SplitSpecifications(configuration["cbor-protected-headers"]),
            SplitSpecifications(configuration["cbor-unprotected-headers"]));
    }

    /// <summary>
    /// Gets the CBOR header usage documentation for command help.
    /// </summary>
    public static string HeaderUsage => $"{Environment.NewLine}" +
           $"CBOR header options (optional):{Environment.NewLine}" +
           $"  --cbor-protected-headers   Comma-separated protected headers with base64-encoded CBOR values (format: label=base64){Environment.NewLine}" +
           $"  --cbor-unprotected-headers Comma-separated unprotected headers with base64-encoded CBOR values (format: label=base64){Environment.NewLine}" +
           $"                             Labels may be integers (e.g. 4242) or strings (e.g. vendor-signature).{Environment.NewLine}";

    /// <summary>
    /// Splits a comma-separated option value into individual header specifications.
    /// </summary>
    /// <param name="value">The raw option value.</param>
    /// <returns>The individual specifications, or null when the value is empty.</returns>
    private static IEnumerable<string>? SplitSpecifications(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? null
            : value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    /// <summary>
    /// Builds a <see cref="CoseHeaderMap"/> from <c>label=base64</c> specifications.
    /// </summary>
    /// <param name="specifications">The specifications to parse.</param>
    /// <returns>The populated map, or null when no specifications were supplied.</returns>
    private static CoseHeaderMap? BuildHeaderMap(IEnumerable<string>? specifications)
    {
        if (specifications is null)
        {
            return null;
        }

        CoseHeaderMap headerMap = new();
        int count = 0;

        foreach (string specification in specifications)
        {
            if (string.IsNullOrWhiteSpace(specification))
            {
                continue;
            }

            string[] parts = specification.Split('=', 2);
            if (parts.Length != 2)
            {
                throw new ArgumentException($"Invalid CBOR header format '{specification}'. Expected 'label=base64'.", nameof(specifications));
            }

            string label = parts[0].Trim();
            string encodedValue = parts[1].Trim();

            if (label.Length == 0)
            {
                throw new ArgumentException($"CBOR header label cannot be empty in '{specification}'.", nameof(specifications));
            }

            headerMap[CreateLabel(label)] = CoseHeaderValue.FromEncodedValue(DecodeCborValue(label, encodedValue));
            count++;
        }

        return count > 0 ? headerMap : null;
    }

    /// <summary>
    /// Creates a <see cref="CoseHeaderLabel"/> from a label that may be an integer or a string.
    /// </summary>
    /// <param name="label">The label text.</param>
    /// <returns>An integer label when the text parses as an integer, otherwise a string label.</returns>
    private static CoseHeaderLabel CreateLabel(string label)
    {
        return int.TryParse(label, out int intLabel)
            ? new CoseHeaderLabel(intLabel)
            : new CoseHeaderLabel(label);
    }

    /// <summary>
    /// Decodes a base64 header value and verifies it is exactly one well-formed CBOR data item.
    /// </summary>
    /// <param name="label">The header label, used for error reporting.</param>
    /// <param name="encodedValue">The base64 text to decode.</param>
    /// <returns>The decoded CBOR bytes.</returns>
    /// <exception cref="ArgumentException">Thrown when the value is not valid base64 or not a single well-formed CBOR data item.</exception>
    private static byte[] DecodeCborValue(string label, string encodedValue)
    {
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(encodedValue);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException($"CBOR header '{label}' does not contain a valid base64 value: {ex.Message}", nameof(encodedValue), ex);
        }

        if (decoded.Length == 0)
        {
            throw new ArgumentException($"CBOR header '{label}' decoded to an empty value.", nameof(encodedValue));
        }

        try
        {
            CborReader reader = new(decoded);
            reader.SkipValue();

            if (reader.BytesRemaining != 0)
            {
                throw new ArgumentException(
                    $"CBOR header '{label}' must contain exactly one CBOR data item but has {reader.BytesRemaining} trailing byte(s).",
                    nameof(encodedValue));
            }
        }
        catch (CborContentException ex)
        {
            throw new ArgumentException($"CBOR header '{label}' does not contain well-formed CBOR: {ex.Message}", nameof(encodedValue), ex);
        }

        return decoded;
    }
}
