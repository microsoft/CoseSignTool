// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Extensions;

/// <summary>
/// Extension methods for working with COSE headers.
/// </summary>
public static class CoseHeaderExtensions
{
    /// <summary>
    /// Converts a collection of CoseHeader{T} to a CoseHeaderMap.
    /// </summary>
    /// <typeparam name="T">The type of the header values.</typeparam>
    /// <param name="headers">The collection of headers to convert.</param>
    /// <returns>A new CoseHeaderMap containing the headers.</returns>
    /// <exception cref="ArgumentNullException">Thrown when headers is null.</exception>
    public static CoseHeaderMap ToCoseHeaderMap<T>(this IEnumerable<CoseHeader<T>> headers)
    {
        if (headers == null)
        {
            throw new ArgumentNullException(nameof(headers));
        }

        CoseHeaderMap headerMap = new();
        
        foreach (var header in headers)
        {
            if (header?.Label == null)
            {
                continue;
            }

            CoseHeaderLabel label = new(header.Label);
            CoseHeaderValue value = CreateCoseHeaderValue(header.Value);
            headerMap.Add(label, value);
        }

        return headerMap;
    }

    /// <summary>
    /// Converts a collection of CoseHeader{T} to a CoseHeaderMap, merging with an existing map.
    /// </summary>
    /// <typeparam name="T">The type of the header values.</typeparam>
    /// <param name="headers">The collection of headers to convert.</param>
    /// <param name="existingHeaderMap">The existing header map to merge with. If null, a new map is created.</param>
    /// <returns>A CoseHeaderMap containing the merged headers.</returns>
    /// <exception cref="ArgumentNullException">Thrown when headers is null.</exception>
    public static CoseHeaderMap ToCoseHeaderMap<T>(this IEnumerable<CoseHeader<T>> headers, CoseHeaderMap? existingHeaderMap)
    {
        if (headers == null)
        {
            throw new ArgumentNullException(nameof(headers));
        }

        CoseHeaderMap targetMap = existingHeaderMap ?? new CoseHeaderMap();
        
        foreach (var header in headers)
        {
            if (header?.Label == null)
            {
                continue;
            }

            CoseHeaderLabel label = new(header.Label);
            CoseHeaderValue value = CreateCoseHeaderValue(header.Value);
            targetMap[label] = value; // Use indexer to overwrite if key exists
        }

        return targetMap;
    }

    /// <summary>
    /// Merges another CoseHeaderMap into this one.
    /// </summary>
    /// <param name="targetMap">The target map to merge into.</param>
    /// <param name="sourceMap">The source map to merge from. If null, returns the target map unchanged.</param>
    /// <returns>The target map with merged headers.</returns>
    /// <exception cref="ArgumentNullException">Thrown when targetMap is null.</exception>
    public static CoseHeaderMap MergeHeaderMap(this CoseHeaderMap targetMap, CoseHeaderMap? sourceMap)
    {
        if (targetMap == null)
        {
            throw new ArgumentNullException(nameof(targetMap));
        }

        if (sourceMap == null)
        {
            return targetMap;
        }

        foreach (var kvp in sourceMap)
        {
            targetMap[kvp.Key] = kvp.Value;
        }

        return targetMap;
    }

    /// <summary>
    /// Creates a CoseHeaderValue from the given value based on its type.
    /// </summary>
    /// <param name="value">The value to convert.</param>
    /// <returns>A CoseHeaderValue representing the value.</returns>
    /// <exception cref="ArgumentException">Thrown when the value type is not supported.</exception>
    private static CoseHeaderValue CreateCoseHeaderValue<T>(T? value)
    {
        return value switch
        {
            int intValue => CoseHeaderValue.FromInt32(intValue),
            string stringValue when !string.IsNullOrEmpty(stringValue) => CoseHeaderValue.FromString(stringValue),
            string => throw new ArgumentException("Header string value cannot be null or empty."),
            null => throw new ArgumentException("Header value cannot be null."),
            _ => throw new ArgumentException($"Unsupported header value type: {typeof(T)}")
        };
    }
}
