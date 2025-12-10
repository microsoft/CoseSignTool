// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Extensions;

using System.Diagnostics;
using System.Reflection;

/// <summary>
/// Extension methods for working with COSE headers.
/// </summary>
public static class CoseHeaderExtensions
{
    /// <summary>
    /// Constant for unknown or custom header label representation.
    /// </summary>
    private const string CustomLabelString = "custom";
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
    /// <param name="overwriteConflicts">
    /// If true (default), source map values will overwrite target map values when keys conflict.
    /// If false, existing target map values are preserved and conflicting source values are ignored.
    /// </param>
    /// <returns>The target map with merged headers.</returns>
    /// <remarks>
    /// When <paramref name="overwriteConflicts"/> is true, any header keys that exist in both maps
    /// will have their values replaced by the source map values. When false, the target map values
    /// are preserved and the conflicting source values are silently ignored.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when targetMap is null.</exception>
    public static CoseHeaderMap MergeHeaderMap(this CoseHeaderMap targetMap, CoseHeaderMap? sourceMap, bool overwriteConflicts = true)
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
            if (overwriteConflicts || !targetMap.ContainsKey(kvp.Key))
            {
                targetMap[kvp.Key] = kvp.Value;
            }
        }

        return targetMap;
    }

    /// <summary>
    /// Extracts and parses CWT claims from a CoseHeaderMap.
    /// </summary>
    /// <param name="headerMap">The header map to extract CWT claims from.</param>
    /// <param name="claims">When this method returns, contains the extracted CWT claims if successful; otherwise, null.</param>
    /// <param name="headerLabel">Optional custom header label to use instead of the default CWT Claims label (15). If not specified, uses CWTClaimsHeaderLabels.CWTClaims.</param>
    /// <returns>true if CWT claims were found and successfully parsed; otherwise, false.</returns>
    public static bool TryGetCwtClaims(this CoseHeaderMap headerMap, out CwtClaims? claims, CoseHeaderLabel? headerLabel = null)
    {
        claims = null;
        
        CoseHeaderLabel label = headerLabel ?? CWTClaimsHeaderLabels.CWTClaims;
        
        if (headerMap == null || !headerMap.TryGetValue(label, out CoseHeaderValue cwtClaimsValue))
        {
            return false;
        }

        try
        {
            byte[] claimsBytes = cwtClaimsValue.EncodedValue.ToArray();
            claims = CwtClaims.FromCborBytes(claimsBytes);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Merges CWT claims into a CoseHeaderMap, combining with any existing CWT claims.
    /// User-provided claims override existing defaults.
    /// </summary>
    /// <param name="headerMap">The header map to merge CWT claims into.</param>
    /// <param name="newClaims">The new claims to merge in.</param>
    /// <param name="logOverrides">Whether to log when user values override defaults.</param>
    /// <param name="headerLabel">Optional custom header label to use instead of the default CWT Claims label (15). If not specified, uses CWTClaimsHeaderLabels.CWTClaims.</param>
    /// <returns>The updated header map with merged CWT claims.</returns>
    /// <remarks>
    /// TODO: Replace logOverrides boolean with ILogger-based logging controlled by standard log levels.
    /// This will allow better integration with the logging infrastructure and removal of this condition.
    /// </remarks>
    public static CoseHeaderMap MergeCwtClaims(this CoseHeaderMap headerMap, CwtClaims newClaims, bool logOverrides = true, CoseHeaderLabel? headerLabel = null)
    {
        if (headerMap == null)
        {
            throw new ArgumentNullException(nameof(headerMap));
        }

        if (newClaims == null)
        {
            return headerMap;
        }

        // Get existing claims if any
        headerMap.TryGetCwtClaims(out CwtClaims? existingClaims, headerLabel);

        // Merge claims: existing claims as base, new claims override
        CwtClaims mergedClaims = existingClaims?.Merge(newClaims, logOverrides) ?? newClaims;

        // Set the merged claims
        headerMap.SetCwtClaims(mergedClaims, headerLabel);
        return headerMap;
    }

    /// <summary>
    /// Sets CWT claims in a CoseHeaderMap, encoding them as CBOR.
    /// </summary>
    /// <param name="headerMap">The header map to set CWT claims in.</param>
    /// <param name="claims">The claims to encode and set.</param>
    /// <param name="headerLabel">Optional custom header label to use instead of the default CWT Claims label (15). If not specified, uses CWTClaimsHeaderLabels.CWTClaims.</param>
    /// <returns>The updated header map.</returns>
    public static CoseHeaderMap SetCwtClaims(this CoseHeaderMap headerMap, CwtClaims claims, CoseHeaderLabel? headerLabel = null)
    {
        if (headerMap == null)
        {
            throw new ArgumentNullException(nameof(headerMap));
        }

        if (claims == null)
        {
            return headerMap;
        }

        CoseHeaderLabel label = headerLabel ?? CWTClaimsHeaderLabels.CWTClaims;

        // Use CwtClaims.ToCborBytes to encode
        byte[] cborBytes = claims.ToCborBytes();
        CoseHeaderValue cwtClaimsValue = CoseHeaderValue.FromEncodedValue(cborBytes);
        headerMap[label] = cwtClaimsValue;

        return headerMap;
    }

    /// <summary>
    /// Formats a CoseHeaderLabel for human-readable output using reflection.
    /// </summary>
    /// <param name="label">The header label to format.</param>
    /// <returns>A string representation of the label (integer or string value), or "custom" if the value cannot be determined.</returns>
    /// <remarks>
    /// This method uses reflection to access the internal properties of CoseHeaderLabel:
    /// LabelAsInt32 for integer labels and LabelAsString for string labels.
    /// </remarks>
    public static string ToLabelString(this CoseHeaderLabel label)
    {
        if (label == null)
        {
            return "null";
        }

        try
        {
            // Try to get LabelAsInt32 property
            var labelAsInt32Property = label.GetType().GetProperty("LabelAsInt32", 
                BindingFlags.Instance | BindingFlags.NonPublic);
            
            if (labelAsInt32Property != null)
            {
                var intValue = labelAsInt32Property.GetValue(label);
                if (intValue != null)
                {
                    return intValue.ToString() ?? CustomLabelString;
                }
            }

            // Try to get LabelAsString property
            var labelAsStringProperty = label.GetType().GetProperty("LabelAsString",
                BindingFlags.Instance | BindingFlags.NonPublic);
            
            if (labelAsStringProperty != null)
            {
                var stringValue = labelAsStringProperty.GetValue(label);
                if (stringValue != null)
                {
                    return stringValue.ToString() ?? CustomLabelString;
                }
            }
        }
        catch (Exception ex) when (ex is TargetException 
                                    or TargetInvocationException 
                                    or ArgumentException 
                                    or MemberAccessException)
        {
            // If reflection fails, fall back to generic description
        }
        
        return CustomLabelString;
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
