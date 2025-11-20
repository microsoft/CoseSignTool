// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Helpers;

/// <summary>
/// Parses CWT Claims from command-line argument strings.
/// </summary>
/// <remarks>
/// Supports parsing claims in the format: "label=value,label2=value2"
/// Labels must be integers (excluding reserved labels 1 and 2 for iss/sub).
/// Values are auto-typed as:
/// - Integers if parseable as int/long
/// - Booleans if "true" or "false" (case-insensitive)
/// - Byte arrays if prefixed with "0x" (hex string)
/// - Strings otherwise
/// 
/// Examples:
/// - "3=audience,4=1234567890" → aud (string), exp (int)
/// - "5=true,6=0x48656c6c6f" → boolean claim, byte array claim
/// </remarks>
public static class CwtClaimsParser
{
    /// <summary>
    /// Parses a comma-separated string of CWT claims into a dictionary.
    /// </summary>
    /// <param name="claimsString">The claims string in format "label=value,label2=value2". Labels can be integers or strings.</param>
    /// <returns>A dictionary of claim labels (int or string) to values.</returns>
    /// <exception cref="ArgumentException">Thrown when the format is invalid.</exception>
    public static Dictionary<object, object> ParseClaims(string? claimsString)
    {
        Dictionary<object, object> claims = new Dictionary<object, object>();

        if (string.IsNullOrWhiteSpace(claimsString))
        {
            return claims;
        }

        // Split by comma
        string[] claimPairs = claimsString.Split(',');

        foreach (string claimPair in claimPairs)
        {
            if (string.IsNullOrWhiteSpace(claimPair))
            {
                continue;
            }

            // Split by equals sign
            string[] parts = claimPair.Split(new[] { '=' }, 2);
            if (parts.Length != 2)
            {
                throw new ArgumentException(
                    $"Invalid claim format: '{claimPair}'. Expected format: 'label=value'",
                    nameof(claimsString));
            }

            string labelStr = parts[0].Trim();
            string valueStr = parts[1].Trim();

            // Try to parse label as integer first, otherwise treat as string
            object label;
            if (int.TryParse(labelStr, out int intLabel))
            {
                // Validate integer label is not reserved and non-negative
                if (intLabel == CWTClaimsHeaderLabels.Issuer)
                {
                    throw new ArgumentException(
                        $"Claim label {intLabel} is reserved for issuer (iss). Use --cwt-issuer instead.",
                        nameof(claimsString));
                }

                if (intLabel == CWTClaimsHeaderLabels.Subject)
                {
                    throw new ArgumentException(
                        $"Claim label {intLabel} is reserved for subject (sub). Use --cwt-subject instead.",
                        nameof(claimsString));
                }

                label = intLabel;
            }
            else
            {
                // String label - validate it's not a reserved string
                if (labelStr.Equals("iss", StringComparison.OrdinalIgnoreCase) ||
                    labelStr.Equals("sub", StringComparison.OrdinalIgnoreCase))
                {
                    throw new ArgumentException(
                        $"Claim label '{labelStr}' is reserved. Use --cwt-issuer or --cwt-subject instead.",
                        nameof(claimsString));
                }

                label = labelStr;
            }

            // Parse value with type inference
            object value = InferValueType(valueStr, claimsString);

            claims[label] = value;
        }

        return claims;
    }

    /// <summary>
    /// Infers the type of a value string and parses it accordingly.
    /// </summary>
    /// <param name="valueStr">The string value to parse.</param>
    /// <param name="originalString">The original claims string for error reporting.</param>
    /// <returns>The parsed value as int, long, bool, byte[], or string.</returns>
    private static object InferValueType(string valueStr, string originalString)
    {
        // Check for hex byte array (0x prefix)
        if (valueStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return ParseHexByteArray(valueStr, originalString);
        }

        // Check for boolean
        if (bool.TryParse(valueStr, out bool boolValue))
        {
            return boolValue;
        }

        // Check for integer (int32)
        if (int.TryParse(valueStr, out int intValue))
        {
            return intValue;
        }

        // Check for long integer (int64)
        if (long.TryParse(valueStr, out long longValue))
        {
            return longValue;
        }

        // Default to string
        return valueStr;
    }

    /// <summary>
    /// Parses a hexadecimal string into a byte array.
    /// </summary>
    /// <param name="hexString">The hex string (with or without "0x" prefix).</param>
    /// <param name="originalString">The original claims string for error reporting.</param>
    /// <returns>The parsed byte array.</returns>
    private static byte[] ParseHexByteArray(string hexString, string originalString)
    {
        // Remove 0x prefix
        string hex = hexString.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? hexString.Substring(2)
            : hexString;

        // Validate length is even
        if (hex.Length % 2 != 0)
        {
            throw new ArgumentException(
                $"Invalid hex string: '{hexString}'. Hex strings must have an even number of characters.",
                nameof(originalString));
        }

        // Parse hex string
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            string byteStr = hex.Substring(i * 2, 2);
            if (!byte.TryParse(byteStr, System.Globalization.NumberStyles.HexNumber, null, out bytes[i]))
            {
                throw new ArgumentException(
                    $"Invalid hex string: '{hexString}'. Contains non-hexadecimal characters.",
                    nameof(originalString));
            }
        }

        return bytes;
    }

    /// <summary>
    /// Validates that a claims dictionary does not contain reserved labels.
    /// </summary>
    /// <param name="claims">The claims dictionary to validate.</param>
    /// <exception cref="ArgumentException">Thrown if reserved labels are present.</exception>
    public static void ValidateClaims(Dictionary<object, object> claims)
    {
        // Check for reserved integer and string labels
        foreach (object key in claims.Keys)
        {
            if (key is int intLabel)
            {
                if (intLabel == CWTClaimsHeaderLabels.Issuer)
                {
                    throw new ArgumentException(
                        $"Claim label {CWTClaimsHeaderLabels.Issuer} is reserved for issuer (iss). Use --cwt-issuer instead.");
                }

                if (intLabel == CWTClaimsHeaderLabels.Subject)
                {
                    throw new ArgumentException(
                        $"Claim label {CWTClaimsHeaderLabels.Subject} is reserved for subject (sub). Use --cwt-subject instead.");
                }
            }
            else if (key is string strLabel)
            {
                if (strLabel.Equals("iss", StringComparison.OrdinalIgnoreCase) ||
                    strLabel.Equals("sub", StringComparison.OrdinalIgnoreCase))
                {
                    throw new ArgumentException($"Claim label '{strLabel}' is reserved. Use --cwt-issuer or --cwt-subject instead.");
                }
            }
        }
    }

    /// <summary>
    /// Gets a human-readable description of supported claim value types.
    /// </summary>
    public static string SupportedTypesDescription => 
        "Supported types: integers (int32/int64), booleans (true/false), byte arrays (0xHEX), strings (default)";
}
