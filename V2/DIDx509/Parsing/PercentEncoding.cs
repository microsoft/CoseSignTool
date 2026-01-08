// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Parsing;

using System;
using System.Text;

/// <summary>
/// Provides percent-encoding and decoding according to RFC 3986 and DID:X509 spec.
/// Allowed unencoded characters: ALPHA / DIGIT / "-" / "." / "_"
/// Note: Tilde (~) is NOT allowed unencoded per DID:X509 spec (differs from RFC 3986).
/// </summary>
public static class PercentEncoding
{
    internal static class ClassStrings
    {
        internal const string ByteToUpperHex2Format = "X2";
    }

    /// <summary>
    /// Encodes a string using percent-encoding per DID:X509 spec.
    /// Only ALPHA, DIGIT, '-', '.', '_' are allowed unencoded.
    /// </summary>
    /// <param name="value">The value to encode.</param>
    /// <returns>The encoded value.</returns>
    public static string Encode(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var encoded = new StringBuilder(value.Length * 2);

        foreach (char c in value)
        {
            if (IsDidX509AllowedCharacter(c))
            {
                encoded.Append(c);
            }
            else
            {
                // Encode as UTF-8 bytes
                byte[] bytes = Encoding.UTF8.GetBytes(new[] { c });
                foreach (byte b in bytes)
                {
                    encoded.Append(DidX509Constants.PercentChar);
                    encoded.Append(b.ToString(ClassStrings.ByteToUpperHex2Format));
                }
            }
        }

        return encoded.ToString();
    }

    /// <summary>
    /// Decodes a percent-encoded string.
    /// </summary>
    /// <param name="value">The value to decode.</param>
    /// <returns>The decoded value.</returns>
    public static string Decode(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        if (!value.Contains(DidX509Constants.PercentChar.ToString()))
        {
            return value;
        }

        var bytes = new System.Collections.Generic.List<byte>();
        var result = new StringBuilder(value.Length);

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];

            if (c == DidX509Constants.PercentChar && i + 2 < value.Length)
            {
                // Decode percent-encoded byte
                string hex = value.Substring(i + 1, 2);
                if (IsHexDigit(hex[0]) && IsHexDigit(hex[1]))
                {
                    byte b = Convert.ToByte(hex, 16);
                    bytes.Add(b);
                    i += 2;
                    continue;
                }
            }

            // Flush accumulated bytes if any
            if (bytes.Count > 0)
            {
                result.Append(Encoding.UTF8.GetString(bytes.ToArray()));
                bytes.Clear();
            }

            // Append non-encoded character
            result.Append(c);
        }

        // Flush remaining bytes
        if (bytes.Count > 0)
        {
            result.Append(Encoding.UTF8.GetString(bytes.ToArray()));
        }

        return result.ToString();
    }

    /// <summary>
    /// Checks if a character is allowed unencoded in DID:X509.
    /// Per spec: ALPHA / DIGIT / "-" / "." / "_"
    /// </summary>
    /// <param name="c">The character to check.</param>
    /// <returns><see langword="true"/> if the character is allowed; otherwise, <see langword="false"/>.</returns>
    public static bool IsDidX509AllowedCharacter(char c)
    {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == DidX509Constants.HyphenChar ||
               c == DidX509Constants.UnderscoreChar ||
               c == DidX509Constants.PeriodChar;
    }

    private static bool IsHexDigit(char c)
    {
        return (c >= '0' && c <= '9') ||
               (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    }
}