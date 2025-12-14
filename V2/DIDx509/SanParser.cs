// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509;

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DIDx509.Models;
#if NET10_0_OR_GREATER
using System.Formats.Asn1;
#endif

/// <summary>
/// Cross-platform Subject Alternative Name (SAN) extension parser.
/// Uses ASN.1 parsing on .NET 10+ for platform independence.
/// </summary>
internal static class SanParser
{
    /// <summary>
    /// Static string constants for the SanParser class.
    /// </summary>
    internal static class ClassStrings
    {
        // Windows-style format prefixes
        public const string WindowsDnsNamePrefix = "DNS Name=";
        public const string WindowsRfc822NamePrefix = "RFC822 Name=";
        public const string WindowsEmailPrefix = "Email=";
        public const string WindowsUrlPrefix = "URL=";
        public const string WindowsUriPrefix = "URI=";

        // Linux OpenSSL-style format prefixes
        public const string LinuxDnsPrefix = "DNS:";
        public const string LinuxEmailPrefix = "email:";
        public const string LinuxUriPrefix = "URI:";
    }

    // ASN.1 context-specific tags for GeneralName (RFC 5280)
    private const int TagRfc822Name = 1;      // email (IA5String)
    private const int TagDnsName = 2;         // DNS (IA5String)
    private const int TagUniformResourceIdentifier = 6;  // URI (IA5String)

    /// <summary>
    /// Parses a SAN extension and returns a list of SubjectAlternativeName entries.
    /// </summary>
    /// <param name="extension">The SAN X509Extension.</param>
    /// <returns>List of parsed SAN entries.</returns>
    public static List<SubjectAlternativeName> Parse(X509Extension extension)
    {
        if (extension == null)
        {
            throw new ArgumentNullException(nameof(extension));
        }

#if NET10_0_OR_GREATER
        return ParseUsingAsnReader(extension.RawData);
#else
        return ParseUsingFormattedString(extension);
#endif
    }

    /// <summary>
    /// Gets the first SAN entry matching the optional type filter.
    /// </summary>
    /// <param name="extension">The SAN X509Extension.</param>
    /// <param name="sanType">Optional SAN type filter (dns, email, uri). Null means any type.</param>
    /// <returns>A tuple of (type, value) or null if no match found.</returns>
    public static (string Type, string Value)? GetFirstSan(X509Extension extension, string? sanType = null)
    {
        var sans = Parse(extension);

        foreach (var san in sans)
        {
            if (sanType == null || string.Equals(san.Type, sanType, StringComparison.OrdinalIgnoreCase))
            {
                // Only return string-typed SAN values (email, dns, uri)
                if (san.ValueAsString is string stringValue)
                {
                    return (san.Type, stringValue);
                }
            }
        }

        return null;
    }

#if NET10_0_OR_GREATER
    /// <summary>
    /// Parses SAN extension using AsnReader for cross-platform compatibility.
    /// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    /// GeneralName ::= CHOICE {
    ///    otherName                       [0] OtherName,
    ///    rfc822Name                      [1] IA5String,
    ///    dNSName                         [2] IA5String,
    ///    x400Address                     [3] ORAddress,
    ///    directoryName                   [4] Name,
    ///    ediPartyName                    [5] EDIPartyName,
    ///    uniformResourceIdentifier       [6] IA5String,
    ///    iPAddress                       [7] OCTET STRING,
    ///    registeredID                    [8] OBJECT IDENTIFIER }
    /// </summary>
    private static List<SubjectAlternativeName> ParseUsingAsnReader(byte[] rawData)
    {
        var sans = new List<SubjectAlternativeName>();

        try
        {
            var reader = new AsnReader(rawData, AsnEncodingRules.DER);
            var sequenceReader = reader.ReadSequence();

            while (sequenceReader.HasData)
            {
                var tag = sequenceReader.PeekTag();

                // Context-specific tags for GeneralName choices
                if (tag.TagClass == TagClass.ContextSpecific)
                {
                    ReadOnlyMemory<byte> valueBytes = sequenceReader.ReadEncodedValue();
                    string? type = null;
                    string? value = null;

                    // Skip the tag byte and length byte(s) to get the actual value
                    var valueSpan = valueBytes.Span;
                    int headerLen = GetAsn1HeaderLength(valueSpan);
                    var actualValue = valueSpan.Slice(headerLen);

                    switch (tag.TagValue)
                    {
                        case TagRfc822Name:
                            type = DidX509Constants.SanTypeEmail;
                            value = Encoding.ASCII.GetString(actualValue);
                            break;
                        case TagDnsName:
                            type = DidX509Constants.SanTypeDns;
                            value = Encoding.ASCII.GetString(actualValue);
                            break;
                        case TagUniformResourceIdentifier:
                            type = DidX509Constants.SanTypeUri;
                            value = Encoding.ASCII.GetString(actualValue);
                            break;
                    }

                    if (type != null && value != null)
                    {
                        sans.Add(new SubjectAlternativeName(type, value));
                    }
                }
                else
                {
                    // Skip unsupported tag types
                    sequenceReader.ReadEncodedValue();
                }
            }
        }
        catch
        {
            // If ASN.1 parsing fails, return empty list
        }

        return sans;
    }

    /// <summary>
    /// Gets the length of ASN.1 header (tag + length bytes).
    /// </summary>
    private static int GetAsn1HeaderLength(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return 0;
        }

        int lengthByte = data[1];
        if (lengthByte < 0x80)
        {
            // Short form: 1 tag byte + 1 length byte
            return 2;
        }
        else
        {
            // Long form: 1 tag byte + 1 length-of-length byte + N length bytes
            int numLengthBytes = lengthByte & 0x7F;
            return 2 + numLengthBytes;
        }
    }
#endif

    /// <summary>
    /// Fallback parser using Format() for netstandard2.0.
    /// Note: This may have platform-specific differences.
    /// </summary>
    private static List<SubjectAlternativeName> ParseUsingFormattedString(X509Extension extension)
    {
        var sans = new List<SubjectAlternativeName>();

        try
        {
            string formatted = extension.Format(false);

            // Handle both comma-separated (Linux) and newline-separated (Windows) formats
            var entries = formatted.Split(new[] { '\r', '\n', ',' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var entry in entries)
            {
                string trimmed = entry.Trim();
                string? type = null;
                string? value = null;

                // Windows format: "DNS Name=example.com", "RFC822 Name=user@example.com"
                // Linux OpenSSL format may differ: "DNS:example.com", "email:user@example.com"
                if (TryParseWindowsFormat(trimmed, out type, out value) ||
                    TryParseLinuxFormat(trimmed, out type, out value))
                {
                    if (type != null && !string.IsNullOrEmpty(value))
                    {
                        sans.Add(new SubjectAlternativeName(type, value));
                    }
                }
            }
        }
        catch
        {
            // Ignore parsing errors
        }

        return sans;
    }

    /// <summary>
    /// Tries to parse Windows-style formatted SAN entries.
    /// </summary>
    private static bool TryParseWindowsFormat(string entry, out string? type, out string? value)
    {
        type = null;
        value = null;

        if (entry.StartsWith(ClassStrings.WindowsDnsNamePrefix, StringComparison.OrdinalIgnoreCase))
        {
            type = DidX509Constants.SanTypeDns;
            value = entry.Substring(ClassStrings.WindowsDnsNamePrefix.Length);
            return true;
        }
        else if (entry.StartsWith(ClassStrings.WindowsRfc822NamePrefix, StringComparison.OrdinalIgnoreCase))
        {
            type = DidX509Constants.SanTypeEmail;
            value = entry.Substring(ClassStrings.WindowsRfc822NamePrefix.Length);
            return true;
        }
        else if (entry.StartsWith(ClassStrings.WindowsEmailPrefix, StringComparison.OrdinalIgnoreCase))
        {
            type = DidX509Constants.SanTypeEmail;
            value = entry.Substring(ClassStrings.WindowsEmailPrefix.Length);
            return true;
        }
        else if (entry.StartsWith(ClassStrings.WindowsUrlPrefix, StringComparison.OrdinalIgnoreCase))
        {
            type = DidX509Constants.SanTypeUri;
            value = entry.Substring(ClassStrings.WindowsUrlPrefix.Length);
            return true;
        }
        else if (entry.StartsWith(ClassStrings.WindowsUriPrefix, StringComparison.OrdinalIgnoreCase))
        {
            type = DidX509Constants.SanTypeUri;
            value = entry.Substring(ClassStrings.WindowsUriPrefix.Length);
            return true;
        }

        return false;
    }

    /// <summary>
    /// Tries to parse Linux OpenSSL-style formatted SAN entries.
    /// OpenSSL typically uses "DNS:value", "email:value", "URI:value" format.
    /// </summary>
    private static bool TryParseLinuxFormat(string entry, out string? type, out string? value)
    {
        type = null;
        value = null;

        // OpenSSL format: "DNS:example.com"
        if (entry.StartsWith(ClassStrings.LinuxDnsPrefix, StringComparison.OrdinalIgnoreCase))
        {
            type = DidX509Constants.SanTypeDns;
            value = entry.Substring(ClassStrings.LinuxDnsPrefix.Length);
            return true;
        }
        else if (entry.StartsWith(ClassStrings.LinuxEmailPrefix, StringComparison.OrdinalIgnoreCase))
        {
            type = DidX509Constants.SanTypeEmail;
            value = entry.Substring(ClassStrings.LinuxEmailPrefix.Length);
            return true;
        }
        else if (entry.StartsWith(ClassStrings.LinuxUriPrefix, StringComparison.OrdinalIgnoreCase))
        {
            type = DidX509Constants.SanTypeUri;
            value = entry.Substring(ClassStrings.LinuxUriPrefix.Length);
            return true;
        }

        return false;
    }
}
