// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.CertificateChain;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DIDx509.Models;

/// <summary>
/// Converts X.509 certificate chains to the DID:X509 JSON data model.
/// </summary>
public static class CertificateChainConverter
{
    /// <summary>
    /// Converts a certificate chain to the DID:X509 JSON data model.
    /// </summary>
    /// <param name="certificates">The certificate chain (leaf first).</param>
    /// <returns>A certificate chain model.</returns>
    public static CertificateChainModel Convert(IEnumerable<X509Certificate2> certificates)
    {
        if (certificates == null)
        {
            throw new ArgumentNullException(nameof(certificates));
        }

        var certArray = certificates.ToArray();
        if (certArray.Length < 2)
        {
            throw new ArgumentException("Certificate chain must contain at least 2 certificates", nameof(certificates));
        }

        var certInfos = new List<CertificateInfo>();
        foreach (var cert in certArray)
        {
            certInfos.Add(ConvertCertificate(cert));
        }

        return new CertificateChainModel(certInfos);
    }

    /// <summary>
    /// Converts a single certificate to the data model.
    /// </summary>
    private static CertificateInfo ConvertCertificate(X509Certificate2 certificate)
    {
        var fingerprints = ComputeFingerprints(certificate);
        var issuer = ParseX509Name(certificate.IssuerName);
        var subject = ParseX509Name(certificate.SubjectName);
        var extensions = ParseExtensions(certificate);

        return new CertificateInfo(fingerprints, issuer, subject, extensions, certificate);
    }

    /// <summary>
    /// Computes certificate fingerprints for all supported hash algorithms.
    /// </summary>
    private static CertificateFingerprints ComputeFingerprints(X509Certificate2 certificate)
    {
        byte[] rawData = certificate.RawData;

#if NET10_0_OR_GREATER
        byte[] sha256Hash = SHA256.HashData(rawData);
        byte[] sha384Hash = SHA384.HashData(rawData);
        byte[] sha512Hash = SHA512.HashData(rawData);
#else
        byte[] sha256Hash;
        byte[] sha384Hash;
        byte[] sha512Hash;

        using (var sha256 = SHA256.Create())
        {
            sha256Hash = sha256.ComputeHash(rawData);
        }

        using (var sha384 = SHA384.Create())
        {
            sha384Hash = sha384.ComputeHash(rawData);
        }

        using (var sha512 = SHA512.Create())
        {
            sha512Hash = sha512.ComputeHash(rawData);
        }
#endif

        return new CertificateFingerprints(
            ConvertToBase64Url(sha256Hash),
            ConvertToBase64Url(sha384Hash),
            ConvertToBase64Url(sha512Hash));
    }

    /// <summary>
    /// Converts bytes to base64url encoding (RFC 4648 Section 5).
    /// </summary>
    private static string ConvertToBase64Url(byte[] data)
    {
        string base64 = System.Convert.ToBase64String(data);
        return base64.Replace(DidX509Constants.PlusChar, DidX509Constants.HyphenChar)
                     .Replace(DidX509Constants.SlashChar, DidX509Constants.UnderscoreChar)
                     .TrimEnd('=');
    }

    /// <summary>
    /// Parses an X.509 Distinguished Name into the data model.
    /// </summary>
    private static X509Name ParseX509Name(X500DistinguishedName distinguishedName)
    {
        var attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Format as RFC 4514 (single line)
        string rfc4514 = distinguishedName.Format(false);

        // Parse components
        var components = SplitRFC4514Components(rfc4514);
        foreach (var component in components)
        {
            int equalIndex = component.IndexOf(DidX509Constants.EqualChar);
            if (equalIndex > 0 && equalIndex < component.Length - 1)
            {
                string key = component.Substring(0, equalIndex).Trim();
                string value = component.Substring(equalIndex + 1).Trim();

                // Unescape RFC 4514 value
                value = UnescapeRFC4514Value(value);

                // Map OID to label if it's a known attribute
                key = MapOidToLabel(key);

                // Store unique keys only (first occurrence wins)
                if (!attributes.ContainsKey(key))
                {
                    attributes[key] = value;
                }
            }
        }

        return new X509Name(attributes);
    }

    /// <summary>
    /// Splits RFC 4514 DN into components, handling escaped commas.
    /// </summary>
    private static List<string> SplitRFC4514Components(string dn)
    {
        var components = new List<string>();
        var current = new StringBuilder();
        bool escaped = false;

        for (int i = 0; i < dn.Length; i++)
        {
            char c = dn[i];

            if (escaped)
            {
                current.Append(c);
                escaped = false;
            }
            else if (c == DidX509Constants.BackslashChar)
            {
                current.Append(c);
                escaped = true;
            }
            else if (c == DidX509Constants.CommaChar)
            {
                if (current.Length > 0)
                {
                    components.Add(current.ToString());
                    current.Clear();
                }
            }
            else
            {
                current.Append(c);
            }
        }

        if (current.Length > 0)
        {
            components.Add(current.ToString());
        }

        return components;
    }

    /// <summary>
    /// Unescapes RFC 4514 escaped values.
    /// </summary>
    private static string UnescapeRFC4514Value(string value)
    {
        if (string.IsNullOrEmpty(value) || !value.Contains(DidX509Constants.BackslashChar.ToString()))
        {
            return value;
        }

        var result = new StringBuilder();
        bool escaped = false;

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];

            if (escaped)
            {
                // Handle hex escape sequences (\XX)
                if (i + 1 < value.Length && IsHexDigit(c) && IsHexDigit(value[i + 1]))
                {
                    string hex = new string(new[] { c, value[i + 1] });
                    result.Append((char)System.Convert.ToByte(hex, 16));
                    i++;
                }
                else
                {
                    result.Append(c);
                }
                escaped = false;
            }
            else if (c == DidX509Constants.BackslashChar)
            {
                escaped = true;
            }
            else
            {
                result.Append(c);
            }
        }

        return result.ToString();
    }

    private static bool IsHexDigit(char c)
    {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /// <summary>
    /// Maps OID to well-known label if applicable.
    /// </summary>
    private static string MapOidToLabel(string key)
    {
        return key switch
        {
            DidX509Constants.OidCommonName => DidX509Constants.AttributeCN,
            DidX509Constants.OidLocalityName => DidX509Constants.AttributeL,
            DidX509Constants.OidStateOrProvinceName => DidX509Constants.AttributeST,
            DidX509Constants.OidOrganizationName => DidX509Constants.AttributeO,
            DidX509Constants.OidOrganizationalUnitName => DidX509Constants.AttributeOU,
            DidX509Constants.OidCountryName => DidX509Constants.AttributeC,
            DidX509Constants.OidStreetAddress => DidX509Constants.AttributeSTREET,
            _ => key
        };
    }

    /// <summary>
    /// Parses certificate extensions.
    /// </summary>
    private static CertificateExtensions ParseExtensions(X509Certificate2 certificate)
    {
        List<string>? eku = null;
        List<SubjectAlternativeName>? san = null;
        string? fulcioIssuer = null;

        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid?.Value == DidX509Constants.OidExtendedKeyUsage)
            {
                eku = ParseEkuExtension(extension);
            }
            else if (extension.Oid?.Value == DidX509Constants.OidSubjectAlternativeName)
            {
                san = ParseSanExtension(extension);
            }
            else if (extension.Oid?.Value == DidX509Constants.OidFulcioIssuer)
            {
                fulcioIssuer = ParseFulcioExtension(extension);
            }
        }

        return new CertificateExtensions(eku, san, fulcioIssuer);
    }

    /// <summary>
    /// Parses Extended Key Usage extension.
    /// </summary>
    private static List<string> ParseEkuExtension(X509Extension extension)
    {
        var ekuOids = new List<string>();

        if (extension is X509EnhancedKeyUsageExtension ekuExt)
        {
            foreach (var oid in ekuExt.EnhancedKeyUsages)
            {
                if (!string.IsNullOrEmpty(oid.Value))
                {
                    ekuOids.Add(oid.Value);
                }
            }
        }

        return ekuOids;
    }

    /// <summary>
    /// Parses Subject Alternative Name extension.
    /// </summary>
    private static List<SubjectAlternativeName> ParseSanExtension(X509Extension extension)
    {
        var sans = new List<SubjectAlternativeName>();

        // Parse SAN extension raw data
        // The format is a sequence of [tag, length, value] triplets
        // Tag 1 = rfc822Name (email), Tag 2 = dNSName, Tag 6 = uniformResourceIdentifier, Tag 4 = directoryName

        try
        {
            // Use the formatted string representation as a fallback
            string formatted = extension.Format(false);
            var lines = formatted.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines)
            {
                string trimmed = line.Trim();

                if (trimmed.StartsWith("DNS Name=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = trimmed.Substring("DNS Name=".Length);
                    sans.Add(new SubjectAlternativeName(DidX509Constants.SanTypeDns, value));
                }
                else if (trimmed.StartsWith("RFC822 Name=", StringComparison.OrdinalIgnoreCase) ||
                         trimmed.StartsWith("Email=", StringComparison.OrdinalIgnoreCase))
                {
                    string prefix = trimmed.StartsWith("RFC822 Name=") ? "RFC822 Name=" : "Email=";
                    string value = trimmed.Substring(prefix.Length);
                    sans.Add(new SubjectAlternativeName(DidX509Constants.SanTypeEmail, value));
                }
                else if (trimmed.StartsWith("URL=", StringComparison.OrdinalIgnoreCase) ||
                         trimmed.StartsWith("URI=", StringComparison.OrdinalIgnoreCase))
                {
                    string prefix = trimmed.StartsWith("URL=") ? "URL=" : "URI=";
                    string value = trimmed.Substring(prefix.Length);
                    sans.Add(new SubjectAlternativeName(DidX509Constants.SanTypeUri, value));
                }
            }
        }
        catch
        {
            // Ignore parsing errors for SAN
        }

        return sans;
    }

    /// <summary>
    /// Parses Fulcio issuer extension (Sigstore-specific).
    /// </summary>
    private static string? ParseFulcioExtension(X509Extension extension)
    {
        try
        {
            // The extension value is typically a UTF8 string
            string value = Encoding.UTF8.GetString(extension.RawData);

            // Skip ASN.1 tag and length bytes if present (typically first 2 bytes)
            if (value.Length > 2 && (value[0] < 32 || value[0] > 126))
            {
                value = Encoding.UTF8.GetString(extension.RawData.Skip(2).ToArray());
            }

            return value.Trim();
        }
        catch
        {
            return null;
        }
    }
}