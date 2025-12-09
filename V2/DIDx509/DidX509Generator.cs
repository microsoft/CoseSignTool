// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

/// <summary>
/// Generates DID:X509 identifiers from X.509 certificates according to the specification at
/// https://github.com/microsoft/did-x509/blob/main/specification.md
/// </summary>
/// <remarks>
/// <para>
/// DID:X509 format: did:x509:0:sha256:{rootCertHash}::subject:{key}:{value}:{key}:{value}...
/// </para>
/// <para>
/// - {rootCertHash} is the base64url-encoded SHA256 hash of the root certificate (43 characters)
/// - Subject policy uses key:value pairs separated by colons (e.g., C:US:O:GitHub:CN:User)
/// - Keys are standard labels (CN, L, ST, O, OU, C, STREET) or OIDs in dotted decimal notation
/// - Values are percent-encoded with only ALPHA, DIGIT, '-', '.', '_' allowed unencoded (tilde NOT allowed)
/// </para>
/// <para>
/// This provides a cryptographically verifiable decentralized identifier based on X.509 PKI.
/// This class can be inherited to customize the DID generation behavior.
/// </para>
/// </remarks>
public class DidX509Generator
{
    private const string DidX509Prefix = "did:x509:0:sha256";

    /// <summary>
    /// Known labels from the DID:X509 specification.
    /// </summary>
    private static readonly HashSet<string> KnownLabels = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "CN", "L", "ST", "O", "OU", "C", "STREET"
    };

    /// <summary>
    /// Generates a DID:X509 identifier from a leaf certificate and root certificate.
    /// </summary>
    /// <param name="leafCertificate">The leaf certificate (end-entity certificate).</param>
    /// <param name="rootCertificate">The root certificate (trust anchor).</param>
    /// <returns>
    /// A DID:X509 formatted identifier. Example:
    /// did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:C:US:O:GitHub:CN:User
    /// </returns>
    public virtual string Generate(X509Certificate2 leafCertificate, X509Certificate2 rootCertificate)
    {
        if (leafCertificate == null)
        {
            throw new ArgumentNullException(nameof(leafCertificate));
        }

        if (rootCertificate == null)
        {
            throw new ArgumentNullException(nameof(rootCertificate));
        }

        // Calculate SHA256 hash of root certificate's raw data
        byte[] rootCertHash = ComputeRootCertificateHash(rootCertificate);
        string rootCertHashBase64Url = ConvertToBase64Url(rootCertHash);

        // Encode the leaf certificate subject per DID:X509 spec
        string encodedSubject = EncodeSubject(leafCertificate.Subject);

        // Format: did:x509:0:sha256:{rootHash}::subject:{encodedSubject}
        return $"{DidX509Prefix}:{rootCertHashBase64Url}::subject:{encodedSubject}";
    }

    /// <summary>
    /// Generates a DID:X509 identifier from a certificate chain.
    /// </summary>
    /// <param name="certificates">The certificate chain. First certificate must be the leaf.</param>
    /// <returns>A DID:X509 formatted identifier.</returns>
    public virtual string GenerateFromChain(IEnumerable<X509Certificate2> certificates)
    {
        if (certificates == null)
        {
            throw new ArgumentNullException(nameof(certificates));
        }

        X509Certificate2[] certArray = certificates.ToArray();

        if (certArray.Length == 0)
        {
            throw new ArgumentException("Certificate chain cannot be empty.", nameof(certificates));
        }

        X509Certificate2 leafCert = certArray[0];
        X509Certificate2 rootCert = FindRootCertificate(certArray);

        return Generate(leafCert, rootCert);
    }

    /// <summary>
    /// Computes the SHA256 hash of the root certificate's raw data.
    /// </summary>
    protected virtual byte[] ComputeRootCertificateHash(X509Certificate2 rootCertificate)
    {
#if NET10_0_OR_GREATER
        return SHA256.HashData(rootCertificate.RawData);
#else
        using SHA256 sha256 = SHA256.Create();
        return sha256.ComputeHash(rootCertificate.RawData);
#endif
    }

    /// <summary>
    /// Finds the root certificate in a chain.
    /// </summary>
    protected virtual X509Certificate2 FindRootCertificate(X509Certificate2[] certificates)
    {
        // Look for a self-signed certificate (issuer == subject)
        X509Certificate2? rootCert = certificates.FirstOrDefault(c =>
            c.Subject.Equals(c.Issuer, StringComparison.OrdinalIgnoreCase));

        // If no self-signed cert found, use the last certificate in the chain
        return rootCert ?? certificates[certificates.Length - 1];
    }

    /// <summary>
    /// Encodes a certificate subject Distinguished Name (DN) for use in DID:X509 subject policy.
    /// </summary>
    protected virtual string EncodeSubject(string subject)
    {
        if (string.IsNullOrEmpty(subject))
        {
            return string.Empty;
        }

        try
        {
            var x500Name = new X500DistinguishedName(subject);
            string rfc4514 = x500Name.Format(false); // false = single line format
            
            var components = ParseRFC4514DistinguishedName(rfc4514);
            
            if (components.Count == 0)
            {
                return string.Empty;
            }

            // Build the DID:X509 subject policy format: key:value:key:value:...
            StringBuilder result = new StringBuilder();
            
            foreach (var (key, value) in components)
            {
                if (result.Length > 0)
                {
                    result.Append(':');
                }
                
                result.Append(key);
                result.Append(':');
                result.Append(PercentEncodeValue(value));
            }

            return result.ToString();
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Parses an RFC 4514 formatted Distinguished Name into key-value pairs.
    /// </summary>
    protected virtual List<(string Key, string Value)> ParseRFC4514DistinguishedName(string dn)
    {
        var components = new List<(string Key, string Value)>();
        var parts = SplitRFC4514Components(dn);
        
        foreach (var part in parts)
        {
            int equalIndex = part.IndexOf('=');
            if (equalIndex > 0 && equalIndex < part.Length - 1)
            {
                string key = part.Substring(0, equalIndex).Trim();
                string value = part.Substring(equalIndex + 1).Trim();
                
                value = UnescapeRFC4514Value(value);
                
                // Only include known labels or OIDs
                if (KnownLabels.Contains(key) || IsOID(key))
                {
                    // Normalize known labels to uppercase
                    if (KnownLabels.Contains(key))
                    {
                        key = key.ToUpperInvariant();
                    }
                    
                    components.Add((key, value));
                }
            }
        }
        
        return components;
    }

    /// <summary>
    /// Splits RFC 4514 DN into components, handling escaped commas.
    /// </summary>
    protected virtual List<string> SplitRFC4514Components(string dn)
    {
        var components = new List<string>();
        StringBuilder current = new StringBuilder();
        bool escaped = false;
        
        for (int i = 0; i < dn.Length; i++)
        {
            char c = dn[i];
            
            if (escaped)
            {
                current.Append(c);
                escaped = false;
            }
            else if (c == '\\')
            {
                current.Append(c);
                escaped = true;
            }
            else if (c == ',')
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
    protected virtual string UnescapeRFC4514Value(string value)
    {
        if (string.IsNullOrEmpty(value) || !value.Contains('\\'))
        {
            return value;
        }
        
        StringBuilder result = new StringBuilder();
        bool escaped = false;
        
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            
            if (escaped)
            {
                if (i + 1 < value.Length && IsHexDigit(c) && IsHexDigit(value[i + 1]))
                {
                    string hex = new string(new[] { c, value[i + 1] });
                    result.Append((char)Convert.ToByte(hex, 16));
                    i++;
                }
                else
                {
                    result.Append(c);
                }
                escaped = false;
            }
            else if (c == '\\')
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

    /// <summary>
    /// Checks if a string is a valid OID (dotted decimal notation).
    /// </summary>
    protected virtual bool IsOID(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }
        
        var parts = value.Split('.');
        if (parts.Length < 2)
        {
            return false;
        }
        
        foreach (var part in parts)
        {
            if (string.IsNullOrEmpty(part) || !part.All(char.IsDigit))
            {
                return false;
            }
        }
        
        return true;
    }

    /// <summary>
    /// Checks if a character is a hex digit.
    /// </summary>
    protected static bool IsHexDigit(char c)
    {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /// <summary>
    /// Percent-encodes a value according to DID:X509 spec.
    /// Allowed unencoded: ALPHA / DIGIT / "-" / "." / "_"
    /// </summary>
    protected virtual string PercentEncodeValue(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        StringBuilder encoded = new StringBuilder(value.Length * 2);

        foreach (char c in value)
        {
            if (IsDidX509AllowedCharacter(c))
            {
                encoded.Append(c);
            }
            else
            {
                byte[] bytes = Encoding.UTF8.GetBytes(new[] { c });
                foreach (byte b in bytes)
                {
                    encoded.AppendFormat("%{0:X2}", b);
                }
            }
        }

        return encoded.ToString();
    }

    /// <summary>
    /// Checks if a character is allowed unencoded in DID:X509 percent-encoding.
    /// Per spec: ALPHA / DIGIT / "-" / "." / "_"
    /// </summary>
    protected static bool IsDidX509AllowedCharacter(char c)
    {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '-' || c == '_' || c == '.';
    }

    /// <summary>
    /// Converts a byte array to base64url encoding (RFC 4648 Section 5).
    /// </summary>
    protected static string ConvertToBase64Url(byte[] data)
    {
        string base64 = Convert.ToBase64String(data);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    /// <summary>
    /// Validates that a string is a valid DID:X509 identifier.
    /// </summary>
    public static bool IsValidDidX509(string did)
    {
        if (string.IsNullOrWhiteSpace(did))
        {
            return false;
        }

        if (!did.StartsWith(DidX509Prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (did.IndexOf("::subject:", StringComparison.OrdinalIgnoreCase) == -1)
        {
            return false;
        }

        string[] parts = did.Split(new[] { "::" }, StringSplitOptions.None);
        if (parts.Length < 2)
        {
            return false;
        }

        // Validate hash part (should be 43 chars for SHA256)
        string hashPart = parts[0].Substring(DidX509Prefix.Length + 1);
        if (hashPart.Length != 43)
        {
            return false;
        }

        foreach (char c in hashPart)
        {
            if (!IsBase64UrlCharacter(c))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsBase64UrlCharacter(char c)
    {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '-' || c == '_';
    }
}
