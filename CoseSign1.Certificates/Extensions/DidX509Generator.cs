// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Extensions;

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
    /// A DID:X509 formatted identifier with base64url-encoded certificate hash and
    /// key:value formatted subject policy. Example:
    /// did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:C:US:O:GitHub:CN:User
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when either certificate is null.</exception>
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
    /// Computes the SHA256 hash of the root certificate's raw data.
    /// The resulting hash will be base64url-encoded in the final DID.
    /// This method can be overridden to use different hash algorithms.
    /// </summary>
    /// <param name="rootCertificate">The root certificate to hash.</param>
    /// <returns>The SHA256 hash bytes (32 bytes).</returns>
    protected virtual byte[] ComputeRootCertificateHash(X509Certificate2 rootCertificate)
    {
        using SHA256 sha256 = SHA256.Create();
        return sha256.ComputeHash(rootCertificate.RawData);
    }

    /// <summary>
    /// Generates a DID:X509 identifier from a certificate chain.
    /// </summary>
    /// <param name="certificates">The certificate chain. First certificate must be the leaf.</param>
    /// <returns>
    /// A DID:X509 formatted identifier with base64url-encoded certificate hash and
    /// key:value formatted subject policy.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when certificates is null.</exception>
    /// <exception cref="ArgumentException">Thrown when chain is empty or invalid.</exception>
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
    /// Finds the root certificate in a chain.
    /// This method can be overridden to customize root certificate selection.
    /// </summary>
    /// <param name="certificates">The certificate chain.</param>
    /// <returns>The root certificate (self-signed certificate at the end of the chain).</returns>
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
    /// Per the DID:X509 specification, this parses the DN into key:value pairs and formats them
    /// as key:value:key:value with values percent-encoded per the spec's allowed character set.
    /// This method can be overridden to customize subject encoding.
    /// </summary>
    /// <param name="subject">The certificate subject DN.</param>
    /// <returns>The formatted and encoded subject for DID:X509 subject policy.</returns>
    protected virtual string EncodeSubject(string subject)
    {
        if (string.IsNullOrEmpty(subject))
        {
            return string.Empty;
        }

        // Parse the DN into key-value pairs using X500DistinguishedName
        try
        {
            var x500Name = new System.Security.Cryptography.X509Certificates.X500DistinguishedName(subject);
            
            // Format with RFC4514 to get standard format, then parse it
            string rfc4514 = x500Name.Format(false); // false = single line format
            
            // Parse the RFC4514 formatted DN
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
            // If parsing fails, return empty string
            return string.Empty;
        }
    }

    /// <summary>
    /// Parses an RFC 4514 formatted Distinguished Name into key-value pairs.
    /// Only extracts the standard labels defined in the DID:X509 spec:
    /// CN, L, ST, O, OU, C, STREET, and numeric OIDs.
    /// </summary>
    protected virtual List<(string Key, string Value)> ParseRFC4514DistinguishedName(string dn)
    {
        var components = new List<(string Key, string Value)>();

        // Simple parser for RFC 4514 format
        // Format: key=value, key=value (comma-separated)
        var parts = SplitRFC4514Components(dn);
        
        foreach (var part in parts)
        {
            int equalIndex = part.IndexOf('=');
            if (equalIndex > 0 && equalIndex < part.Length - 1)
            {
                string key = part.Substring(0, equalIndex).Trim();
                string value = part.Substring(equalIndex + 1).Trim();
                
                // Unescape RFC 4514 escaped characters
                value = UnescapeRFC4514Value(value);
                
                // Only include known labels or OIDs (numeric dotted notation)
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
    /// RFC 4514 uses backslash escaping for special characters.
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
                // Check for hex escape (\XX)
                if (i + 1 < value.Length && IsHexDigit(c) && IsHexDigit(value[i + 1]))
                {
                    string hex = new string(new[] { c, value[i + 1] });
                    result.Append((char)Convert.ToByte(hex, 16));
                    i++; // Skip next character
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
    /// Allowed unencoded characters: ALPHA / DIGIT / "-" / "." / "_"
    /// Note: Tilde (~) is NOT in the allowed set per the spec.
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
            // Allowed characters per DID:X509 spec: A-Z a-z 0-9 - . _
            if (IsDidX509AllowedCharacter(c))
            {
                encoded.Append(c);
            }
            else
            {
                // Percent-encode the character
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
    /// Per the spec: ALPHA / DIGIT / "-" / "." / "_"
    /// Note: Tilde (~) is explicitly NOT included, unlike standard RFC 3986.
    /// </summary>
    protected static bool IsDidX509AllowedCharacter(char c)
    {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '-' || c == '_' || c == '.';
    }

    /// <summary>
    /// Converts a byte array to base64url encoding as per RFC 4648 Section 5.
    /// Base64url encoding uses '-' and '_' instead of '+' and '/' and omits padding '='.
    /// </summary>
    /// <param name="data">The data to encode.</param>
    /// <returns>The base64url-encoded string.</returns>
    protected static string ConvertToBase64Url(byte[] data)
    {
        string base64 = Convert.ToBase64String(data);
        // Convert to base64url: replace '+' with '-', '/' with '_', and remove padding '='
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    /// <summary>
    /// Checks if a character is valid in base64url encoding.
    /// Valid characters are: A-Z, a-z, 0-9, '-', '_'
    /// </summary>
    protected static bool IsBase64UrlCharacter(char c)
    {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '-' || c == '_';
    }

    /// <summary>
    /// Validates that a string is a valid DID:X509 identifier.
    /// Checks for correct prefix, base64url-encoded hash (43 characters for SHA256),
    /// and properly formatted subject policy with key:value pairs.
    /// </summary>
    /// <param name="did">The DID to validate.</param>
    /// <returns>True if the DID is valid according to the DID:X509 specification, false otherwise.</returns>
    public static bool IsValidDidX509(string did)
    {
        if (string.IsNullOrWhiteSpace(did))
        {
            return false;
        }

        // Must start with correct prefix
        if (!did.StartsWith(DidX509Prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Must contain ::subject: separator
        if (did.IndexOf("::subject:", StringComparison.OrdinalIgnoreCase) == -1)
        {
            return false;
        }

        // Basic structure check: did:x509:0:sha256:{hash}::subject:{subject}
        string[] parts = did.Split(new[] { "::" }, StringSplitOptions.None);
        if (parts.Length < 2)
        {
            return false;
        }

        // Hash part should be base64url string of appropriate length (43 chars for SHA256)
        string hashPart = parts[0].Substring(DidX509Prefix.Length + 1);
        if (hashPart.Length != 43)
        {
            return false;
        }

        // Verify hash is valid base64url
        foreach (char c in hashPart)
        {
            if (!IsBase64UrlCharacter(c))
            {
                return false;
            }
        }

        // Validate subject policy format
        // Format should be: subject:key:value:key:value...
        for (int i = 1; i < parts.Length; i++)
        {
            if (!parts[i].StartsWith("subject:", StringComparison.OrdinalIgnoreCase))
            {
                continue; // Other policies may exist in the future
            }

            string subjectPolicyValue = parts[i].Substring(8); // Remove "subject:" prefix
            if (string.IsNullOrEmpty(subjectPolicyValue))
            {
                return false; // Subject policy must have at least one key:value pair
            }

            // Split by colon to get key:value pairs
            string[] components = subjectPolicyValue.Split(':');
            
            // Must have even number of components (key:value pairs)
            if (components.Length < 2 || components.Length % 2 != 0)
            {
                return false;
            }

            // Validate keys and values
            for (int j = 0; j < components.Length; j += 2)
            {
                string key = components[j];
                string value = components[j + 1];

                // Key must not be empty
                if (string.IsNullOrEmpty(key))
                {
                    return false;
                }

                // Key must be a known label or OID
                if (!IsValidSubjectKey(key))
                {
                    return false;
                }

                // Value can be any idchar sequence (including percent-encoded)
                if (string.IsNullOrEmpty(value))
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// Validates if a key is a valid subject policy key.
    /// Valid keys are: CN, L, ST, O, OU, C, STREET, or numeric OID format.
    /// </summary>
    private static bool IsValidSubjectKey(string key)
    {
        // Check for known labels (case-insensitive)
        var knownLabels = new[] { "CN", "L", "ST", "O", "OU", "C", "STREET" };
        if (knownLabels.Any(label => label.Equals(key, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        // Check for OID format (dotted decimal notation)
        if (key.Contains('.'))
        {
            var parts = key.Split('.');
            if (parts.Length >= 2)
            {
                return parts.All(p => !string.IsNullOrEmpty(p) && p.All(char.IsDigit));
            }
        }

        return false;
    }
}
