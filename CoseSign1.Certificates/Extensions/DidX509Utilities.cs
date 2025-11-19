// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace CoseSign1.Certificates.Extensions;

/// <summary>
/// Provides utility methods for generating DID:x509 identifiers from X.509 certificates.
/// </summary>
/// <remarks>
/// <para>
/// The DID:x509 method specification defines how to derive decentralized identifiers from X.509 certificates.
/// This implementation follows the specification at: https://github.com/microsoft/did-x509/blob/main/specification.md
/// </para>
/// <para>
/// A DID:x509 identifier has the format:
/// did:x509:0:sha256:{root-cert-hash}::subject:{encoded-subject-fields}
/// </para>
/// </remarks>
public static class DidX509Utilities
{
    /// <summary>
    /// Generates a DID:x509 identifier from an X.509 certificate chain using the subject policy.
    /// </summary>
    /// <param name="leafCertificate">The leaf certificate whose subject will be encoded in the DID.</param>
    /// <param name="rootCertificate">The root (or intermediate) CA certificate to pin the DID to.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use for the CA fingerprint. Defaults to SHA256.</param>
    /// <returns>A DID:x509 identifier string in the format: did:x509:0:{alg}:{ca-fingerprint}::subject:{encoded-subject}</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="leafCertificate"/> or <paramref name="rootCertificate"/> is null.</exception>
    /// <remarks>
    /// <para>
    /// This method generates a DID:x509 identifier that pins to a specific root/intermediate CA certificate
    /// and uses the subject policy to identify the leaf certificate. The subject fields are percent-encoded
    /// according to RFC 3986.
    /// </para>
    /// <para>
    /// Example output: did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::subject:C:US:ST:California:O:My%20Organisation
    /// </para>
    /// </remarks>
    public static string GenerateDidX509Identifier(
        X509Certificate2 leafCertificate,
        X509Certificate2 rootCertificate,
        HashAlgorithmName? hashAlgorithm = null)
    {
        if (leafCertificate == null)
        {
            throw new ArgumentNullException(nameof(leafCertificate));
        }

        if (rootCertificate == null)
        {
            throw new ArgumentNullException(nameof(rootCertificate));
        }

        HashAlgorithmName algorithm = hashAlgorithm ?? HashAlgorithmName.SHA256;
        string algorithmName = algorithm.Name?.ToLowerInvariant() ?? "sha256";

        // Calculate the CA certificate fingerprint
        string caFingerprint = CalculateCertificateFingerprint(rootCertificate, algorithm);

        // Encode the leaf certificate subject
        string encodedSubject = EncodeSubjectForDidX509(leafCertificate);

        // Construct the DID
        string did = $"did:x509:0:{algorithmName}:{caFingerprint}::subject:{encodedSubject}";

        Trace.TraceInformation($"DidX509Utilities: Generated DID:x509 identifier: {did}");
        return did;
    }

    /// <summary>
    /// Calculates the base64url-encoded hash fingerprint of an X.509 certificate.
    /// </summary>
    /// <param name="certificate">The certificate to hash.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <returns>A base64url-encoded string representing the certificate hash.</returns>
    private static string CalculateCertificateFingerprint(X509Certificate2 certificate, HashAlgorithmName hashAlgorithm)
    {
        byte[] certBytes = certificate.RawData;
        byte[] hashBytes;

        // Use the appropriate hash algorithm based on the name
        if (hashAlgorithm == HashAlgorithmName.SHA256)
        {
            using SHA256 hasher = SHA256.Create();
            hashBytes = hasher.ComputeHash(certBytes);
        }
        else if (hashAlgorithm == HashAlgorithmName.SHA384)
        {
            using SHA384 hasher = SHA384.Create();
            hashBytes = hasher.ComputeHash(certBytes);
        }
        else if (hashAlgorithm == HashAlgorithmName.SHA512)
        {
            using SHA512 hasher = SHA512.Create();
            hashBytes = hasher.ComputeHash(certBytes);
        }
        else
        {
            throw new InvalidOperationException($"Unsupported hash algorithm: {hashAlgorithm.Name}");
        }

        // Convert to base64url encoding (RFC 4648 Section 5)
        string base64url = Convert.ToBase64String(hashBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');

        Trace.TraceInformation($"DidX509Utilities: Calculated {hashAlgorithm.Name} fingerprint: {base64url}");
        return base64url;
    }

    /// <summary>
    /// Encodes the subject fields of an X.509 certificate for use in a DID:x509 subject policy.
    /// </summary>
    /// <param name="certificate">The certificate whose subject to encode.</param>
    /// <returns>A colon-separated, percent-encoded string of subject fields (e.g., "C:US:ST:California:O:My%20Organisation").</returns>
    /// <remarks>
    /// <para>
    /// The encoding follows the DID:x509 specification:
    /// - Subject fields are extracted and encoded as key:value pairs separated by colons
    /// - Values are percent-encoded according to RFC 3986
    /// - Only standard attribute types are encoded with their labels (CN, C, ST, L, O, OU, STREET)
    /// - Other attribute types use their dotted OID notation
    /// </para>
    /// </remarks>
    private static string EncodeSubjectForDidX509(X509Certificate2 certificate)
    {
        // Parse the subject distinguished name
        // The Subject property gives us a string like "CN=Test, O=Microsoft, C=US"
        // We need to parse this and encode it according to the DID:x509 spec

        string subjectDN = certificate.Subject;
        List<string> encodedParts = new();

        // Parse the DN using X500DistinguishedName for proper handling
        X500DistinguishedName dn = certificate.SubjectName;

        // Map of OIDs to their short labels according to RFC 4514
        Dictionary<string, string> oidToLabel = new()
        {
            { "2.5.4.3", "CN" },      // Common Name
            { "2.5.4.6", "C" },       // Country
            { "2.5.4.8", "ST" },      // State or Province
            { "2.5.4.7", "L" },       // Locality
            { "2.5.4.10", "O" },      // Organization
            { "2.5.4.11", "OU" },     // Organizational Unit
            { "2.5.4.9", "STREET" }   // Street Address
        };

        // Format the DN with OIDs for parsing
        string dnWithOids = dn.Format(true); // multiLine = true gives us OID=value format

        // Parse each line
        string[] lines = dnWithOids.Split(new[] { Environment.NewLine, "\r\n", "\n", "\r" }, StringSplitOptions.RemoveEmptyEntries);

        foreach (string line in lines)
        {
            string trimmedLine = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmedLine))
            {
                continue;
            }

            // Split on the first '=' to get OID and value
            int equalIndex = trimmedLine.IndexOf('=');
            if (equalIndex < 0)
            {
                continue;
            }

            string oidOrLabel = trimmedLine.Substring(0, equalIndex).Trim();
            string value = trimmedLine.Substring(equalIndex + 1).Trim();

            // Determine the label to use
            string label;
            if (oidToLabel.TryGetValue(oidOrLabel, out string? mappedLabel))
            {
                label = mappedLabel;
            }
            else if (oidToLabel.ContainsValue(oidOrLabel))
            {
                // Already a label
                label = oidOrLabel;
            }
            else
            {
                // Use the OID as-is
                label = oidOrLabel;
            }

            // Percent-encode the value according to DID:x509 spec
            string encodedValue = PercentEncodeForDidX509(value);

            encodedParts.Add($"{label}:{encodedValue}");
        }

        // Reverse the order to match certificate subject order (most significant first)
        // The Format method returns in reverse order compared to how they appear in the certificate
        encodedParts.Reverse();

        string result = string.Join(":", encodedParts);
        Trace.TraceInformation($"DidX509Utilities: Encoded subject: {result}");
        return result;
    }

    /// <summary>
    /// Percent-encodes a string value according to the DID:x509 specification.
    /// </summary>
    /// <param name="value">The string value to encode.</param>
    /// <returns>The percent-encoded string.</returns>
    /// <remarks>
    /// <para>
    /// Per the DID:x509 specification, the allowed characters are:
    /// ALPHA / DIGIT / "-" / "." / "_"
    /// All other characters must be percent-encoded.
    /// </para>
    /// <para>
    /// Note: Most URL encoding libraries encode '~' as '%7E', but the DID:x509 spec
    /// does not include '~' in the allowed set, so it should be encoded.
    /// </para>
    /// </remarks>
    private static string PercentEncodeForDidX509(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        StringBuilder encoded = new();

        foreach (char c in value)
        {
            // Allowed characters per DID:x509 spec: ALPHA / DIGIT / "-" / "." / "_"
            if ((c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') ||
                c == '-' || c == '.' || c == '_')
            {
                encoded.Append(c);
            }
            else
            {
                // Percent-encode the character
                byte[] bytes = Encoding.UTF8.GetBytes(new char[] { c });
                foreach (byte b in bytes)
                {
                    encoded.Append('%');
                    encoded.Append(b.ToString("X2"));
                }
            }
        }

        return encoded.ToString();
    }

    /// <summary>
    /// Generates a DID:x509 identifier from a certificate chain, automatically using the root certificate.
    /// </summary>
    /// <param name="certificateChain">The certificate chain (leaf first order).</param>
    /// <param name="hashAlgorithm">The hash algorithm to use for the CA fingerprint. Defaults to SHA256.</param>
    /// <returns>A DID:x509 identifier string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateChain"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when the certificate chain is empty or contains only one certificate.</exception>
    public static string GenerateDidX509IdentifierFromChain(
        IEnumerable<X509Certificate2> certificateChain,
        HashAlgorithmName? hashAlgorithm = null)
    {
        if (certificateChain == null)
        {
            throw new ArgumentNullException(nameof(certificateChain));
        }

        List<X509Certificate2> chain = certificateChain.ToList();

        if (chain.Count == 0)
        {
            throw new ArgumentException("Certificate chain cannot be empty.", nameof(certificateChain));
        }

        X509Certificate2 leafCertificate = chain[0];
        // For self-signed certificates (chain.Count == 1), use the same certificate as both leaf and root
        X509Certificate2 rootCertificate = chain.Count == 1 ? chain[0] : chain[chain.Count - 1];

        return GenerateDidX509Identifier(leafCertificate, rootCertificate, hashAlgorithm);
    }
}
