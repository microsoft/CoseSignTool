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
/// DID:X509 format: did:x509:0:sha256:{rootCertHash}::subject:{encodedLeafSubject}
/// This provides a cryptographically verifiable decentralized identifier based on X.509 PKI.
/// This class can be inherited to customize the DID generation behavior.
/// </remarks>
public class DidX509Generator
{
    private const string DidX509Prefix = "did:x509:0:sha256";

    /// <summary>
    /// Generates a DID:X509 identifier from a leaf certificate and root certificate.
    /// </summary>
    /// <param name="leafCertificate">The leaf certificate (end-entity certificate).</param>
    /// <param name="rootCertificate">The root certificate (trust anchor).</param>
    /// <returns>A DID:X509 formatted identifier.</returns>
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
        string rootCertHashHex = BitConverter.ToString(rootCertHash).Replace("-", "").ToLowerInvariant();

        // Encode the leaf certificate subject per DID:X509 spec
        string encodedSubject = EncodeSubject(leafCertificate.Subject);

        // Format: did:x509:0:sha256:{rootHash}::subject:{encodedSubject}
        return $"{DidX509Prefix}:{rootCertHashHex}::subject:{encodedSubject}";
    }

    /// <summary>
    /// Computes the hash of the root certificate.
    /// This method can be overridden to use different hash algorithms.
    /// </summary>
    /// <param name="rootCertificate">The root certificate to hash.</param>
    /// <returns>The hash bytes.</returns>
    protected virtual byte[] ComputeRootCertificateHash(X509Certificate2 rootCertificate)
    {
        using SHA256 sha256 = SHA256.Create();
        return sha256.ComputeHash(rootCertificate.RawData);
    }

    /// <summary>
    /// Generates a DID:X509 identifier from a certificate chain.
    /// </summary>
    /// <param name="certificates">The certificate chain. First certificate must be the leaf.</param>
    /// <returns>A DID:X509 formatted identifier.</returns>
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
    /// Encodes a certificate subject Distinguished Name (DN) for use in DID:X509.
    /// Per the specification, this uses percent-encoding (RFC 3986) for special characters.
    /// This method can be overridden to customize subject encoding.
    /// </summary>
    /// <param name="subject">The certificate subject DN.</param>
    /// <returns>The percent-encoded subject.</returns>
    protected virtual string EncodeSubject(string subject)
    {
        if (string.IsNullOrEmpty(subject))
        {
            return string.Empty;
        }

        StringBuilder encoded = new StringBuilder(subject.Length * 2);

        foreach (char c in subject)
        {
            // Unreserved characters per RFC 3986: A-Z a-z 0-9 - _ . ~
            if (IsUnreservedCharacter(c))
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
    /// Checks if a character is unreserved per RFC 3986.
    /// </summary>
    protected static bool IsUnreservedCharacter(char c)
    {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '-' || c == '_' || c == '.' || c == '~';
    }

    /// <summary>
    /// Validates that a string is a valid DID:X509 identifier.
    /// </summary>
    /// <param name="did">The DID to validate.</param>
    /// <returns>True if valid, false otherwise.</returns>
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
        if (!did.Contains("::subject:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Basic structure check: did:x509:0:sha256:{hash}::subject:{subject}
        string[] parts = did.Split(new[] { "::" }, StringSplitOptions.None);
        if (parts.Length != 2)
        {
            return false;
        }

        // Hash part should be hex string of appropriate length (64 chars for SHA256)
        string hashPart = parts[0].Substring(DidX509Prefix.Length + 1);
        if (hashPart.Length != 64)
        {
            return false;
        }

        // Verify hash is valid hex
        foreach (char c in hashPart)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            {
                return false;
            }
        }
        return true;
    }
}
