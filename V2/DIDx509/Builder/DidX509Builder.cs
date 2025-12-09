// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Builder;

using DIDx509.Parsing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Fluent builder for creating DID:X509 identifiers with full specification support.
/// Supports all policy types: subject, san, eku, fulcio-issuer.
/// Supports all hash algorithms: SHA-256, SHA-384, SHA-512.
/// </summary>
public sealed class DidX509Builder
{
    private X509Certificate2? _leafCertificate;
    private X509Certificate2? _caCertificate;
    private string _hashAlgorithm = DidX509Constants.HashAlgorithmSha256;
    private readonly List<(string Name, string Value)> _policies = new List<(string, string)>();

    /// <summary>
    /// Sets the leaf certificate (end-entity certificate).
    /// </summary>
    public DidX509Builder WithLeafCertificate(X509Certificate2 certificate)
    {
        _leafCertificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        return this;
    }

    /// <summary>
    /// Sets the CA certificate to pin to (intermediate or root).
    /// </summary>
    public DidX509Builder WithCaCertificate(X509Certificate2 certificate)
    {
        _caCertificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        return this;
    }

    /// <summary>
    /// Sets the CA certificate from a certificate chain (finds the root or uses the last cert).
    /// </summary>
    public DidX509Builder WithCertificateChain(IEnumerable<X509Certificate2> certificates)
    {
        if (certificates == null)
        {
            throw new ArgumentNullException(nameof(certificates));
        }

        var certArray = certificates.ToArray();
        if (certArray.Length == 0)
        {
            throw new ArgumentException("Certificate chain cannot be empty", nameof(certificates));
        }

        _leafCertificate = certArray[0];
        _caCertificate = FindRootCertificate(certArray);

        return this;
    }

    /// <summary>
    /// Sets the hash algorithm for the CA fingerprint (default: SHA-256).
    /// </summary>
    public DidX509Builder WithHashAlgorithm(string algorithm)
    {
        if (string.IsNullOrWhiteSpace(algorithm))
        {
            throw new ArgumentException("Hash algorithm cannot be null or empty", nameof(algorithm));
        }

        algorithm = algorithm.ToLowerInvariant();
        if (algorithm != DidX509Constants.HashAlgorithmSha256 &&
            algorithm != DidX509Constants.HashAlgorithmSha384 &&
            algorithm != DidX509Constants.HashAlgorithmSha512)
        {
            throw new ArgumentException($"Unsupported hash algorithm: {algorithm}", nameof(algorithm));
        }

        _hashAlgorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Adds a subject policy with specified attributes.
    /// </summary>
    /// <param name="attributes">Subject attributes as key-value pairs (e.g., "CN" => "User", "O" => "Org").</param>
    public DidX509Builder WithSubjectPolicy(IDictionary<string, string> attributes)
    {
        if (attributes == null || attributes.Count == 0)
        {
            throw new ArgumentException("Subject attributes cannot be null or empty", nameof(attributes));
        }

        // Build subject policy value: key:value:key:value:...
        var parts = new List<string>();
        foreach (var kvp in attributes)
        {
            if (string.IsNullOrWhiteSpace(kvp.Key))
            {
                throw new ArgumentException("Subject attribute key cannot be null or empty");
            }

            parts.Add(kvp.Key);
            parts.Add(PercentEncoding.Encode(kvp.Value ?? string.Empty));
        }

        string policyValue = string.Join(DidX509Constants.ValueSeparator, parts);
        _policies.Add((DidX509Constants.PolicySubject, policyValue));

        return this;
    }

    /// <summary>
    /// Adds a subject policy using the leaf certificate's subject.
    /// </summary>
    public DidX509Builder WithSubjectFromCertificate()
    {
        if (_leafCertificate == null)
        {
            throw new InvalidOperationException("Leaf certificate must be set before calling WithSubjectFromCertificate");
        }

        var attributes = ExtractSubjectAttributes(_leafCertificate.Subject);
        return WithSubjectPolicy(attributes);
    }

    /// <summary>
    /// Adds a SAN (Subject Alternative Name) policy.
    /// </summary>
    /// <param name="type">SAN type: "email", "dns", or "uri".</param>
    /// <param name="value">SAN value.</param>
    public DidX509Builder WithSanPolicy(string type, string value)
    {
        if (string.IsNullOrWhiteSpace(type))
        {
            throw new ArgumentException("SAN type cannot be null or empty", nameof(type));
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("SAN value cannot be null or empty", nameof(value));
        }

        type = type.ToLowerInvariant();
        if (type != DidX509Constants.SanTypeEmail &&
            type != DidX509Constants.SanTypeDns &&
            type != DidX509Constants.SanTypeUri)
        {
            throw new ArgumentException($"Invalid SAN type: {type}. Must be 'email', 'dns', or 'uri'", nameof(type));
        }

        string encodedValue = PercentEncoding.Encode(value);
        string policyValue = $"{type}{DidX509Constants.ValueSeparator}{encodedValue}";
        _policies.Add((DidX509Constants.PolicySan, policyValue));

        return this;
    }

    /// <summary>
    /// Adds an EKU (Extended Key Usage) policy.
    /// </summary>
    /// <param name="oid">EKU OID in dotted decimal notation (e.g., "1.3.6.1.4.1.311.10.3.13").</param>
    public DidX509Builder WithEkuPolicy(string oid)
    {
        if (string.IsNullOrWhiteSpace(oid))
        {
            throw new ArgumentException("EKU OID cannot be null or empty", nameof(oid));
        }

        if (!IsValidOid(oid))
        {
            throw new ArgumentException($"Invalid OID format: {oid}", nameof(oid));
        }

        _policies.Add((DidX509Constants.PolicyEku, oid));
        return this;
    }

    /// <summary>
    /// Adds a Fulcio issuer policy (Sigstore-specific).
    /// </summary>
    /// <param name="issuer">Issuer domain without "https://" prefix (e.g., "accounts.google.com").</param>
    public DidX509Builder WithFulcioIssuerPolicy(string issuer)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new ArgumentException("Fulcio issuer cannot be null or empty", nameof(issuer));
        }

        // Remove https:// prefix if provided
        if (issuer.StartsWith(DidX509Constants.ProtocolHttps, StringComparison.OrdinalIgnoreCase))
        {
            issuer = issuer.Substring(DidX509Constants.ProtocolHttps.Length);
        }

        string encodedIssuer = PercentEncoding.Encode(issuer);
        _policies.Add((DidX509Constants.PolicyFulcioIssuer, encodedIssuer));

        return this;
    }

    /// <summary>
    /// Builds the DID:X509 identifier.
    /// </summary>
    public string Build()
    {
        if (_leafCertificate == null)
        {
            throw new InvalidOperationException("Leaf certificate must be set");
        }

        if (_caCertificate == null)
        {
            throw new InvalidOperationException("CA certificate must be set");
        }

        if (_policies.Count == 0)
        {
            throw new InvalidOperationException("At least one policy must be added");
        }

        // Compute CA fingerprint
        byte[] caHash = ComputeHash(_caCertificate.RawData, _hashAlgorithm);
        string caFingerprint = ConvertToBase64Url(caHash);

        // Build DID: did:x509:version:algorithm:fingerprint::policy1:value1::policy2:value2...
        var parts = new List<string>
        {
            DidX509Constants.DidMethod,
            DidX509Constants.MethodName,
            DidX509Constants.Version,
            _hashAlgorithm,
            caFingerprint
        };

        string prefix = string.Join(DidX509Constants.ValueSeparator, parts);

        // Add policies
        var policyParts = _policies.Select(p => $"{p.Name}{DidX509Constants.ValueSeparator}{p.Value}");
        string policiesString = string.Join(DidX509Constants.PolicySeparator, policyParts);

        return $"{prefix}{DidX509Constants.PolicySeparator}{policiesString}";
    }

    private static byte[] ComputeHash(byte[] data, string algorithm)
    {
        return algorithm switch
        {
#if NET10_0_OR_GREATER
            DidX509Constants.HashAlgorithmSha256 => SHA256.HashData(data),
            DidX509Constants.HashAlgorithmSha384 => SHA384.HashData(data),
            DidX509Constants.HashAlgorithmSha512 => SHA512.HashData(data),
#else
            DidX509Constants.HashAlgorithmSha256 => ComputeHashLegacy<SHA256>(data),
            DidX509Constants.HashAlgorithmSha384 => ComputeHashLegacy<SHA384>(data),
            DidX509Constants.HashAlgorithmSha512 => ComputeHashLegacy<SHA512>(data),
#endif
            _ => throw new NotSupportedException($"Unsupported hash algorithm: {algorithm}")
        };
    }

#if !NET10_0_OR_GREATER
    private static byte[] ComputeHashLegacy<T>(byte[] data) where T : HashAlgorithm
    {
        using var hasher = (T)Activator.CreateInstance(typeof(T))!;
        return hasher.ComputeHash(data);
    }
#endif

    private static string ConvertToBase64Url(byte[] data)
    {
        string base64 = Convert.ToBase64String(data);
        return base64.Replace(DidX509Constants.PlusChar, DidX509Constants.HyphenChar)
                     .Replace(DidX509Constants.SlashChar, DidX509Constants.UnderscoreChar)
                     .TrimEnd('=');
    }

    private static X509Certificate2 FindRootCertificate(X509Certificate2[] certificates)
    {
        // Look for a self-signed certificate (issuer == subject)
        var rootCert = certificates.FirstOrDefault(c =>
            c.Subject.Equals(c.Issuer, StringComparison.OrdinalIgnoreCase));

        // If no self-signed cert found, use the last certificate in the chain
        return rootCert ?? certificates[certificates.Length - 1];
    }

    private static Dictionary<string, string> ExtractSubjectAttributes(string subject)
    {
        var attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var x500Name = new X500DistinguishedName(subject);
        string rfc4514 = x500Name.Format(false);

        var components = rfc4514.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var component in components)
        {
            int equalIndex = component.IndexOf('=');
            if (equalIndex > 0 && equalIndex < component.Length - 1)
            {
                string key = component.Substring(0, equalIndex).Trim();
                string value = component.Substring(equalIndex + 1).Trim();

                // Only include known labels
                if (IsKnownLabel(key))
                {
                    attributes[key.ToUpperInvariant()] = value;
                }
            }
        }

        return attributes;
    }

    private static bool IsKnownLabel(string key)
    {
        return DidX509Constants.KnownLabels.Contains(key);
    }

    private static bool IsValidOid(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
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
}
