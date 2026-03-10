// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Builder;

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DIDx509.Parsing;

/// <summary>
/// Fluent builder for creating DID:X509 identifiers with full specification support.
/// Supports all policy types: subject, san, eku, fulcio-issuer.
/// Supports all hash algorithms: SHA-256, SHA-384, SHA-512.
/// </summary>
public sealed class DidX509Builder
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorCertificateChainCannotBeEmpty = "Certificate chain cannot be empty";
        public const string ErrorHashAlgorithmCannotBeNullOrEmpty = "Hash algorithm cannot be null or empty";
        public const string ErrorFormatUnsupportedHashAlgorithm = "Unsupported hash algorithm: {0}";

        public const string ErrorSubjectAttributesCannotBeNullOrEmpty = "Subject attributes cannot be null or empty";
        public const string ErrorSubjectAttributeKeyCannotBeNullOrEmpty = "Subject attribute key cannot be null or empty";
        public const string ErrorLeafCertificateMustBeSetBeforeSubjectFromCertificate = "Leaf certificate must be set before calling WithSubjectFromCertificate";

        public const string ErrorSanTypeCannotBeNullOrEmpty = "SAN type cannot be null or empty";
        public const string ErrorSanValueCannotBeNullOrEmpty = "SAN value cannot be null or empty";
        public const string ErrorFormatInvalidSanType = "Invalid SAN type: {0}. Must be 'email', 'dns', or 'uri'";

        public const string ErrorEkuOidCannotBeNullOrEmpty = "EKU OID cannot be null or empty";
        public const string ErrorFormatInvalidOidFormat = "Invalid OID format: {0}";

        public const string ErrorFulcioIssuerCannotBeNullOrEmpty = "Fulcio issuer cannot be null or empty";
        public const string ErrorLeafCertificateMustBeSet = "Leaf certificate must be set";
        public const string ErrorCaCertificateMustBeSet = "CA certificate must be set";
        public const string ErrorAtLeastOnePolicyMustBeAdded = "At least one policy must be added";
    }

    private X509Certificate2? LeafCertificate;
    private X509Certificate2? CaCertificate;
    private string HashAlgorithm = DidX509Constants.HashAlgorithmSha256;
    private readonly List<(string Name, string Value)> Policies = new List<(string, string)>();

    /// <summary>
    /// Sets the leaf certificate (end-entity certificate).
    /// </summary>
    /// <param name="certificate">The leaf certificate.</param>
    /// <returns>The current builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> is <see langword="null"/>.</exception>
    public DidX509Builder WithLeafCertificate(X509Certificate2 certificate)
    {
        LeafCertificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        return this;
    }

    /// <summary>
    /// Sets the CA certificate to pin to (intermediate or root).
    /// </summary>
    /// <param name="certificate">The CA certificate.</param>
    /// <returns>The current builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> is <see langword="null"/>.</exception>
    public DidX509Builder WithCaCertificate(X509Certificate2 certificate)
    {
        CaCertificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        return this;
    }

    /// <summary>
    /// Sets the CA certificate from a certificate chain (finds the root or uses the last cert).
    /// </summary>
    /// <param name="certificates">The certificate chain (leaf first).</param>
    /// <returns>The current builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificates"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="certificates"/> is empty.</exception>
    public DidX509Builder WithCertificateChain(IEnumerable<X509Certificate2> certificates)
    {
        if (certificates == null)
        {
            throw new ArgumentNullException(nameof(certificates));
        }

        var certArray = certificates.ToArray();
        if (certArray.Length == 0)
        {
            throw new ArgumentException(ClassStrings.ErrorCertificateChainCannotBeEmpty, nameof(certificates));
        }

        LeafCertificate = certArray[0];
        CaCertificate = FindRootCertificate(certArray);

        return this;
    }

    /// <summary>
    /// Sets the hash algorithm for the CA fingerprint (default: SHA-256).
    /// </summary>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <returns>The current builder instance.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="algorithm"/> is <see langword="null"/>, empty, or unsupported.</exception>
    public DidX509Builder WithHashAlgorithm(string algorithm)
    {
        if (string.IsNullOrWhiteSpace(algorithm))
        {
            throw new ArgumentException(ClassStrings.ErrorHashAlgorithmCannotBeNullOrEmpty, nameof(algorithm));
        }

        algorithm = algorithm.ToLowerInvariant();
        if (algorithm != DidX509Constants.HashAlgorithmSha256 &&
            algorithm != DidX509Constants.HashAlgorithmSha384 &&
            algorithm != DidX509Constants.HashAlgorithmSha512)
        {
            throw new ArgumentException(string.Format(ClassStrings.ErrorFormatUnsupportedHashAlgorithm, algorithm), nameof(algorithm));
        }

        HashAlgorithm = algorithm;
        return this;
    }

    /// <summary>
    /// Adds a subject policy with specified attributes.
    /// </summary>
    /// <param name="attributes">Subject attributes as key-value pairs (e.g., "CN" => "User", "O" => "Org").</param>
    /// <returns>The current builder instance.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="attributes"/> is <see langword="null"/>, empty, or contains an invalid key.</exception>
    public DidX509Builder WithSubjectPolicy(IDictionary<string, string> attributes)
    {
        if (attributes == null || attributes.Count == 0)
        {
            throw new ArgumentException(ClassStrings.ErrorSubjectAttributesCannotBeNullOrEmpty, nameof(attributes));
        }

        // Build subject policy value: key:value:key:value:...
        var parts = new List<string>();
        foreach (var kvp in attributes)
        {
            if (string.IsNullOrWhiteSpace(kvp.Key))
            {
                throw new ArgumentException(ClassStrings.ErrorSubjectAttributeKeyCannotBeNullOrEmpty);
            }

            parts.Add(kvp.Key);
            parts.Add(PercentEncoding.Encode(kvp.Value ?? string.Empty));
        }

        string policyValue = string.Join(DidX509Constants.ValueSeparator, parts);
        Policies.Add((DidX509Constants.PolicySubject, policyValue));

        return this;
    }

    /// <summary>
    /// Adds a subject policy using the leaf certificate's subject.
    /// </summary>
    /// <returns>The current builder instance.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the leaf certificate has not been set.</exception>
    public DidX509Builder WithSubjectFromCertificate()
    {
        if (LeafCertificate == null)
        {
            throw new InvalidOperationException(ClassStrings.ErrorLeafCertificateMustBeSetBeforeSubjectFromCertificate);
        }

        var attributes = ExtractSubjectAttributes(LeafCertificate.Subject);
        return WithSubjectPolicy(attributes);
    }

    /// <summary>
    /// Adds a SAN (Subject Alternative Name) policy.
    /// </summary>
    /// <param name="type">SAN type: "email", "dns", or "uri".</param>
    /// <param name="value">SAN value.</param>
    /// <returns>The current builder instance.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="type"/> or <paramref name="value"/> is invalid.</exception>
    public DidX509Builder WithSanPolicy(string type, string value)
    {
        if (string.IsNullOrWhiteSpace(type))
        {
            throw new ArgumentException(ClassStrings.ErrorSanTypeCannotBeNullOrEmpty, nameof(type));
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException(ClassStrings.ErrorSanValueCannotBeNullOrEmpty, nameof(value));
        }

        type = type.ToLowerInvariant();
        if (type != DidX509Constants.SanTypeEmail &&
            type != DidX509Constants.SanTypeDns &&
            type != DidX509Constants.SanTypeUri)
        {
            throw new ArgumentException(string.Format(ClassStrings.ErrorFormatInvalidSanType, type), nameof(type));
        }

        string encodedValue = PercentEncoding.Encode(value);
        string policyValue = string.Concat(type, DidX509Constants.ValueSeparator, encodedValue);
        Policies.Add((DidX509Constants.PolicySan, policyValue));

        return this;
    }

    /// <summary>
    /// Adds an EKU (Extended Key Usage) policy.
    /// </summary>
    /// <param name="oid">EKU OID in dotted decimal notation (e.g., "1.3.6.1.4.1.311.10.3.13").</param>
    /// <returns>The current builder instance.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="oid"/> is <see langword="null"/>, empty, or not a valid OID.</exception>
    public DidX509Builder WithEkuPolicy(string oid)
    {
        if (string.IsNullOrWhiteSpace(oid))
        {
            throw new ArgumentException(ClassStrings.ErrorEkuOidCannotBeNullOrEmpty, nameof(oid));
        }

        if (!IsValidOid(oid))
        {
            throw new ArgumentException(string.Format(ClassStrings.ErrorFormatInvalidOidFormat, oid), nameof(oid));
        }

        Policies.Add((DidX509Constants.PolicyEku, oid));
        return this;
    }

    /// <summary>
    /// Adds a Fulcio issuer policy (Sigstore-specific).
    /// </summary>
    /// <param name="issuer">Issuer domain without "https://" prefix (e.g., "accounts.google.com").</param>
    /// <returns>The current builder instance.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="issuer"/> is <see langword="null"/> or empty.</exception>
    public DidX509Builder WithFulcioIssuerPolicy(string issuer)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            throw new ArgumentException(ClassStrings.ErrorFulcioIssuerCannotBeNullOrEmpty, nameof(issuer));
        }

        // Remove https:// prefix if provided
        if (issuer.StartsWith(DidX509Constants.ProtocolHttps, StringComparison.OrdinalIgnoreCase))
        {
            issuer = issuer.Substring(DidX509Constants.ProtocolHttps.Length);
        }

        string encodedIssuer = PercentEncoding.Encode(issuer);
        Policies.Add((DidX509Constants.PolicyFulcioIssuer, encodedIssuer));

        return this;
    }

    /// <summary>
    /// Builds the DID:X509 identifier.
    /// </summary>
    /// <returns>The DID:X509 identifier.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the leaf certificate, CA certificate, or required policies are missing.</exception>
    public string Build()
    {
        if (LeafCertificate == null)
        {
            throw new InvalidOperationException(ClassStrings.ErrorLeafCertificateMustBeSet);
        }

        if (CaCertificate == null)
        {
            throw new InvalidOperationException(ClassStrings.ErrorCaCertificateMustBeSet);
        }

        if (Policies.Count == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorAtLeastOnePolicyMustBeAdded);
        }

        // Compute CA fingerprint
        byte[] caHash = ComputeHash(CaCertificate.RawData, HashAlgorithm);
        string caFingerprint = ConvertToBase64Url(caHash);

        // Build DID: did:x509:version:algorithm:fingerprint::policy1:value1::policy2:value2...
        var parts = new List<string>
        {
            DidX509Constants.DidMethod,
            DidX509Constants.MethodName,
            DidX509Constants.Version,
            HashAlgorithm,
            caFingerprint
        };

        string prefix = string.Join(DidX509Constants.ValueSeparator, parts);

        // Add policies
        var policyParts = Policies.Select(p => string.Concat(p.Name, DidX509Constants.ValueSeparator, p.Value));
        string policiesString = string.Join(DidX509Constants.PolicySeparator, policyParts);

        return string.Concat(prefix, DidX509Constants.PolicySeparator, policiesString);
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
            _ => throw new NotSupportedException(string.Format(ClassStrings.ErrorFormatUnsupportedHashAlgorithm, algorithm))
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