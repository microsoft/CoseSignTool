// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509;

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using DIDx509.Builder;

/// <summary>
/// Preference for selecting Extended Key Usage (EKU) OID when generating DIDs.
/// </summary>
public enum EkuPreference
{
    /// <summary>
    /// Use the first EKU OID found.
    /// </summary>
    First,

    /// <summary>
    /// Use the EKU OID with the most segments (most dots, highest specificity).
    /// </summary>
    MostSpecific,

    /// <summary>
    /// Use the EKU OID with the numerically largest value.
    /// </summary>
    Largest,

    /// <summary>
    /// Use the EKU OID with the most segments; if tied, select the one with the numerically largest last segment.
    /// </summary>
    MostSpecificAndLargest
}

/// <summary>
/// Extension methods for X509Certificate2 to simplify DID:X509 generation.
/// </summary>
public static class X509Certificate2Extensions
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorIntermediateIndexMustBeAtLeastOne = "Intermediate index must be >= 1 (1 = PCA)";
        public const string ErrorChainMustContainAtLeastOneCertificate = "Chain must contain at least 1 certificate";
        public const string ErrorFormatLocationOutOfRangeForChainLength = "Location {0} is out of range for chain of {1} certificates";

        public const string ErrorDidCannotBeNullOrEmpty = "DID cannot be null or empty";
    }

    /// <summary>
    /// Gets a fully customizable DID:X509 builder for this certificate.
    /// Use this for complete control over the DID generation.
    /// </summary>
    /// <param name="certificate">The leaf certificate.</param>
    /// <returns>A DID:X509 builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> is <see langword="null"/>.</exception>
    /// <example>
    /// <code>
    /// string did = cert.GetDidBuilder()
    ///     .WithCaCertificate(rootCert)
    ///     .WithHashAlgorithm("sha512")
    ///     .WithSubjectFromCertificate()
    ///     .WithEkuPolicy("1.3.6.1.4.1.311.10.3.13")
    ///     .Build();
    /// </code>
    /// </example>
    public static DidX509Builder GetDidBuilder(this X509Certificate2 certificate)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        return new DidX509Builder().WithLeafCertificate(certificate);
    }

    /// <summary>
    /// Gets a DID:X509 identifier using the root certificate from a chain (SHA-256 by default).
    /// Uses subject policy from the leaf certificate.
    /// </summary>
    /// <param name="certificate">The leaf certificate.</param>
    /// <param name="chain">The certificate chain (leaf first).</param>
    /// <param name="hashAlgorithm">Hash algorithm (sha256, sha384, or sha512). Default: sha256.</param>
    /// <returns>A DID:X509 identifier string.</returns>
    public static string GetDidWithRoot(
        this X509Certificate2 certificate,
        IEnumerable<X509Certificate2> chain,
        string hashAlgorithm = DidX509Constants.HashAlgorithmSha256)
    {
        return certificate.GetDidWithCertAtLocationInChain(chain, chain.Count() - 1, hashAlgorithm);
    }

    /// <summary>
    /// Gets a DID:X509 identifier using the Policy CA (immediate parent) from a chain.
    /// Uses subject policy from the leaf certificate.
    /// </summary>
    /// <param name="certificate">The leaf certificate.</param>
    /// <param name="chain">The certificate chain (leaf first, must have at least 2 certificates).</param>
    /// <param name="hashAlgorithm">Hash algorithm (sha256, sha384, or sha512). Default: sha256.</param>
    /// <returns>A DID:X509 identifier string.</returns>
    public static string GetDidWithPca(
        this X509Certificate2 certificate,
        IEnumerable<X509Certificate2> chain,
        string hashAlgorithm = DidX509Constants.HashAlgorithmSha256)
    {
        return certificate.GetDidWithCertAtLocationInChain(chain, 1, hashAlgorithm);
    }

    /// <summary>
    /// Gets a DID:X509 identifier using an intermediate certificate from a chain.
    /// Uses subject policy from the leaf certificate.
    /// </summary>
    /// <param name="certificate">The leaf certificate.</param>
    /// <param name="chain">The certificate chain (leaf first, must have at least 3 certificates).</param>
    /// <param name="intermediateIndex">Index of the intermediate (1-based, where 1 is PCA, 2 is next intermediate, etc.).</param>
    /// <param name="hashAlgorithm">Hash algorithm (sha256, sha384, or sha512). Default: sha256.</param>
    /// <returns>A DID:X509 identifier string.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="intermediateIndex"/> is less than 1.</exception>
    public static string GetDidWithIntermediate(
        this X509Certificate2 certificate,
        IEnumerable<X509Certificate2> chain,
        int intermediateIndex = 1,
        string hashAlgorithm = DidX509Constants.HashAlgorithmSha256)
    {
        if (intermediateIndex < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(intermediateIndex), ClassStrings.ErrorIntermediateIndexMustBeAtLeastOne);
        }

        return certificate.GetDidWithCertAtLocationInChain(chain, intermediateIndex, hashAlgorithm);
    }

    /// <summary>
    /// Gets a DID:X509 identifier using a certificate at a specific location in the chain.
    /// Supports both forward (0-based) and backward (negative) indexing.
    /// </summary>
    /// <param name="certificate">The leaf certificate.</param>
    /// <param name="chain">The certificate chain (leaf first).</param>
    /// <param name="location">Location in chain. Positive: 0=leaf, 1=PCA, etc. Negative: -1=root (last), -2=second from end.</param>
    /// <param name="hashAlgorithm">Hash algorithm (sha256, sha384, or sha512). Default: sha256.</param>
    /// <returns>A DID:X509 identifier string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> or <paramref name="chain"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="chain"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="location"/> is out of range for the provided chain.</exception>
    /// <remarks>
    /// For self-signed certificates (chain with only the leaf certificate), the leaf certificate
    /// is used as both the leaf and CA certificate in the DID.
    /// </remarks>
    public static string GetDidWithCertAtLocationInChain(
        this X509Certificate2 certificate,
        IEnumerable<X509Certificate2> chain,
        int location,
        string hashAlgorithm = DidX509Constants.HashAlgorithmSha256)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        if (chain == null)
        {
            throw new ArgumentNullException(nameof(chain));
        }

        var certArray = chain.ToArray();
        if (certArray.Length < 1)
        {
            throw new ArgumentException(ClassStrings.ErrorChainMustContainAtLeastOneCertificate, nameof(chain));
        }

        // For self-signed certificates (single cert chain), use the same cert as CA
        X509Certificate2 caCert;
        if (certArray.Length == 1)
        {
            caCert = certArray[0];
        }
        else
        {
            // Convert negative indices to positive (Python-style)
            int offset = location < 0 ? certArray.Length + location : location;
            if (offset < 0 || offset >= certArray.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(location), string.Format(ClassStrings.ErrorFormatLocationOutOfRangeForChainLength, location, certArray.Length));
            }

            caCert = certArray[offset];
        }

        return new DidX509Builder()
            .WithLeafCertificate(certificate)
            .WithCaCertificate(caCert)
            .WithHashAlgorithm(hashAlgorithm)
            .WithSubjectFromCertificate()
            .Build();
    }

    /// <summary>
    /// Gets a DID:X509 identifier with an EKU policy added.
    /// </summary>
    /// <param name="certificate">The leaf certificate.</param>
    /// <param name="chain">The certificate chain (leaf first).</param>
    /// <param name="ekuPreference">Preference for selecting which EKU to use if multiple are present.</param>
    /// <param name="ekuPrefixFilter">Optional OID prefix to filter EKUs (e.g., "1.3.6.1.4.1" for enterprise-specific).</param>
    /// <param name="hashAlgorithm">Hash algorithm (sha256, sha384, or sha512). Default: sha256.</param>
    /// <returns>A DID:X509 identifier string with EKU policy.</returns>
    public static string GetDidWithRootAndEku(
        this X509Certificate2 certificate,
        IEnumerable<X509Certificate2> chain,
        EkuPreference ekuPreference = EkuPreference.First,
        string? ekuPrefixFilter = null,
        string hashAlgorithm = DidX509Constants.HashAlgorithmSha256)
    {
        return certificate.GetDidWithCertAtLocationInChainAndEku(
            chain,
            -1, // Use root certificate (last in chain)
            ekuPreference,
            ekuPrefixFilter,
            hashAlgorithm);
    }

    /// <summary>
    /// Gets a DID:X509 identifier with subject and EKU policies.
    /// </summary>
    /// <param name="certificate">The leaf certificate.</param>
    /// <param name="chain">The certificate chain (leaf first).</param>
    /// <param name="location">Location in chain for CA pinning. Positive: 0=leaf, 1=PCA. Negative: -1=root.</param>
    /// <param name="ekuPreference">Preference for selecting which EKU to use if multiple are present.</param>
    /// <param name="ekuPrefixFilter">Optional OID prefix to filter EKUs (e.g., "1.3.6.1.4.1" for enterprise-specific).</param>
    /// <param name="hashAlgorithm">Hash algorithm (sha256, sha384, or sha512). Default: sha256.</param>
    /// <returns>A DID:X509 identifier string with subject and EKU policies.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> is <see langword="null"/>.</exception>
    public static string GetDidWithCertAtLocationInChainAndEku(
        this X509Certificate2 certificate,
        IEnumerable<X509Certificate2> chain,
        int location,
        EkuPreference ekuPreference = EkuPreference.First,
        string? ekuPrefixFilter = null,
        string hashAlgorithm = DidX509Constants.HashAlgorithmSha256)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        // Get the base builder with subject policy
        var builder = new DidX509Builder()
            .WithLeafCertificate(certificate)
            .WithCertificateChain(chain)
            .WithHashAlgorithm(hashAlgorithm)
            .WithSubjectFromCertificate();

        // Update to use specific CA location if needed
        var certArray = chain.ToArray();
        int offset = location < 0 ? certArray.Length + location : location;
        if (offset > 0 && offset < certArray.Length)
        {
            builder.WithCaCertificate(certArray[offset]);
        }

        // Extract and add EKU if present
        var ekuOid = certificate.SelectEku(ekuPreference, ekuPrefixFilter);
        if (ekuOid != null)
        {
            builder.WithEkuPolicy(ekuOid);
        }

        return builder.Build();
    }

    /// <summary>
    /// Gets a DID:X509 identifier with a SAN policy.
    /// </summary>
    /// <param name="certificate">The leaf certificate.</param>
    /// <param name="chain">The certificate chain (leaf first).</param>
    /// <param name="sanType">SAN type (email, dns, or uri). If null, uses the first available SAN.</param>
    /// <param name="hashAlgorithm">Hash algorithm (sha256, sha384, or sha512). Default: sha256.</param>
    /// <returns>A DID:X509 identifier string with SAN policy, or null if no matching SAN found.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> is <see langword="null"/>.</exception>
    public static string? GetDidWithRootAndSan(
        this X509Certificate2 certificate,
        IEnumerable<X509Certificate2> chain,
        string? sanType = null,
        string hashAlgorithm = DidX509Constants.HashAlgorithmSha256)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        var builder = new DidX509Builder()
            .WithCertificateChain(chain)
            .WithHashAlgorithm(hashAlgorithm);

        // Try to add SAN policy
        var sanExt = certificate.Extensions
            .OfType<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == DidX509Constants.OidSubjectAlternativeName);

        if (sanExt == null)
        {
            return null;
        }

        // Use cross-platform SAN parser
        var sanResult = SanParser.GetFirstSan(sanExt, sanType);

        if (sanResult.HasValue)
        {
            builder.WithSanPolicy(sanResult.Value.Type, sanResult.Value.Value);
            return builder.Build();
        }

        return null;
    }

    /// <summary>
    /// Selects an EKU OID from the certificate based on the specified preference.
    /// </summary>
    private static string? SelectEku(
        this X509Certificate2 certificate,
        EkuPreference preference,
        string? prefixFilter)
    {
        var ekuExt = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();

        if (ekuExt == null || ekuExt.EnhancedKeyUsages.Count == 0)
        {
            return null;
        }

        // Get all EKU OIDs
        var ekus = ekuExt.EnhancedKeyUsages
            .Cast<System.Security.Cryptography.Oid>()
            .Where(oid => !string.IsNullOrEmpty(oid.Value))
            .Select(oid => oid.Value!)
            .ToList();

        // Filter by prefix if specified
        if (!string.IsNullOrEmpty(prefixFilter))
        {
            ekus = ekus.Where(oid => oid.StartsWith(prefixFilter, StringComparison.Ordinal)).ToList();
        }

        if (ekus.Count == 0)
        {
            return null;
        }

        return preference switch
        {
            EkuPreference.First => ekus[0],
            EkuPreference.MostSpecific => ekus.OrderByDescending(oid => oid.Split('.').Length).First(),
            EkuPreference.Largest => ekus.OrderByDescending(oid => oid,
                Comparer<string>.Create((a, b) =>
                {
                    var aParts = a.Split('.');
                    var bParts = b.Split('.');
                    int maxLen = Math.Max(aParts.Length, bParts.Length);

                    // Compare each segment numerically from left to right
                    for (int i = 0; i < maxLen; i++)
                    {
                        long aVal = i < aParts.Length && long.TryParse(aParts[i], out long aTemp) ? aTemp : 0;
                        long bVal = i < bParts.Length && long.TryParse(bParts[i], out long bTemp) ? bTemp : 0;

                        int cmp = aVal.CompareTo(bVal);
                        if (cmp != 0)
                        {
                            return cmp;
                        }
                    }

                    return 0;
                })).First(),
            EkuPreference.MostSpecificAndLargest => ekus
                .OrderByDescending(oid => oid.Split('.').Length)
                .ThenByDescending(oid =>
                {
                    var parts = oid.Split('.');
                    return long.TryParse(parts[parts.Length - 1], out long lastSegment) ? lastSegment : 0;
                })
                .First(),
            _ => ekus[0]
        };
    }

    // ==================== Verification Extension Methods ====================

    /// <summary>
    /// Verifies that this certificate (leaf) matches the specified DID:X509 identifier.
    /// This is a convenience method that validates the DID against a certificate chain.
    /// </summary>
    /// <param name="certificate">The leaf certificate to verify.</param>
    /// <param name="did">The DID:X509 identifier to verify against.</param>
    /// <param name="chain">The certificate chain (leaf first).</param>
    /// <param name="validateChain">Whether to perform RFC 5280 chain validation (default: true).</param>
    /// <param name="checkRevocation">Whether to check certificate revocation (default: false).</param>
    /// <returns>True if the certificate matches the DID; otherwise, false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> or <paramref name="chain"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="did"/> is <see langword="null"/> or empty.</exception>
    /// <example>
    /// <code>
    /// // Simple verification
    /// if (leafCert.VerifyByDid(did, certificateChain))
    /// {
    ///     Console.WriteLine("Certificate matches DID!");
    /// }
    /// 
    /// // Verification without chain validation (faster)
    /// if (leafCert.VerifyByDid(did, certificateChain, validateChain: false))
    /// {
    ///     Console.WriteLine("Policies match!");
    /// }
    /// </code>
    /// </example>
    public static bool VerifyByDid(
        this X509Certificate2 certificate,
        string did,
        IEnumerable<X509Certificate2> chain,
        bool validateChain = true,
        bool checkRevocation = false)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        if (string.IsNullOrWhiteSpace(did))
        {
            throw new ArgumentException(ClassStrings.ErrorDidCannotBeNullOrEmpty, nameof(did));
        }

        if (chain == null)
        {
            throw new ArgumentNullException(nameof(chain));
        }

        var result = Validation.DidX509Validator.Validate(did, chain, validateChain, checkRevocation);
        return result.IsValid;
    }

    /// <summary>
    /// Verifies that this certificate (leaf) matches the specified DID:X509 identifier,
    /// returning detailed validation result with errors if validation fails.
    /// </summary>
    /// <param name="certificate">The leaf certificate to verify.</param>
    /// <param name="did">The DID:X509 identifier to verify against.</param>
    /// <param name="chain">The certificate chain (leaf first).</param>
    /// <param name="validateChain">Whether to perform RFC 5280 chain validation (default: true).</param>
    /// <param name="checkRevocation">Whether to check certificate revocation (default: false).</param>
    /// <returns>A detailed validation result with success status and errors.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> or <paramref name="chain"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="did"/> is <see langword="null"/> or empty.</exception>
    /// <example>
    /// <code>
    /// var result = leafCert.VerifyByDidDetailed(did, certificateChain);
    /// if (result.IsValid)
    /// {
    ///     Console.WriteLine("Valid! Parsed DID: " + result.ParsedDid.Version);
    /// }
    /// else
    /// {
    ///     foreach (var error in result.Errors)
    ///     {
    ///         Console.WriteLine($"Error: {error}");
    ///     }
    /// }
    /// </code>
    /// </example>
    public static Models.DidX509ValidationResult VerifyByDidDetailed(
        this X509Certificate2 certificate,
        string did,
        IEnumerable<X509Certificate2> chain,
        bool validateChain = true,
        bool checkRevocation = false)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        if (string.IsNullOrWhiteSpace(did))
        {
            throw new ArgumentException(ClassStrings.ErrorDidCannotBeNullOrEmpty, nameof(did));
        }

        if (chain == null)
        {
            throw new ArgumentNullException(nameof(chain));
        }

        return Validation.DidX509Validator.Validate(did, chain, validateChain, checkRevocation);
    }

    /// <summary>
    /// Verifies that this certificate (leaf) matches the specified DID:X509 identifier,
    /// validating policies only without performing RFC 5280 chain validation.
    /// This is faster but less secure - use when chain validation is performed separately.
    /// </summary>
    /// <param name="certificate">The leaf certificate to verify.</param>
    /// <param name="did">The DID:X509 identifier to verify against.</param>
    /// <param name="chain">The certificate chain (leaf first).</param>
    /// <returns>True if the certificate policies match the DID; otherwise, false.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> or <paramref name="chain"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="did"/> is <see langword="null"/> or empty.</exception>
    /// <example>
    /// <code>
    /// // Fast policy-only verification (no chain validation)
    /// if (leafCert.VerifyByDidPoliciesOnly(did, certificateChain))
    /// {
    ///     Console.WriteLine("Policies match!");
    /// }
    /// </code>
    /// </example>
    public static bool VerifyByDidPoliciesOnly(
        this X509Certificate2 certificate,
        string did,
        IEnumerable<X509Certificate2> chain)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        if (string.IsNullOrWhiteSpace(did))
        {
            throw new ArgumentException(ClassStrings.ErrorDidCannotBeNullOrEmpty, nameof(did));
        }

        if (chain == null)
        {
            throw new ArgumentNullException(nameof(chain));
        }

        var result = Validation.DidX509Validator.ValidatePoliciesOnly(did, chain);
        return result.IsValid;
    }

    /// <summary>
    /// Attempts to verify this certificate against a DID:X509 identifier,
    /// returning false on any errors instead of throwing exceptions.
    /// </summary>
    /// <param name="certificate">The leaf certificate to verify.</param>
    /// <param name="did">The DID:X509 identifier to verify against.</param>
    /// <param name="chain">The certificate chain (leaf first).</param>
    /// <param name="errors">Output parameter containing validation errors if verification fails.</param>
    /// <param name="validateChain">Whether to perform RFC 5280 chain validation (default: true).</param>
    /// <param name="checkRevocation">Whether to check certificate revocation (default: false).</param>
    /// <returns>True if verification succeeds; otherwise, false with errors populated.</returns>
    /// <example>
    /// <code>
    /// if (leafCert.TryVerifyByDid(did, certificateChain, out var errors))
    /// {
    ///     Console.WriteLine("Success!");
    /// }
    /// else
    /// {
    ///     Console.WriteLine($"Failed: {string.Join(", ", errors)}");
    /// }
    /// </code>
    /// </example>
    public static bool TryVerifyByDid(
        this X509Certificate2 certificate,
        string did,
        IEnumerable<X509Certificate2> chain,
        out IReadOnlyList<string> errors,
        bool validateChain = true,
        bool checkRevocation = false)
    {
        try
        {
            var result = Validation.DidX509Validator.Validate(did, chain, validateChain, checkRevocation);
            errors = result.Errors;
            return result.IsValid;
        }
        catch (Exception ex)
        {
            errors = new[] { ex.Message };
            return false;
        }
    }

    /// <summary>
    /// Verifies that this certificate chain matches the specified DID:X509 identifier
    /// and resolves to a DID Document in one operation.
    /// </summary>
    /// <param name="certificate">The leaf certificate to verify.</param>
    /// <param name="did">The DID:X509 identifier to verify against.</param>
    /// <param name="chain">The certificate chain (leaf first).</param>
    /// <param name="document">Output parameter containing the resolved DID Document if verification succeeds.</param>
    /// <param name="validateChain">Whether to perform RFC 5280 chain validation (default: true).</param>
    /// <param name="checkRevocation">Whether to check certificate revocation (default: false).</param>
    /// <returns>True if verification and resolution succeed; otherwise, false.</returns>
    /// <example>
    /// <code>
    /// if (leafCert.VerifyByDidAndResolve(did, certificateChain, out var document))
    /// {
    ///     Console.WriteLine($"Valid! DID Document ID: {document.Id}");
    ///     Console.WriteLine($"Verification methods: {document.VerificationMethods.Count}");
    /// }
    /// </code>
    /// </example>
    public static bool VerifyByDidAndResolve(
        this X509Certificate2 certificate,
        string did,
        IEnumerable<X509Certificate2> chain,
        out Resolution.DidDocument? document,
        bool validateChain = true,
        bool checkRevocation = false)
    {
        try
        {
            document = Resolution.DidX509Resolver.Resolve(did, chain, validateChain, checkRevocation);
            return true;
        }
        catch
        {
            document = null;
            return false;
        }
    }
}