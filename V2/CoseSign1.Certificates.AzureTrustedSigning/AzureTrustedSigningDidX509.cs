// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using DIDx509.Builder;

namespace CoseSign1.Certificates.AzureTrustedSigning;

/// <summary>
/// Generates DID:X509 identifiers specifically for Azure Trusted Signing certificates.
/// Format: did:x509:0:sha256:{base64url-hash}::eku:{oid}
/// Per the DID:X509 specification at https://github.com/microsoft/did-x509/blob/main/specification.md#eku-policy
/// </summary>
/// <remarks>
/// <para>
/// Azure Trusted Signing certificates include Microsoft-specific Enhanced Key Usage (EKU) extensions
/// that identify the certificate's intended purpose. This generator creates EKU-based DID identifiers
/// when Microsoft EKUs (starting with 1.3.6.1.4.1.311) are present in the certificate.
/// </para>
/// <para>
/// Per the DID:X509 EKU Policy specification:
/// - Format: did:x509:0:{algorithm}:{base64url-hash}::eku:{oid}
/// - {oid} is a single OID from chain[0].extensions.eku in dotted decimal notation
/// - The OID is NOT percent-encoded (it's just the raw OID string)
/// - The base64url-encoded hash is 43 characters for SHA256 (RFC 4648 Section 5)
/// </para>
/// <para>
/// The "deepest greatest" Microsoft EKU is selected based on OID depth and last segment value
/// when multiple Microsoft EKUs are present.
/// </para>
/// </remarks>
public static class AzureTrustedSigningDidX509
{
    /// <summary>
    /// Microsoft reserved EKU prefix used by Azure Trusted Signing certificates.
    /// </summary>
    private const string MicrosoftEkuPrefix = ClassStrings.MicrosoftEkuPrefix;

    /// <summary>
    /// Generates a DID:X509:0 identifier from an Azure Trusted Signing certificate chain.
    /// Uses EKU-based format when Microsoft EKUs are present, otherwise uses standard format.
    /// </summary>
    /// <param name="certificateChain">The certificate chain (leaf-first order).</param>
    /// <returns>
    /// A DID:X509:0 formatted identifier. Example:
    /// did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::eku:1.3.6.1.4.1.311.10.3.13
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateChain"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="certificateChain"/> is empty.</exception>
    public static string Generate(IEnumerable<X509Certificate2> certificateChain)
    {
        if (certificateChain == null)
        {
            throw new ArgumentNullException(nameof(certificateChain));
        }

        var certArray = certificateChain.ToArray();
        if (certArray.Length == 0)
        {
            throw new ArgumentException(ClassStrings.ErrorCertificateChainCannotBeEmpty, nameof(certificateChain));
        }

        var leafCert = certArray[0];

        // Check for Microsoft EKUs in the leaf certificate
        var microsoftEku = GetDeepestGreatestMicrosoftEku(leafCert);

        if (microsoftEku != null)
        {
            // Use EKU-based format for Azure Trusted Signing certificates
            return new DidX509Builder()
                .WithCertificateChain(certArray)
                .WithEkuPolicy(microsoftEku)
                .Build();
        }
        else
        {
            // Fall back to standard DID:X509 format (no policy)
            return new DidX509Builder()
                .WithCertificateChain(certArray)
                .Build();
        }
    }

    /// <summary>
    /// Generates a DID:X509:0 identifier with EKU policy from a leaf certificate and CA certificate.
    /// </summary>
    /// <param name="leafCertificate">The leaf certificate.</param>
    /// <param name="caCertificate">The CA certificate to pin to.</param>
    /// <returns>A DID:X509:0 formatted identifier with EKU policy.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="leafCertificate"/> or <paramref name="caCertificate"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the leaf certificate does not contain a Microsoft EKU.</exception>
    public static string GenerateWithEku(X509Certificate2 leafCertificate, X509Certificate2 caCertificate)
    {
        if (leafCertificate == null)
        {
            throw new ArgumentNullException(nameof(leafCertificate));
        }

        if (caCertificate == null)
        {
            throw new ArgumentNullException(nameof(caCertificate));
        }

        var microsoftEku = GetDeepestGreatestMicrosoftEku(leafCertificate);
        if (microsoftEku == null)
        {
            throw new InvalidOperationException(ClassStrings.ErrorNoMicrosoftEkuFoundInCertificate);
        }

        return new DidX509Builder()
            .WithLeafCertificate(leafCertificate)
            .WithCaCertificate(caCertificate)
            .WithEkuPolicy(microsoftEku)
            .Build();
    }

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string MicrosoftEkuPrefix = "1.3.6.1.4.1.311";
        public const string ErrorCertificateChainCannotBeEmpty = "Certificate chain cannot be empty";
        public const string ErrorNoMicrosoftEkuFoundInCertificate = "No Microsoft EKU found in certificate. Azure Trusted Signing certificates should contain Microsoft-specific EKU extensions.";
    }

    /// <summary>
    /// Finds the "deepest greatest" Microsoft EKU from a certificate's EKU extension.
    /// </summary>
    /// <remarks>
    /// Selection criteria:
    /// 1. Filter to Microsoft EKUs (starting with 1.3.6.1.4.1.311)
    /// 2. Select the OID with the most segments (deepest)
    /// 3. If tied, select the one with the greatest last segment value
    /// </remarks>
    private static string? GetDeepestGreatestMicrosoftEku(X509Certificate2 certificate)
    {
        // Get the EKU extension
        var ekuExtension = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();

        if (ekuExtension == null)
        {
            return null;
        }

        // Filter to Microsoft EKUs and select deepest/greatest
        var microsoftEkus = ekuExtension.EnhancedKeyUsages
            .Cast<System.Security.Cryptography.Oid>()
            .Where(oid => oid.Value?.StartsWith(MicrosoftEkuPrefix, StringComparison.Ordinal) == true)
            .Select(oid => oid.Value!)
            .ToList();

        if (microsoftEkus.Count == 0)
        {
            return null;
        }

        // Find the deepest (most segments) and greatest (highest last segment)
        return microsoftEkus
            .OrderByDescending(eku => GetSegmentCount(eku))
            .ThenByDescending(eku => GetLastSegment(eku))
            .FirstOrDefault();
    }

    /// <summary>
    /// Gets the number of segments in an OID (e.g., "1.2.3.4" has 4 segments).
    /// </summary>
    private static int GetSegmentCount(string oid)
    {
        return oid.Split('.').Length;
    }

    /// <summary>
    /// Gets the last segment value of an OID (e.g., "1.2.3.4" returns 4).
    /// Returns 0 if parsing fails.
    /// </summary>
    private static int GetLastSegment(string oid)
    {
        var segments = oid.Split('.');
        if (segments.Length == 0)
        {
            return 0;
        }

        return int.TryParse(segments[segments.Length - 1], out var value) ? value : 0;
    }
}