// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.AzureTrustedSigning;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Extensions;

/// <summary>
/// Generates DID:X509:0 identifiers specifically for Azure Trusted Signing certificates.
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
public class AzureTrustedSigningDidX509Generator : DidX509Generator
{
    /// <summary>
    /// Microsoft reserved EKU prefix used by Azure Trusted Signing certificates.
    /// </summary>
    private const string MicrosoftEkuPrefix = "1.3.6.1.4.1.311";

    /// <summary>
    /// Generates a DID:X509:0 identifier from an Azure Trusted Signing certificate chain.
    /// Uses EKU-based format when Microsoft EKUs are present, otherwise delegates to base implementation.
    /// </summary>
    /// <param name="certificates">The certificate chain. First certificate must be the leaf.</param>
    /// <returns>
    /// A DID:X509:0 formatted identifier. Example:
    /// did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::eku:1.3.6.1.4.1.311.10.3.13
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when certificates is null.</exception>
    /// <exception cref="ArgumentException">Thrown when chain is empty or invalid.</exception>
    public override string GenerateFromChain(IEnumerable<X509Certificate2> certificates)
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
        
        // Generate the base DID using subject policy from the base class
        string baseDid = base.GenerateFromChain(certificates);
        
        // Extract EKUs from the leaf certificate
        List<string> ekus = ExtractEkus(leafCert);
        
        // Filter to Microsoft EKUs (Azure Trusted Signing specific)
        List<string> microsoftEkus = ekus
            .Where(eku => eku.StartsWith(MicrosoftEkuPrefix, StringComparison.OrdinalIgnoreCase))
            .ToList();
        
        // If no Microsoft EKUs present, return the base implementation (subject policy)
        if (microsoftEkus.Count == 0)
        {
            return baseDid;
        }
        
        // Select the deepest greatest Microsoft EKU per Azure Trusted Signing conventions
        string deepestGreatestEku = SelectDeepestGreatestEku(microsoftEkus);
        
        // Replace the ::subject: portion with ::eku:{oid}
        // Per spec: policy-value for EKU is just the OID, not percent-encoded
        int subjectIndex = baseDid.IndexOf("::subject:", StringComparison.OrdinalIgnoreCase);
        if (subjectIndex == -1)
        {
            // Should not happen if base class follows spec, but handle gracefully
            return baseDid;
        }
        
        string didPrefix = baseDid.Substring(0, subjectIndex);
        return $"{didPrefix}::eku:{deepestGreatestEku}";
    }

    /// <summary>
    /// Extracts Enhanced Key Usage (EKU) OIDs from a certificate.
    /// </summary>
    /// <param name="certificate">The certificate to extract EKUs from.</param>
    /// <returns>A list of EKU OID strings in dotted decimal notation.</returns>
    protected virtual List<string> ExtractEkus(X509Certificate2 certificate)
    {
        List<string> ekus = new();
        
        // Find the Enhanced Key Usage extension
        X509Extension? ekuExtension = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .FirstOrDefault();
        
        if (ekuExtension == null)
        {
            return ekus;
        }
        
        X509EnhancedKeyUsageExtension enhancedKeyUsage = (X509EnhancedKeyUsageExtension)ekuExtension;
        
        foreach (Oid oid in enhancedKeyUsage.EnhancedKeyUsages)
        {
            if (!string.IsNullOrEmpty(oid.Value))
            {
                ekus.Add(oid.Value);
            }
        }
        
        return ekus;
    }

    /// <summary>
    /// Selects the "deepest greatest" Microsoft EKU from a list of EKU OIDs.
    /// The deepest EKU is the one with the most OID segments (highest depth).
    /// If multiple EKUs have the same depth, the one with the greatest last segment numeric value is selected.
    /// </summary>
    /// <param name="ekus">The list of Microsoft EKU OID strings to evaluate.</param>
    /// <returns>The OID string of the deepest greatest Microsoft EKU in dotted decimal notation.</returns>
    protected virtual string SelectDeepestGreatestEku(List<string> ekus)
    {
        if (ekus.Count == 0)
        {
            throw new ArgumentException("EKU list cannot be empty.", nameof(ekus));
        }

        if (ekus.Count == 1)
        {
            return ekus[0];
        }

        string deepestGreatest = ekus[0];
        int maxDepth = CountSegments(deepestGreatest);
        long maxLastSegment = GetLastSegmentValue(deepestGreatest);

        for (int i = 1; i < ekus.Count; i++)
        {
            string currentEku = ekus[i];
            int currentDepth = CountSegments(currentEku);
            long currentLastSegment = GetLastSegmentValue(currentEku);

            // Compare by depth first
            if (currentDepth > maxDepth)
            {
                deepestGreatest = currentEku;
                maxDepth = currentDepth;
                maxLastSegment = currentLastSegment;
            }
            // If depth is the same, compare by last segment value
            else if (currentDepth == maxDepth && currentLastSegment > maxLastSegment)
            {
                deepestGreatest = currentEku;
                maxLastSegment = currentLastSegment;
            }
        }

        return deepestGreatest;
    }

    /// <summary>
    /// Counts the number of segments in an OID string (number of dots + 1).
    /// </summary>
    /// <param name="oid">The OID string in dotted decimal notation.</param>
    /// <returns>The number of segments (depth of the OID).</returns>
    protected virtual int CountSegments(string oid)
    {
        if (string.IsNullOrEmpty(oid))
        {
            return 0;
        }

        return oid.Split('.').Length;
    }

    /// <summary>
    /// Gets the numeric value of the last segment in an OID string.
    /// </summary>
    /// <param name="oid">The OID string in dotted decimal notation.</param>
    /// <returns>The numeric value of the last segment, or 0 if parsing fails.</returns>
    protected virtual long GetLastSegmentValue(string oid)
    {
        if (string.IsNullOrEmpty(oid))
        {
            return 0;
        }

        string[] segments = oid.Split('.');
        if (segments.Length == 0)
        {
            return 0;
        }

        string lastSegment = segments[segments.Length - 1];
        return long.TryParse(lastSegment, out long value) ? value : 0;
    }
}
