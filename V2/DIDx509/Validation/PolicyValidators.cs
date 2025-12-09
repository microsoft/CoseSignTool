// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Validation;

using DIDx509.Models;
using DIDx509.Parsing;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Validates the "subject" policy against a certificate chain.
/// </summary>
internal static class SubjectPolicyValidator
{
    /// <summary>
    /// Validates that the leaf certificate subject contains all specified attributes.
    /// </summary>
    public static bool Validate(DidX509Policy policy, CertificateChainModel chain, out List<string> errors)
    {
        errors = new List<string>();

        if (policy.ParsedValue is not Dictionary<string, string> requiredAttributes)
        {
            errors.Add($"{DidX509Constants.ErrorInvalidSubjectPolicy}: Failed to parse policy value");
            return false;
        }

        if (requiredAttributes.Count == 0)
        {
            errors.Add($"{DidX509Constants.ErrorInvalidSubjectPolicy}: Must contain at least one attribute");
            return false;
        }

        var leafSubject = chain.LeafCertificate.Subject;

        // Check if all required attributes are present in the leaf certificate subject
        foreach (var kvp in requiredAttributes)
        {
            string? actualValue = leafSubject.GetAttribute(kvp.Key);
            
            if (actualValue == null)
            {
                errors.Add($"Subject policy validation failed: Required attribute '{kvp.Key}' not found in leaf certificate subject");
                return false;
            }

            if (!string.Equals(actualValue, kvp.Value, System.StringComparison.Ordinal))
            {
                errors.Add($"Subject policy validation failed: Attribute '{kvp.Key}' value mismatch (expected '{kvp.Value}', got '{actualValue}')");
                return false;
            }
        }

        return true;
    }
}

/// <summary>
/// Validates the "san" policy against a certificate chain.
/// </summary>
internal static class SanPolicyValidator
{
    /// <summary>
    /// Validates that the leaf certificate contains the specified SAN.
    /// </summary>
    public static bool Validate(DidX509Policy policy, CertificateChainModel chain, out List<string> errors)
    {
        errors = new List<string>();

        if (!(policy.ParsedValue is ValueTuple<string, string> sanTuple))
        {
            errors.Add($"{DidX509Constants.ErrorInvalidSanPolicy}: Failed to parse policy value");
            return false;
        }

        var leafExtensions = chain.LeafCertificate.Extensions;

        if (leafExtensions.San == null || leafExtensions.San.Count == 0)
        {
            errors.Add("SAN policy validation failed: Leaf certificate has no Subject Alternative Names");
            return false;
        }

        // Check if the required SAN is present
        bool found = leafExtensions.San.Any(san =>
            string.Equals(san.Type, sanTuple.Item1, System.StringComparison.OrdinalIgnoreCase) &&
            san.ValueAsString != null &&
            string.Equals(san.ValueAsString, sanTuple.Item2, System.StringComparison.Ordinal));

        if (!found)
        {
            errors.Add($"SAN policy validation failed: Required SAN '{sanTuple.Item1}:{sanTuple.Item2}' not found in leaf certificate");
            return false;
        }

        return true;
    }
}

/// <summary>
/// Validates the "eku" policy against a certificate chain.
/// </summary>
internal static class EkuPolicyValidator
{
    /// <summary>
    /// Validates that the leaf certificate contains the specified EKU OID.
    /// </summary>
    public static bool Validate(DidX509Policy policy, CertificateChainModel chain, out List<string> errors)
    {
        errors = new List<string>();

        if (policy.ParsedValue is not string requiredEkuOid)
        {
            errors.Add($"{DidX509Constants.ErrorInvalidEkuPolicy}: Failed to parse policy value");
            return false;
        }

        var leafExtensions = chain.LeafCertificate.Extensions;

        if (leafExtensions.Eku == null || leafExtensions.Eku.Count == 0)
        {
            errors.Add("EKU policy validation failed: Leaf certificate has no Extended Key Usage extension");
            return false;
        }

        // Check if the required EKU OID is present
        bool found = leafExtensions.Eku.Any(oid =>
            string.Equals(oid, requiredEkuOid, System.StringComparison.Ordinal));

        if (!found)
        {
            errors.Add($"EKU policy validation failed: Required EKU OID '{requiredEkuOid}' not found in leaf certificate");
            return false;
        }

        return true;
    }
}

/// <summary>
/// Validates the "fulcio-issuer" policy against a certificate chain.
/// </summary>
internal static class FulcioIssuerPolicyValidator
{
    /// <summary>
    /// Validates that the leaf certificate contains the specified Fulcio issuer.
    /// </summary>
    public static bool Validate(DidX509Policy policy, CertificateChainModel chain, out List<string> errors)
    {
        errors = new List<string>();

        if (policy.ParsedValue is not string requiredIssuerSuffix)
        {
            errors.Add($"{DidX509Constants.ErrorInvalidFulcioPolicy}: Failed to parse policy value");
            return false;
        }

        var leafExtensions = chain.LeafCertificate.Extensions;

        if (string.IsNullOrEmpty(leafExtensions.FulcioIssuer))
        {
            errors.Add("Fulcio issuer policy validation failed: Leaf certificate has no Fulcio issuer extension");
            return false;
        }

        // The policy value should match the issuer URL without the "https://" prefix
        string expectedUrl = DidX509Constants.ProtocolHttps + requiredIssuerSuffix;
        
        if (!string.Equals(leafExtensions.FulcioIssuer, expectedUrl, System.StringComparison.Ordinal))
        {
            errors.Add($"Fulcio issuer policy validation failed: Expected '{expectedUrl}', got '{leafExtensions.FulcioIssuer}'");
            return false;
        }

        return true;
    }
}
