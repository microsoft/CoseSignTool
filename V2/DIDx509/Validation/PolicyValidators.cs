// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Validation;

using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using DIDx509.Models;

/// <summary>
/// Validates the "subject" policy against a certificate chain.
/// </summary>
internal static class SubjectPolicyValidator
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ErrorFailedToParsePolicyValue =
            string.Concat(DidX509Constants.ErrorInvalidSubjectPolicy, ": Failed to parse policy value");
        public static readonly string ErrorMustContainAtLeastOneAttribute =
            string.Concat(DidX509Constants.ErrorInvalidSubjectPolicy, ": Must contain at least one attribute");

        public const string ErrorRequiredAttributeNotFound =
            "Subject policy validation failed: Required attribute '{0}' not found in leaf certificate subject";
        public const string ErrorAttributeValueMismatch =
            "Subject policy validation failed: Attribute '{0}' value mismatch (expected '{1}', got '{2}')";
    }

    /// <summary>
    /// Validates that the leaf certificate subject contains all specified attributes.
    /// </summary>
    /// <param name="policy">The policy to validate.</param>
    /// <param name="chain">The certificate chain model.</param>
    /// <param name="errors">When this method returns, contains validation errors if validation failed.</param>
    /// <returns><see langword="true"/> if the policy validates; otherwise, <see langword="false"/>.</returns>
    public static bool Validate(DidX509Policy policy, CertificateChainModel chain, out List<string> errors)
    {
        errors = new List<string>();

        if (policy.ParsedValue is not Dictionary<string, string> requiredAttributes)
        {
            errors.Add(ClassStrings.ErrorFailedToParsePolicyValue);
            return false;
        }

        if (requiredAttributes.Count == 0)
        {
            errors.Add(ClassStrings.ErrorMustContainAtLeastOneAttribute);
            return false;
        }

        var leafSubject = chain.LeafCertificate.Subject;

        // Check if all required attributes are present in the leaf certificate subject
        foreach (var kvp in requiredAttributes)
        {
            string? actualValue = leafSubject.GetAttribute(kvp.Key);

            if (actualValue == null)
            {
                errors.Add(string.Format(ClassStrings.ErrorRequiredAttributeNotFound, kvp.Key));
                return false;
            }

            if (!string.Equals(actualValue, kvp.Value, System.StringComparison.Ordinal))
            {
                errors.Add(string.Format(ClassStrings.ErrorAttributeValueMismatch, kvp.Key, kvp.Value, actualValue));
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
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ErrorFailedToParsePolicyValue =
            string.Concat(DidX509Constants.ErrorInvalidSanPolicy, ": Failed to parse policy value");

        public const string ErrorNoSans =
            "SAN policy validation failed: Leaf certificate has no Subject Alternative Names";
        public const string ErrorRequiredSanNotFound =
            "SAN policy validation failed: Required SAN '{0}:{1}' not found in leaf certificate";
    }

    /// <summary>
    /// Validates that the leaf certificate contains the specified SAN.
    /// </summary>
    /// <param name="policy">The policy to validate.</param>
    /// <param name="chain">The certificate chain model.</param>
    /// <param name="errors">When this method returns, contains validation errors if validation failed.</param>
    /// <returns><see langword="true"/> if the policy validates; otherwise, <see langword="false"/>.</returns>
    public static bool Validate(DidX509Policy policy, CertificateChainModel chain, out List<string> errors)
    {
        errors = new List<string>();

        if (!(policy.ParsedValue is ValueTuple<string, string> sanTuple))
        {
            errors.Add(ClassStrings.ErrorFailedToParsePolicyValue);
            return false;
        }

        var leafExtensions = chain.LeafCertificate.Extensions;

        if (leafExtensions.San == null || leafExtensions.San.Count == 0)
        {
            errors.Add(ClassStrings.ErrorNoSans);
            return false;
        }

        // Check if the required SAN is present
        bool found = leafExtensions.San.Any(san =>
            string.Equals(san.Type, sanTuple.Item1, System.StringComparison.OrdinalIgnoreCase) &&
            san.ValueAsString != null &&
            string.Equals(san.ValueAsString, sanTuple.Item2, System.StringComparison.Ordinal));

        if (!found)
        {
            errors.Add(string.Format(ClassStrings.ErrorRequiredSanNotFound, sanTuple.Item1, sanTuple.Item2));
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
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ErrorFailedToParsePolicyValue =
            string.Concat(DidX509Constants.ErrorInvalidEkuPolicy, ": Failed to parse policy value");

        public const string ErrorNoEku =
            "EKU policy validation failed: Leaf certificate has no Extended Key Usage extension";
        public const string ErrorRequiredEkuNotFound =
            "EKU policy validation failed: Required EKU OID '{0}' not found in leaf certificate";
    }

    /// <summary>
    /// Validates that the leaf certificate contains the specified EKU OID.
    /// </summary>
    /// <param name="policy">The policy to validate.</param>
    /// <param name="chain">The certificate chain model.</param>
    /// <param name="errors">When this method returns, contains validation errors if validation failed.</param>
    /// <returns><see langword="true"/> if the policy validates; otherwise, <see langword="false"/>.</returns>
    public static bool Validate(DidX509Policy policy, CertificateChainModel chain, out List<string> errors)
    {
        errors = new List<string>();

        if (policy.ParsedValue is not string requiredEkuOid)
        {
            errors.Add(ClassStrings.ErrorFailedToParsePolicyValue);
            return false;
        }

        var leafExtensions = chain.LeafCertificate.Extensions;

        if (leafExtensions.Eku == null || leafExtensions.Eku.Count == 0)
        {
            errors.Add(ClassStrings.ErrorNoEku);
            return false;
        }

        // Check if the required EKU OID is present
        bool found = leafExtensions.Eku.Any(oid =>
            string.Equals(oid, requiredEkuOid, System.StringComparison.Ordinal));

        if (!found)
        {
            errors.Add(string.Format(ClassStrings.ErrorRequiredEkuNotFound, requiredEkuOid));
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
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ErrorFailedToParsePolicyValue =
            string.Concat(DidX509Constants.ErrorInvalidFulcioPolicy, ": Failed to parse policy value");

        public const string ErrorNoFulcioIssuer =
            "Fulcio issuer policy validation failed: Leaf certificate has no Fulcio issuer extension";
        public const string ErrorExpectedGot =
            "Fulcio issuer policy validation failed: Expected '{0}', got '{1}'";
    }

    /// <summary>
    /// Validates that the leaf certificate contains the specified Fulcio issuer.
    /// </summary>
    /// <param name="policy">The policy to validate.</param>
    /// <param name="chain">The certificate chain model.</param>
    /// <param name="errors">When this method returns, contains validation errors if validation failed.</param>
    /// <returns><see langword="true"/> if the policy validates; otherwise, <see langword="false"/>.</returns>
    public static bool Validate(DidX509Policy policy, CertificateChainModel chain, out List<string> errors)
    {
        errors = new List<string>();

        if (policy.ParsedValue is not string requiredIssuerSuffix)
        {
            errors.Add(ClassStrings.ErrorFailedToParsePolicyValue);
            return false;
        }

        var leafExtensions = chain.LeafCertificate.Extensions;

        if (string.IsNullOrEmpty(leafExtensions.FulcioIssuer))
        {
            errors.Add(ClassStrings.ErrorNoFulcioIssuer);
            return false;
        }

        // The policy value should match the issuer URL without the "https://" prefix
        string expectedUrl = DidX509Constants.ProtocolHttps + requiredIssuerSuffix;

        if (!string.Equals(leafExtensions.FulcioIssuer, expectedUrl, System.StringComparison.Ordinal))
        {
            errors.Add(string.Format(ClassStrings.ErrorExpectedGot, expectedUrl, leafExtensions.FulcioIssuer));
            return false;
        }

        return true;
    }
}