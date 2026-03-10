// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Parsing;

using System;
using System.Collections.Generic;
using DIDx509.Models;
using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Parses DID:X509 identifiers according to the specification.
/// </summary>
public static class DidX509Parser
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorDidCannotBeNullOrEmpty = "DID cannot be null or empty";

        public const string DidExpectedFormat = "did:x509:version:algorithm:fingerprint";
        public const string PolicyExpectedFormat = "name:value";
        public const string SanExpectedFormat = "type:value";

        public const string ErrorInvalidDidMustStartWithTemplate = "{0}: Must start with '{1}:'";
        public const string ErrorInvalidDidMustContainAtLeastOnePolicyTemplate = "{0}: Must contain at least one policy";
        public const string ErrorInvalidDidExpectedFormatTemplate = "{0}: Expected format '{1}'";
        public const string ErrorInvalidDidUnsupportedVersionTemplate = "{0}: Unsupported version '{1}', expected '{2}'";
        public const string ErrorInvalidDidUnsupportedHashAlgorithmTemplate = "{0}: Unsupported hash algorithm '{1}'";
        public const string ErrorInvalidDidCaFingerprintCannotBeEmptyTemplate = "{0}: CA fingerprint cannot be empty";
        public const string ErrorInvalidDidCaFingerprintLengthMismatchTemplate =
            "{0}: CA fingerprint length mismatch for {1} (expected {2}, got {3})";
        public const string ErrorInvalidDidCaFingerprintInvalidCharsTemplate = "{0}: CA fingerprint contains invalid base64url characters";
        public const string ErrorInvalidDidEmptyPolicyAtPositionTemplate = "{0}: Empty policy at position {1}";
        public const string ErrorInvalidDidPolicyMustHaveFormatTemplate = "{0}: Policy must have format '{1}'";
        public const string ErrorInvalidDidPolicyNameCannotBeEmptyTemplate = "{0}: Policy name cannot be empty";
        public const string ErrorInvalidDidPolicyValueCannotBeEmptyTemplate = "{0}: Policy value cannot be empty";

        public const string ErrorInvalidSubjectPolicyMustHaveEvenComponentsTemplate =
            "{0}: Must have even number of components (key:value pairs)";
        public const string ErrorInvalidSubjectPolicyKeyCannotBeEmptyTemplate = "{0}: Key cannot be empty";
        public const string ErrorInvalidSubjectPolicyDuplicateKeyTemplate = "{0}: Duplicate key '{1}'";

        public const string ErrorInvalidSanPolicyMustHaveFormatTemplate = "{0}: Must have format '{1}'";
        public const string ErrorInvalidSanPolicySanTypeMustBeTemplate =
            "{0}: SAN type must be '{1}', '{2}', or '{3}' (got '{4}')";

        public const string ErrorInvalidEkuPolicyMustBeValidOidTemplate =
            "{0}: Must be a valid OID in dotted decimal notation";
        public const string ErrorInvalidFulcioIssuerCannotBeEmptyTemplate = "{0}: Issuer cannot be empty";
    }

    /// <summary>
    /// Parses a DID:X509 identifier string.
    /// </summary>
    /// <param name="did">The DID string to parse.</param>
    /// <returns>A parsed DID identifier.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="did"/> is <see langword="null"/> or empty.</exception>
    /// <exception cref="FormatException">Thrown when the DID format is invalid.</exception>
    public static DidX509ParsedIdentifier Parse(string did)
    {
        if (string.IsNullOrWhiteSpace(did))
            {
                throw new ArgumentException(ClassStrings.ErrorDidCannotBeNullOrEmpty, nameof(did));
            }

        // Expected format: did:x509:0:sha256:fingerprint::policy1:value1::policy2:value2...
        if (!did.StartsWith(DidX509Constants.DidPrefix + DidX509Constants.ValueSeparator, StringComparison.OrdinalIgnoreCase))
        {
            throw new FormatException(
                string.Format(
                    ClassStrings.ErrorInvalidDidMustStartWithTemplate,
                    DidX509Constants.ErrorInvalidDid,
                    DidX509Constants.DidPrefix));
        }

        // Split on :: to separate CA fingerprint from policies
        string[] majorParts = did.Split(new[] { DidX509Constants.PolicySeparator }, StringSplitOptions.None);
        if (majorParts.Length < 2)
        {
            throw new FormatException(
                string.Format(
                    ClassStrings.ErrorInvalidDidMustContainAtLeastOnePolicyTemplate,
                    DidX509Constants.ErrorInvalidDid));
        }

        // Parse the prefix part: did:x509:version:algorithm:fingerprint
        string prefixPart = majorParts[0];
        string[] prefixComponents = prefixPart.Split(DidX509Constants.ColonChar);

        if (prefixComponents.Length != 5)
        {
            throw new FormatException(
                string.Format(
                    ClassStrings.ErrorInvalidDidExpectedFormatTemplate,
                    DidX509Constants.ErrorInvalidDid,
                    ClassStrings.DidExpectedFormat));
        }

        string version = prefixComponents[2];
        string hashAlgorithm = prefixComponents[3].ToLowerInvariant();
        string caFingerprint = prefixComponents[4];

        // Validate version
        if (version != DidX509Constants.Version)
        {
            throw new FormatException(
                string.Format(
                    ClassStrings.ErrorInvalidDidUnsupportedVersionTemplate,
                    DidX509Constants.ErrorInvalidDid,
                    version,
                    DidX509Constants.Version));
        }

        // Validate hash algorithm
        if (hashAlgorithm != DidX509Constants.HashAlgorithmSha256 &&
            hashAlgorithm != DidX509Constants.HashAlgorithmSha384 &&
            hashAlgorithm != DidX509Constants.HashAlgorithmSha512)
        {
            throw new FormatException(
                string.Format(
                    ClassStrings.ErrorInvalidDidUnsupportedHashAlgorithmTemplate,
                    DidX509Constants.ErrorInvalidDid,
                    hashAlgorithm));
        }

        // Validate CA fingerprint (base64url format)
        if (string.IsNullOrWhiteSpace(caFingerprint))
        {
            throw new FormatException(
                string.Format(
                    ClassStrings.ErrorInvalidDidCaFingerprintCannotBeEmptyTemplate,
                    DidX509Constants.ErrorInvalidDid));
        }

        // Expected lengths: SHA-256=43, SHA-384=64, SHA-512=86 characters (base64url without padding)
        int expectedLength = hashAlgorithm switch
        {
            DidX509Constants.HashAlgorithmSha256 => 43,
            DidX509Constants.HashAlgorithmSha384 => 64,
            DidX509Constants.HashAlgorithmSha512 => 86,
            _ => -1
        };

        if (caFingerprint.Length != expectedLength)
        {
            throw new FormatException(
                string.Format(
                    ClassStrings.ErrorInvalidDidCaFingerprintLengthMismatchTemplate,
                    DidX509Constants.ErrorInvalidDid,
                    hashAlgorithm,
                    expectedLength,
                    caFingerprint.Length));
        }

        if (!IsValidBase64Url(caFingerprint))
        {
            throw new FormatException(
                string.Format(
                    ClassStrings.ErrorInvalidDidCaFingerprintInvalidCharsTemplate,
                    DidX509Constants.ErrorInvalidDid));
        }

        // Parse policies (skip the first element which is the prefix)
        var policies = new List<DidX509Policy>();
        for (int i = 1; i < majorParts.Length; i++)
        {
            string policyPart = majorParts[i];
            if (string.IsNullOrWhiteSpace(policyPart))
            {
                throw new FormatException(
                    string.Format(
                        ClassStrings.ErrorInvalidDidEmptyPolicyAtPositionTemplate,
                        DidX509Constants.ErrorInvalidDid,
                        i));
            }

            // Split policy into name:value
            int firstColon = policyPart.IndexOf(DidX509Constants.ColonChar);
            if (firstColon <= 0)
            {
                throw new FormatException(
                    string.Format(
                        ClassStrings.ErrorInvalidDidPolicyMustHaveFormatTemplate,
                        DidX509Constants.ErrorInvalidDid,
                        ClassStrings.PolicyExpectedFormat));
            }

            string policyName = policyPart.Substring(0, firstColon);
            string policyValue = policyPart.Substring(firstColon + 1);

            if (string.IsNullOrWhiteSpace(policyName))
            {
                throw new FormatException(
                    string.Format(
                        ClassStrings.ErrorInvalidDidPolicyNameCannotBeEmptyTemplate,
                        DidX509Constants.ErrorInvalidDid));
            }

            if (string.IsNullOrWhiteSpace(policyValue))
            {
                throw new FormatException(
                    string.Format(
                        ClassStrings.ErrorInvalidDidPolicyValueCannotBeEmptyTemplate,
                        DidX509Constants.ErrorInvalidDid));
            }

            // Parse the policy value based on policy type
            object? parsedValue = ParsePolicyValue(policyName, policyValue);
            policies.Add(new DidX509Policy(policyName, policyValue, parsedValue));
        }

        return new DidX509ParsedIdentifier(did, version, hashAlgorithm, caFingerprint, policies);
    }

    /// <summary>
    /// Attempts to parse a DID:X509 identifier string.
    /// </summary>
    /// <param name="did">The DID string to parse.</param>
    /// <param name="parsed">When this method returns, contains the parsed identifier if parsing succeeded; otherwise, <see langword="null"/>.</param>
    /// <returns><see langword="true"/> if parsing succeeded; otherwise, <see langword="false"/>.</returns>
    public static bool TryParse(string did, out DidX509ParsedIdentifier? parsed)
    {
        try
        {
            parsed = Parse(did);
            return true;
        }
        catch
        {
            parsed = null;
            return false;
        }
    }

    private static object? ParsePolicyValue(string policyName, string policyValue)
    {
        return policyName.ToLowerInvariant() switch
        {
            DidX509Constants.PolicySubject => ParseSubjectPolicy(policyValue),
            DidX509Constants.PolicySan => ParseSanPolicy(policyValue),
            DidX509Constants.PolicyEku => ParseEkuPolicy(policyValue),
            DidX509Constants.PolicyFulcioIssuer => ParseFulcioIssuerPolicy(policyValue),
            _ => null // Unknown policy, keep raw value only
        };
    }

    private static Dictionary<string, string> ParseSubjectPolicy(string value)
    {
        // Format: key:value:key:value:...
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string[] parts = value.Split(DidX509Constants.ColonChar);

        if (parts.Length % 2 != 0)
        {
            throw new FormatException(
                string.Format(
                    ClassStrings.ErrorInvalidSubjectPolicyMustHaveEvenComponentsTemplate,
                    DidX509Constants.ErrorInvalidSubjectPolicy));
        }

        for (int i = 0; i < parts.Length; i += 2)
        {
            string key = parts[i];
            string encodedValue = parts[i + 1];

            if (string.IsNullOrWhiteSpace(key))
            {
                throw new FormatException(
                    string.Format(
                        ClassStrings.ErrorInvalidSubjectPolicyKeyCannotBeEmptyTemplate,
                        DidX509Constants.ErrorInvalidSubjectPolicy));
            }

            if (result.ContainsKey(key))
            {
                throw new FormatException(
                    string.Format(
                        ClassStrings.ErrorInvalidSubjectPolicyDuplicateKeyTemplate,
                        DidX509Constants.ErrorInvalidSubjectPolicy,
                        key));
            }

            // Decode percent-encoded value
            string decodedValue = PercentEncoding.Decode(encodedValue);
            result[key] = decodedValue;
        }

        return result;
    }

    private static (string Type, string Value) ParseSanPolicy(string value)
    {
        // Format: type:value (only one colon separating type and value)
        int colonIndex = value.IndexOf(DidX509Constants.ColonChar);
        if (colonIndex <= 0 || colonIndex >= value.Length - 1)
        {
            throw new FormatException(
                string.Format(
                    ClassStrings.ErrorInvalidSanPolicyMustHaveFormatTemplate,
                    DidX509Constants.ErrorInvalidSanPolicy,
                    ClassStrings.SanExpectedFormat));
        }

        string sanType = value.Substring(0, colonIndex).ToLowerInvariant();
        string encodedValue = value.Substring(colonIndex + 1);

        // Validate SAN type
        if (sanType != DidX509Constants.SanTypeEmail &&
            sanType != DidX509Constants.SanTypeDns &&
            sanType != DidX509Constants.SanTypeUri)
        {
            throw new FormatException(
                string.Format(
                    ClassStrings.ErrorInvalidSanPolicySanTypeMustBeTemplate,
                    DidX509Constants.ErrorInvalidSanPolicy,
                    DidX509Constants.SanTypeEmail,
                    DidX509Constants.SanTypeDns,
                    DidX509Constants.SanTypeUri,
                    sanType));
        }

        // Decode percent-encoded value
        string decodedValue = PercentEncoding.Decode(encodedValue);

        return (sanType, decodedValue);
    }

    private static string ParseEkuPolicy(string value)
    {
        // Format: OID (dotted decimal notation)
        if (!IsValidOid(value))
        {
            throw new FormatException(
                string.Format(
                    ClassStrings.ErrorInvalidEkuPolicyMustBeValidOidTemplate,
                    DidX509Constants.ErrorInvalidEkuPolicy));
        }

        return value;
    }

    private static string ParseFulcioIssuerPolicy(string value)
    {
        // Format: issuer domain (without https:// prefix), percent-encoded
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new FormatException(
                string.Format(
                    ClassStrings.ErrorInvalidFulcioIssuerCannotBeEmptyTemplate,
                    DidX509Constants.ErrorInvalidFulcioPolicy));
        }

        // Decode percent-encoded value
        return PercentEncoding.Decode(value);
    }

    private static bool IsValidBase64Url(string value)
    {
        foreach (char c in value)
        {
            if (!((c >= 'A' && c <= 'Z') ||
                  (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') ||
                  c == DidX509Constants.HyphenChar ||
                  c == DidX509Constants.UnderscoreChar))
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsValidOid(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string[] parts = value.Split(DidX509Constants.PeriodChar);
        if (parts.Length < 2)
        {
            return false;
        }

        foreach (string part in parts)
        {
            if (string.IsNullOrEmpty(part))
            {
                return false;
            }

            foreach (char c in part)
            {
                if (!char.IsDigit(c))
                {
                    return false;
                }
            }
        }

        return true;
    }
}