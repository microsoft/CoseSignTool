// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Parsing;

using DIDx509.Models;
using System;
using System.Collections.Generic;
using System.Text;

/// <summary>
/// Parses DID:X509 identifiers according to the specification.
/// </summary>
public static class DidX509Parser
{
    /// <summary>
    /// Parses a DID:X509 identifier string.
    /// </summary>
    /// <param name="did">The DID string to parse.</param>
    /// <returns>A parsed DID identifier.</returns>
    /// <exception cref="FormatException">Thrown if the DID format is invalid.</exception>
    public static DidX509ParsedIdentifier Parse(string did)
    {
        if (string.IsNullOrWhiteSpace(did))
        {
            throw new ArgumentException("DID cannot be null or empty", nameof(did));
        }

        // Expected format: did:x509:0:sha256:fingerprint::policy1:value1::policy2:value2...
        if (!did.StartsWith(DidX509Constants.DidPrefix + DidX509Constants.ValueSeparator, StringComparison.OrdinalIgnoreCase))
        {
            throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: Must start with '{DidX509Constants.DidPrefix}:'");
        }

        // Split on :: to separate CA fingerprint from policies
        string[] majorParts = did.Split(new[] { DidX509Constants.PolicySeparator }, StringSplitOptions.None);
        if (majorParts.Length < 2)
        {
            throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: Must contain at least one policy");
        }

        // Parse the prefix part: did:x509:version:algorithm:fingerprint
        string prefixPart = majorParts[0];
        string[] prefixComponents = prefixPart.Split(DidX509Constants.ColonChar);

        if (prefixComponents.Length != 5)
        {
            throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: Expected format 'did:x509:version:algorithm:fingerprint'");
        }

        if (!string.Equals(prefixComponents[0], DidX509Constants.DidMethod, StringComparison.OrdinalIgnoreCase))
        {
            throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: Must start with 'did:'");
        }

        if (!string.Equals(prefixComponents[1], DidX509Constants.MethodName, StringComparison.OrdinalIgnoreCase))
        {
            throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: Method must be 'x509'");
        }

        string version = prefixComponents[2];
        string hashAlgorithm = prefixComponents[3].ToLowerInvariant();
        string caFingerprint = prefixComponents[4];

        // Validate version
        if (version != DidX509Constants.Version)
        {
            throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: Unsupported version '{version}', expected '{DidX509Constants.Version}'");
        }

        // Validate hash algorithm
        if (hashAlgorithm != DidX509Constants.HashAlgorithmSha256 &&
            hashAlgorithm != DidX509Constants.HashAlgorithmSha384 &&
            hashAlgorithm != DidX509Constants.HashAlgorithmSha512)
        {
            throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: Unsupported hash algorithm '{hashAlgorithm}'");
        }

        // Validate CA fingerprint (base64url format)
        if (string.IsNullOrWhiteSpace(caFingerprint))
        {
            throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: CA fingerprint cannot be empty");
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
            throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: CA fingerprint length mismatch for {hashAlgorithm} (expected {expectedLength}, got {caFingerprint.Length})");
        }

        if (!IsValidBase64Url(caFingerprint))
        {
            throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: CA fingerprint contains invalid base64url characters");
        }

        // Parse policies (skip the first element which is the prefix)
        var policies = new List<DidX509Policy>();
        for (int i = 1; i < majorParts.Length; i++)
        {
            string policyPart = majorParts[i];
            if (string.IsNullOrWhiteSpace(policyPart))
            {
                throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: Empty policy at position {i}");
            }

            // Split policy into name:value
            int firstColon = policyPart.IndexOf(DidX509Constants.ColonChar);
            if (firstColon <= 0)
            {
                throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: Policy must have format 'name:value'");
            }

            string policyName = policyPart.Substring(0, firstColon);
            string policyValue = policyPart.Substring(firstColon + 1);

            if (string.IsNullOrWhiteSpace(policyName))
            {
                throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: Policy name cannot be empty");
            }

            if (string.IsNullOrWhiteSpace(policyValue))
            {
                throw new FormatException($"{DidX509Constants.ErrorInvalidDid}: Policy value cannot be empty");
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
            throw new FormatException($"{DidX509Constants.ErrorInvalidSubjectPolicy}: Must have even number of components (key:value pairs)");
        }

        for (int i = 0; i < parts.Length; i += 2)
        {
            string key = parts[i];
            string encodedValue = parts[i + 1];

            if (string.IsNullOrWhiteSpace(key))
            {
                throw new FormatException($"{DidX509Constants.ErrorInvalidSubjectPolicy}: Key cannot be empty");
            }

            if (result.ContainsKey(key))
            {
                throw new FormatException($"{DidX509Constants.ErrorInvalidSubjectPolicy}: Duplicate key '{key}'");
            }

            // Decode percent-encoded value
            string decodedValue = PercentEncoding.Decode(encodedValue);
            result[key] = decodedValue;
        }

        if (result.Count == 0)
        {
            throw new FormatException($"{DidX509Constants.ErrorInvalidSubjectPolicy}: Must contain at least one key-value pair");
        }

        return result;
    }

    private static (string Type, string Value) ParseSanPolicy(string value)
    {
        // Format: type:value (only one colon separating type and value)
        int colonIndex = value.IndexOf(DidX509Constants.ColonChar);
        if (colonIndex <= 0 || colonIndex >= value.Length - 1)
        {
            throw new FormatException($"{DidX509Constants.ErrorInvalidSanPolicy}: Must have format 'type:value'");
        }

        string sanType = value.Substring(0, colonIndex).ToLowerInvariant();
        string encodedValue = value.Substring(colonIndex + 1);

        // Validate SAN type
        if (sanType != DidX509Constants.SanTypeEmail &&
            sanType != DidX509Constants.SanTypeDns &&
            sanType != DidX509Constants.SanTypeUri)
        {
            throw new FormatException($"{DidX509Constants.ErrorInvalidSanPolicy}: SAN type must be 'email', 'dns', or 'uri' (got '{sanType}')");
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
            throw new FormatException($"{DidX509Constants.ErrorInvalidEkuPolicy}: Must be a valid OID in dotted decimal notation");
        }

        return value;
    }

    private static string ParseFulcioIssuerPolicy(string value)
    {
        // Format: issuer domain (without https:// prefix), percent-encoded
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new FormatException($"{DidX509Constants.ErrorInvalidFulcioPolicy}: Issuer cannot be empty");
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
