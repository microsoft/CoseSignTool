// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Validation;

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using DIDx509.CertificateChain;
using DIDx509.Models;
using DIDx509.Parsing;

/// <summary>
/// Validates DID:X509 identifiers against X.509 certificate chains.
/// Implements the complete DID:X509 validation specification.
/// </summary>
public static class DidX509Validator
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorDidParsingFailed = "DID parsing failed: {0}";
        public const string ErrorCertificateChainConversionFailed = "Certificate chain conversion failed: {0}";
        public const string ErrorNoCaMatchTemplate = "{0}: No CA certificate in chain matches fingerprint {1} ({2})";
        public const string ErrorUnknownPolicyType = "Unknown policy type: {0}";
        public const string ErrorChainValidationError = "Chain validation error: {0} - {1}";
        public const string ErrorChainValidationException = "Chain validation exception: {0}";
    }

    /// <summary>
    /// Validates a DID:X509 identifier against a certificate chain.
    /// </summary>
    /// <param name="did">The DID:X509 identifier string.</param>
    /// <param name="certificates">The certificate chain (leaf first).</param>
    /// <param name="validateChain">Whether to perform RFC 5280 chain validation (default: true).</param>
    /// <param name="checkRevocation">Whether to check certificate revocation (default: false).</param>
    /// <returns>A validation result indicating success or failure with detailed errors.</returns>
    public static DidX509ValidationResult Validate(
        string did,
        IEnumerable<X509Certificate2> certificates,
        bool validateChain = true,
        bool checkRevocation = false)
    {
        var errors = new List<string>();

        // Step 1: Parse the DID
        DidX509ParsedIdentifier parsedDid;
        try
        {
            parsedDid = DidX509Parser.Parse(did);
        }
        catch (Exception ex)
        {
            return DidX509ValidationResult.Failure(string.Format(ClassStrings.ErrorDidParsingFailed, ex.Message));
        }

        // Step 2: Validate certificate chain structure
        var certArray = certificates?.ToArray();
        if (certArray == null || certArray.Length < 2)
        {
            return DidX509ValidationResult.Failure(DidX509Constants.ErrorInvalidChain);
        }

        // Step 3: Perform RFC 5280 certificate chain validation if requested
        if (validateChain)
        {
            if (!ValidateCertificateChain(certArray, checkRevocation, out var chainErrors))
            {
                errors.AddRange(chainErrors);
                return DidX509ValidationResult.Failure(errors);
            }
        }

        // Step 4: Convert chain to JSON data model
        CertificateChainModel chainModel;
        try
        {
            chainModel = CertificateChainConverter.Convert(certArray);
        }
        catch (Exception ex)
        {
            return DidX509ValidationResult.Failure(string.Format(ClassStrings.ErrorCertificateChainConversionFailed, ex.Message));
        }

        // Step 5: Validate CA fingerprint match
        var matchingCa = chainModel.FindCaByFingerprint(parsedDid.HashAlgorithm, parsedDid.CaFingerprint);
        if (matchingCa == null)
        {
            return DidX509ValidationResult.Failure(
                string.Format(
                    ClassStrings.ErrorNoCaMatchTemplate,
                    DidX509Constants.ErrorNoCaMatch,
                    parsedDid.CaFingerprint,
                    parsedDid.HashAlgorithm));
        }

        // Step 6: Validate all policies
        foreach (var policy in parsedDid.Policies)
        {
            if (!ValidatePolicy(policy, chainModel, out var policyErrors))
            {
                errors.AddRange(policyErrors);
            }
        }

        if (errors.Count > 0)
        {
            return DidX509ValidationResult.Failure(errors);
        }

        // Step 7: Validation successful
        return DidX509ValidationResult.Success(parsedDid, chainModel);
    }

    /// <summary>
    /// Validates all policies in a parsed DID against a certificate chain.
    /// </summary>
    private static bool ValidatePolicy(DidX509Policy policy, CertificateChainModel chain, out List<string> errors)
    {
        errors = new List<string>();

        switch (policy.Name.ToLowerInvariant())
        {
            case DidX509Constants.PolicySubject:
                return SubjectPolicyValidator.Validate(policy, chain, out errors);

            case DidX509Constants.PolicySan:
                return SanPolicyValidator.Validate(policy, chain, out errors);

            case DidX509Constants.PolicyEku:
                return EkuPolicyValidator.Validate(policy, chain, out errors);

            case DidX509Constants.PolicyFulcioIssuer:
                return FulcioIssuerPolicyValidator.Validate(policy, chain, out errors);

            default:
                // Unknown policy type - fail validation
                errors.Add(string.Format(ClassStrings.ErrorUnknownPolicyType, policy.Name));
                return false;
        }
    }

    /// <summary>
    /// Performs RFC 5280 certificate chain validation.
    /// </summary>
    private static bool ValidateCertificateChain(
        X509Certificate2[] certificates,
        bool checkRevocation,
        out List<string> errors)
    {
        errors = new List<string>();

        try
        {
            // Build the chain
            using var chain = new X509Chain();

            // Configure chain building
            chain.ChainPolicy.RevocationMode = checkRevocation
                ? X509RevocationMode.Online
                : X509RevocationMode.NoCheck;

            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            // Add intermediate and root certificates to extra store
            for (int i = 1; i < certificates.Length; i++)
            {
                chain.ChainPolicy.ExtraStore.Add(certificates[i]);
            }

#if NET5_0_OR_GREATER
            // Use the last certificate as the trust anchor
            var rootCert = certificates[certificates.Length - 1];
            chain.ChainPolicy.CustomTrustStore.Add(rootCert);
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
#endif

            // Build and validate the chain
            bool isValid = chain.Build(certificates[0]);

            if (!isValid)
            {
                foreach (var status in chain.ChainStatus)
                {
                    // Ignore UntrustedRoot if we're using custom trust
                    if (status.Status != X509ChainStatusFlags.UntrustedRoot)
                    {
                        errors.Add(string.Format(ClassStrings.ErrorChainValidationError, status.Status, status.StatusInformation.Trim()));
                    }
                }

                if (errors.Count > 0)
                {
                    return false;
                }
            }

            return true;
        }
        catch (Exception ex)
        {
            errors.Add(string.Format(ClassStrings.ErrorChainValidationException, ex.Message));
            return false;
        }
    }

    /// <summary>
    /// Validates a DID against a certificate chain without performing full chain validation.
    /// Useful for testing or when chain validation is performed externally.
    /// </summary>
    /// <param name="did">The DID:X509 identifier string.</param>
    /// <param name="certificates">The certificate chain (leaf first).</param>
    /// <returns>A validation result indicating success or failure with detailed errors.</returns>
    public static DidX509ValidationResult ValidatePoliciesOnly(
        string did,
        IEnumerable<X509Certificate2> certificates)
    {
        return Validate(did, certificates, validateChain: false, checkRevocation: false);
    }
}