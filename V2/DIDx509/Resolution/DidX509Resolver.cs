// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Resolution;

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DIDx509.Models;
using DIDx509.Validation;

/// <summary>
/// Resolves DID:X509 identifiers to DID Documents according to the specification.
/// </summary>
public static class DidX509Resolver
{
    /// <summary>
    /// Resolves a DID:X509 identifier to a DID Document.
    /// </summary>
    /// <param name="did">The DID:X509 identifier.</param>
    /// <param name="certificates">The certificate chain (passed as x509chain resolution option).</param>
    /// <param name="validateChain">Whether to perform RFC 5280 chain validation (default: true).</param>
    /// <param name="checkRevocation">Whether to check certificate revocation (default: false).</param>
    /// <returns>A DID Document if resolution succeeds.</returns>
    /// <exception cref="InvalidOperationException">Thrown if resolution fails.</exception>
    public static DidDocument Resolve(
        string did,
        IEnumerable<X509Certificate2> certificates,
        bool validateChain = true,
        bool checkRevocation = false)
    {
        // Step 1-6: Validate DID against certificate chain
        var validationResult = DidX509Validator.Validate(did, certificates, validateChain, checkRevocation);

        if (!validationResult.IsValid)
        {
            throw new InvalidOperationException(
                $"DID resolution failed: {string.Join("; ", validationResult.Errors)}");
        }

        var chainModel = validationResult.ChainModel!;
        var leafCert = chainModel.LeafCertificate.Certificate;

        // Step 7: Extract public key from leaf certificate
        var publicKey = leafCert.GetPublicKey();

        // Step 8: Convert public key to JWK
        var jwk = ConvertPublicKeyToJwk(leafCert);

        // Step 9: Create verification method
        string verificationMethodId = did + DidX509Constants.VerificationMethodSuffix;
        var verificationMethod = new VerificationMethod(
            verificationMethodId,
            DidX509Constants.VerificationMethodType,
            did,
            jwk);

        // Step 10-11: Determine verification relationships based on key usage
        List<string>? assertionMethod = null;
        List<string>? keyAgreement = null;

        var keyUsageExt = leafCert.Extensions
            .OfType<X509KeyUsageExtension>()
            .FirstOrDefault();

        if (keyUsageExt == null)
        {
            // Step 10: No key usage extension - include both
            assertionMethod = new List<string> { verificationMethodId };
            keyAgreement = new List<string> { verificationMethodId };
        }
        else
        {
            // Step 10: Has digitalSignature bit
            if ((keyUsageExt.KeyUsages & X509KeyUsageFlags.DigitalSignature) != 0)
            {
                assertionMethod = new List<string> { verificationMethodId };
            }

            // Step 11: Has keyAgreement bit
            if ((keyUsageExt.KeyUsages & X509KeyUsageFlags.KeyAgreement) != 0)
            {
                keyAgreement = new List<string> { verificationMethodId };
            }

            // Step 12: If has key usage but neither bit is set, fail
            if (assertionMethod == null && keyAgreement == null)
            {
                throw new InvalidOperationException(
                    DidX509Constants.ErrorInvalidKeyUsage +
                    ": Certificate has key usage extension but neither digitalSignature nor keyAgreement is set");
            }
        }

        // Step 13: Return complete DID document
        return new DidDocument(
            did,
            new[] { verificationMethod },
            assertionMethod,
            keyAgreement);
    }

    /// <summary>
    /// Attempts to resolve a DID:X509 identifier.
    /// </summary>
    public static bool TryResolve(
        string did,
        IEnumerable<X509Certificate2> certificates,
        out DidDocument? document,
        bool validateChain = true,
        bool checkRevocation = false)
    {
        try
        {
            document = Resolve(did, certificates, validateChain, checkRevocation);
            return true;
        }
        catch
        {
            document = null;
            return false;
        }
    }

    /// <summary>
    /// Converts a certificate's public key to JWK format.
    /// </summary>
    private static Dictionary<string, object> ConvertPublicKeyToJwk(X509Certificate2 certificate)
    {
        var publicKey = certificate.PublicKey;
        var jwk = new Dictionary<string, object>();

        if (publicKey.Oid.Value == "1.2.840.113549.1.1.1") // RSA
        {
            var rsa = certificate.GetRSAPublicKey();
            if (rsa == null)
            {
                throw new InvalidOperationException("Failed to extract RSA public key");
            }

            var parameters = rsa.ExportParameters(false);

            jwk[DidX509Constants.JwkKeyKty] = DidX509Constants.JwkKtyRsa;
            jwk[DidX509Constants.JwkKeyN] = Base64UrlEncode(parameters.Modulus!);
            jwk[DidX509Constants.JwkKeyE] = Base64UrlEncode(parameters.Exponent!);
        }
        else if (publicKey.Oid.Value == "1.2.840.10045.2.1") // EC
        {
            var ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa == null)
            {
                throw new InvalidOperationException("Failed to extract EC public key");
            }

            var parameters = ecdsa.ExportParameters(false);

            jwk[DidX509Constants.JwkKeyKty] = DidX509Constants.JwkKtyEc;
            jwk[DidX509Constants.JwkKeyCrv] = GetCurveName(parameters.Curve);
            jwk[DidX509Constants.JwkKeyX] = Base64UrlEncode(parameters.Q.X!);
            jwk[DidX509Constants.JwkKeyY] = Base64UrlEncode(parameters.Q.Y!);
        }
        else
        {
            throw new NotSupportedException($"Unsupported public key algorithm: {publicKey.Oid.FriendlyName}");
        }

        return jwk;
    }

    private static string GetCurveName(ECCurve curve)
    {
        if (curve.Oid == null)
        {
            throw new InvalidOperationException("EC curve OID is null");
        }

        return curve.Oid.Value switch
        {
            "1.2.840.10045.3.1.7" => DidX509Constants.CurveP256, // secp256r1 / prime256v1
            "1.3.132.0.34" => DidX509Constants.CurveP384,         // secp384r1
            "1.3.132.0.35" => DidX509Constants.CurveP521,         // secp521r1
            _ => throw new NotSupportedException($"Unsupported EC curve: {curve.Oid.FriendlyName}")
        };
    }

    private static string Base64UrlEncode(byte[] data)
    {
        string base64 = Convert.ToBase64String(data);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}