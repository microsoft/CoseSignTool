// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace CoseSign1.AzureKeyVault.Common;

/// <summary>
/// Provides algorithm mapping utilities for Azure Key Vault cryptographic operations.
/// </summary>
public static class KeyVaultAlgorithmMapper
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorRsaAlgorithmNotSupportedFormat = "RSA algorithm with {0} and {1} is not supported.";
    }

    /// <summary>
    /// Maps RSA hash algorithm and padding to Azure Key Vault SignatureAlgorithm.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="padding">The RSA signature padding.</param>
    /// <returns>The corresponding Azure Key Vault SignatureAlgorithm.</returns>
    /// <exception cref="NotSupportedException">Thrown if the combination is not supported.</exception>
    public static SignatureAlgorithm MapRsaAlgorithm(HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (padding == RSASignaturePadding.Pkcs1)
        {
            if (hashAlgorithm == HashAlgorithmName.SHA256)
            {
                return SignatureAlgorithm.RS256;
            }

            if (hashAlgorithm == HashAlgorithmName.SHA384)
            {
                return SignatureAlgorithm.RS384;
            }

            if (hashAlgorithm == HashAlgorithmName.SHA512)
            {
                return SignatureAlgorithm.RS512;
            }
        }
        else if (padding == RSASignaturePadding.Pss)
        {
            if (hashAlgorithm == HashAlgorithmName.SHA256)
            {
                return SignatureAlgorithm.PS256;
            }

            if (hashAlgorithm == HashAlgorithmName.SHA384)
            {
                return SignatureAlgorithm.PS384;
            }

            if (hashAlgorithm == HashAlgorithmName.SHA512)
            {
                return SignatureAlgorithm.PS512;
            }
        }

        throw new NotSupportedException(string.Format(ClassStrings.ErrorRsaAlgorithmNotSupportedFormat, hashAlgorithm, padding));
    }

    /// <summary>
    /// Maps ECDSA hash length to Azure Key Vault SignatureAlgorithm.
    /// </summary>
    /// <param name="hashLength">The length of the hash in bytes.</param>
    /// <returns>The corresponding Azure Key Vault SignatureAlgorithm.</returns>
    public static SignatureAlgorithm MapEcdsaAlgorithm(int hashLength)
    {
        return hashLength switch
        {
            32 => SignatureAlgorithm.ES256,  // SHA-256
            48 => SignatureAlgorithm.ES384,  // SHA-384
            64 => SignatureAlgorithm.ES512,  // SHA-512
            _ => SignatureAlgorithm.ES256    // Default to ES256
        };
    }

    /// <summary>
    /// Maps a hash algorithm name to Azure Key Vault SignatureAlgorithm for ECDSA.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm name.</param>
    /// <returns>The corresponding Azure Key Vault SignatureAlgorithm.</returns>
    public static SignatureAlgorithm MapEcdsaAlgorithmFromHash(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA256)
        {
            return SignatureAlgorithm.ES256;
        }

        if (hashAlgorithm == HashAlgorithmName.SHA384)
        {
            return SignatureAlgorithm.ES384;
        }

        if (hashAlgorithm == HashAlgorithmName.SHA512)
        {
            return SignatureAlgorithm.ES512;
        }

        return SignatureAlgorithm.ES256;
    }
}
