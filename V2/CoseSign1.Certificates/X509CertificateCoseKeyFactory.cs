// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;

/// <summary>
/// Factory for creating <see cref="CoseKey"/> instances from X509 certificates.
/// Centralizes the algorithm detection and CoseKey construction logic.
/// </summary>
public static class X509CertificateCoseKeyFactory
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorUnsupportedKeyTypePublic = "Certificate does not contain a supported public key type (ECDSA, RSA, or ML-DSA).";
        public const string ErrorUnsupportedKeyTypePrivate = "Certificate uses unsupported key algorithm. Only RSA, ECDsa, and ML-DSA are supported for signing.";
        public const string ErrorCertificateMustHavePrivateKey = "Certificate must have a private key for signing operations.";
    }

    /// <summary>
    /// Creates a <see cref="CoseKey"/> from the certificate's public key for verification operations.
    /// </summary>
    /// <param name="certificate">The certificate containing the public key.</param>
    /// <returns>A <see cref="CoseKey"/> suitable for signature verification.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> is null.</exception>
    /// <exception cref="NotSupportedException">Thrown when the certificate uses an unsupported key algorithm.</exception>
    public static CoseKey CreateFromPublicKey(X509Certificate2 certificate)
    {
        Guard.ThrowIfNull(certificate);

        // Try RSA first (for verification we use public key)
        var rsa = certificate.GetRSAPublicKey();
        if (rsa != null)
        {
            var hashAlgorithm = GetHashAlgorithmForKeySize(rsa.KeySize);
            return new CoseKey(rsa, RSASignaturePadding.Pss, hashAlgorithm);
        }

        // Try ECDsa
        var ecdsa = certificate.GetECDsaPublicKey();
        if (ecdsa != null)
        {
            var hashAlgorithm = GetHashAlgorithmForKeySize(ecdsa.KeySize);
            return new CoseKey(ecdsa, hashAlgorithm);
        }

#if NET10_0_OR_GREATER
        // Try ML-DSA (Post-Quantum) - only available in .NET 10+
#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview in .NET 10
        var mlDsa = certificate.GetMLDsaPublicKey();
        if (mlDsa != null)
        {
            return new CoseKey(mlDsa);
        }
#pragma warning restore SYSLIB5006
#endif

        throw new NotSupportedException(ClassStrings.ErrorUnsupportedKeyTypePublic);
    }

    /// <summary>
    /// Creates a <see cref="CoseKey"/> from the certificate's private key for signing operations.
    /// </summary>
    /// <param name="certificate">The certificate containing the private key.</param>
    /// <returns>A <see cref="CoseKey"/> suitable for signing.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when the certificate does not have a private key.</exception>
    /// <exception cref="NotSupportedException">Thrown when the certificate uses an unsupported key algorithm.</exception>
    public static CoseKey CreateFromPrivateKey(X509Certificate2 certificate)
    {
        Guard.ThrowIfNull(certificate);

        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException(ClassStrings.ErrorCertificateMustHavePrivateKey, nameof(certificate));
        }

        // Try RSA first
        var rsa = certificate.GetRSAPrivateKey();
        if (rsa != null)
        {
            var hashAlgorithm = GetHashAlgorithmForKeySize(rsa.KeySize);
            return new CoseKey(rsa, RSASignaturePadding.Pss, hashAlgorithm);
        }

        // Try ECDsa
        var ecdsa = certificate.GetECDsaPrivateKey();
        if (ecdsa != null)
        {
            var hashAlgorithm = GetHashAlgorithmForKeySize(ecdsa.KeySize);
            return new CoseKey(ecdsa, hashAlgorithm);
        }

#if NET10_0_OR_GREATER
        // Try ML-DSA (Post-Quantum) - only available in .NET 10+
#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview in .NET 10
        var mlDsa = certificate.GetMLDsaPrivateKey();
        if (mlDsa != null)
        {
            return new CoseKey(mlDsa);
        }
#pragma warning restore SYSLIB5006
#endif

        throw new NotSupportedException(ClassStrings.ErrorUnsupportedKeyTypePrivate);
    }

    /// <summary>
    /// Determines the appropriate hash algorithm based on key size.
    /// </summary>
    /// <param name="keySizeInBits">The key size in bits.</param>
    /// <returns>The appropriate <see cref="HashAlgorithmName"/>.</returns>
    /// <remarks>
    /// For RSA:
    /// <list type="bullet">
    /// <item><description>4096+ bits → SHA-512 (PS512)</description></item>
    /// <item><description>3072+ bits → SHA-384 (PS384)</description></item>
    /// <item><description>Otherwise → SHA-256 (PS256)</description></item>
    /// </list>
    /// For ECDSA:
    /// <list type="bullet">
    /// <item><description>521 bits (P-521) → SHA-512 (ES512)</description></item>
    /// <item><description>384 bits (P-384) → SHA-384 (ES384)</description></item>
    /// <item><description>Otherwise (P-256) → SHA-256 (ES256)</description></item>
    /// </list>
    /// </remarks>
    public static HashAlgorithmName GetHashAlgorithmForKeySize(int keySizeInBits)
    {
        return keySizeInBits switch
        {
            >= 4096 => HashAlgorithmName.SHA512,
            >= 3072 or 521 => keySizeInBits == 521 ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA384,
            384 => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA256
        };
    }
}
