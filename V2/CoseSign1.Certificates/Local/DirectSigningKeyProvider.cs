// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Interfaces;

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Signing key provider that uses X509Certificate2 private keys directly.
/// Supports RSA, ECDsa, and ML-DSA (Post-Quantum) algorithms.
/// </summary>
public class DirectSigningKeyProvider : ISigningKeyProvider
{
    private readonly X509Certificate2 Certificate;
    private CoseKey? CoseKeyField;
    private readonly object CoseKeyLock = new();
    private bool Disposed;

    /// <summary>
    /// Initializes a new instance of DirectSigningKeyProvider.
    /// </summary>
    /// <param name="certificate">Certificate with private key</param>
    public DirectSigningKeyProvider(X509Certificate2 certificate)
    {
        Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));

        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException("Certificate must have a private key for local signing.", nameof(certificate));
        }
    }

    /// <inheritdoc/>
    public CoseKey GetCoseKey()
    {
        if (CoseKeyField != null)
        {
            return CoseKeyField;
        }

        lock (CoseKeyLock)
        {
            if (CoseKeyField != null)
            {
                return CoseKeyField;
            }

            CoseKeyField = CreateCoseKey();
            return CoseKeyField;
        }
    }

    /// <inheritdoc/>
    public bool IsRemote => false;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Disposed)
        {
            return;
        }

        // Don't dispose certificate - caller owns it
        Disposed = true;
        GC.SuppressFinalize(this);
    }

    private CoseKey CreateCoseKey()
    {
        // Try RSA first
        var rsa = Certificate.GetRSAPrivateKey();
        if (rsa != null)
        {
            // Determine hash algorithm based on key size
            var hashAlgorithm = rsa.KeySize switch
            {
                >= 4096 => HashAlgorithmName.SHA512, // PS512
                >= 3072 => HashAlgorithmName.SHA384, // PS384
                _ => HashAlgorithmName.SHA256        // PS256
            };
            return new CoseKey(rsa, RSASignaturePadding.Pss, hashAlgorithm);
        }

        // Try ECDsa
        var ecdsa = Certificate.GetECDsaPrivateKey();
        if (ecdsa != null)
        {
            // Determine hash algorithm based on curve size
            var hashAlgorithm = ecdsa.KeySize switch
            {
                521 => HashAlgorithmName.SHA512, // ES512 (P-521)
                384 => HashAlgorithmName.SHA384, // ES384 (P-384)
                _ => HashAlgorithmName.SHA256    // ES256 (P-256)
            };
            return new CoseKey(ecdsa, hashAlgorithm);
        }

        // Try ML-DSA (Post-Quantum)
#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview in .NET 10
        var mlDsa = Certificate.GetMLDsaPrivateKey();
        if (mlDsa != null)
        {
            return new CoseKey(mlDsa);
        }
#pragma warning restore SYSLIB5006

        throw new NotSupportedException(
            $"Certificate uses unsupported key algorithm. Only RSA, ECDsa, and ML-DSA are supported for local signing.");
    }
}