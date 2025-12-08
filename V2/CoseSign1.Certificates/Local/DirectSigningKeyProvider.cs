// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Interfaces;

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Signing key provider that uses X509Certificate2 private keys directly.
/// Supports RSA, ECDsa, and ML-DSA algorithms.
/// </summary>
public class DirectSigningKeyProvider : ISigningKeyProvider
{
    private readonly X509Certificate2 _certificate;
    private CoseKey? _coseKey;
    private readonly object _coseKeyLock = new();
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of DirectSigningKeyProvider.
    /// </summary>
    /// <param name="certificate">Certificate with private key</param>
    public DirectSigningKeyProvider(X509Certificate2 certificate)
    {
        _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));

        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException("Certificate must have a private key for local signing.", nameof(certificate));
        }
    }

    /// <inheritdoc/>
    public CoseKey GetCoseKey()
    {
        if (_coseKey != null)
        {
            return _coseKey;
        }

        lock (_coseKeyLock)
        {
            if (_coseKey != null)
            {
                return _coseKey;
            }

            _coseKey = CreateCoseKey();
            return _coseKey;
        }
    }

    /// <inheritdoc/>
    public bool IsRemote => false;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        // Don't dispose certificate - caller owns it
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private CoseKey CreateCoseKey()
    {
        // Try RSA first
        var rsa = _certificate.GetRSAPrivateKey();
        if (rsa != null)
        {
            return new CoseKey(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256); // PS256
        }

        // Try ECDsa
        var ecdsa = _certificate.GetECDsaPrivateKey();
        if (ecdsa != null)
        {
            return new CoseKey(ecdsa, HashAlgorithmName.SHA256);
        }

        throw new NotSupportedException(
            $"Certificate uses unsupported key algorithm. Only RSA and ECDsa are supported for local signing.");
    }
}
