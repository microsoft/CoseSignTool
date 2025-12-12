// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;

namespace CoseSign1.Certificates.Remote;

/// <summary>
/// RSA implementation that delegates signing operations to a remote service.
/// This class wraps RSA public key information but performs signing through RemoteCertificateSource.
/// </summary>
internal sealed class RemoteRsa : RSA
{
    private readonly RemoteCertificateSource _certificateSource;
    private readonly RSAParameters _publicParameters;
    private bool _disposed;

    public RemoteRsa(RemoteCertificateSource certificateSource, RSAParameters publicParameters)
    {
        _certificateSource = certificateSource ?? throw new ArgumentNullException(nameof(certificateSource));
        _publicParameters = publicParameters;
        KeySizeValue = _publicParameters.Modulus?.Length * 8 ?? 0;
    }

    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new CryptographicException("Private key export is not supported for remote signing.");
        }

        return _publicParameters;
    }

    public override void ImportParameters(RSAParameters parameters)
    {
        throw new NotSupportedException("Parameter import is not supported for remote signing.");
    }

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        if (padding != RSASignaturePadding.Pss)
        {
            throw new CryptographicException("Only PSS padding is supported for remote RSA signing.");
        }

        return _certificateSource.SignHashWithRsa(hash, hashAlgorithm, padding);
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _disposed = true;
            base.Dispose(disposing);
        }
    }

    #region Not Implemented - Encryption/Decryption not needed for COSE signing

    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
    {
        throw new NotSupportedException("Decryption is not supported for remote signing.");
    }

    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
    {
        throw new NotSupportedException("Encryption is not supported for remote signing.");
    }

    #endregion
}