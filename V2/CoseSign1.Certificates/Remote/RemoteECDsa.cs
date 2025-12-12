// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;

namespace CoseSign1.Certificates.Remote;

/// <summary>
/// ECDsa implementation that delegates signing operations to a remote service.
/// This class wraps ECDsa public key information but performs signing through RemoteCertificateSource.
/// </summary>
internal sealed class RemoteECDsa : ECDsa
{
    private readonly RemoteCertificateSource CertificateSource;
    private readonly ECParameters PublicParameters;
    private readonly HashAlgorithmName DefaultHashAlgorithm;
    private bool Disposed;

    public RemoteECDsa(RemoteCertificateSource certificateSource, ECParameters publicParameters)
    {
        CertificateSource = certificateSource ?? throw new ArgumentNullException(nameof(certificateSource));
        PublicParameters = publicParameters;

        // Determine key size from curve
        KeySizeValue = PublicParameters.Curve.Oid?.FriendlyName switch
        {
            "nistP256" => 256,
            "nistP384" => 384,
            "nistP521" => 521,
            _ => 256 // Default
        };

        // Default hash algorithm based on curve
        DefaultHashAlgorithm = KeySizeValue switch
        {
            521 => HashAlgorithmName.SHA512,
            384 => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA256
        };
    }

    public override ECParameters ExportParameters(bool includePrivateParameters)
    {
        if (includePrivateParameters)
        {
            throw new CryptographicException("Private key export is not supported for remote signing.");
        }

        return PublicParameters;
    }

    public override void ImportParameters(ECParameters parameters)
    {
        throw new NotSupportedException("Parameter import is not supported for remote signing.");
    }

    public override byte[] SignHash(byte[] hash)
    {
        // Determine hash algorithm from hash length
        var hashAlgorithm = hash.Length switch
        {
            32 => HashAlgorithmName.SHA256,
            48 => HashAlgorithmName.SHA384,
            64 => HashAlgorithmName.SHA512,
            _ => DefaultHashAlgorithm
        };

        return CertificateSource.SignHashWithEcdsa(hash);
    }

    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        throw new NotSupportedException("Verification should be performed using public key directly, not through remote service.");
    }

    protected override void Dispose(bool disposing)
    {
        if (!Disposed)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    #region Not Implemented - Key generation not needed for COSE signing

    public override void GenerateKey(ECCurve curve)
    {
        throw new NotSupportedException("Key generation is not supported for remote signing.");
    }

    #endregion
}