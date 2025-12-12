// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;

namespace CoseSign1.Certificates.Remote;

/// <summary>
/// ML-DSA implementation that delegates signing operations to a remote service.
/// This class wraps ML-DSA public key information but performs signing through RemoteCertificateSource.
/// </summary>
#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview in .NET 10
internal sealed class RemoteMLDsa : MLDsa
{
    private readonly RemoteCertificateSource _certificateSource;
    private readonly byte[] _publicKey;
    private bool _disposed;

    public RemoteMLDsa(RemoteCertificateSource certificateSource, byte[] publicKey, int securityLevel)
        : base(securityLevel switch
        {
            44 => MLDsaAlgorithm.MLDsa44,
            65 => MLDsaAlgorithm.MLDsa65,
            87 => MLDsaAlgorithm.MLDsa87,
            _ => MLDsaAlgorithm.MLDsa65
        })
    {
        _certificateSource = certificateSource ?? throw new ArgumentNullException(nameof(certificateSource));
        _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
    }

    #region Core Abstract Methods - Must implement for ML-DSA base class

    protected override void SignDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> context, Span<byte> destination)
    {
        var signature = _certificateSource.SignDataWithMLDsa(data.ToArray(), hashAlgorithm: null);
        signature.CopyTo(destination);
    }

    protected override void SignPreHashCore(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> context, string hashAlgorithm, Span<byte> destination)
    {
        // For pre-hashed signing, we need to use the hash directly
        var hashAlgName = hashAlgorithm switch
        {
            "SHA-256" => HashAlgorithmName.SHA256,
            "SHA-384" => HashAlgorithmName.SHA384,
            "SHA-512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256
        };

        var signature = _certificateSource.SignDataWithMLDsa(hash.ToArray(), hashAlgName);
        signature.CopyTo(destination);
    }

    protected override void SignMuCore(ReadOnlySpan<byte> mu, Span<byte> destination)
    {
        // ML-DSA pure mode signing (no pre-hashing)
        var signature = _certificateSource.SignDataWithMLDsa(mu.ToArray(), hashAlgorithm: null);
        signature.CopyTo(destination);
    }

    protected override bool VerifyDataCore(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context)
    {
        throw new NotSupportedException("Verification should be performed using public key directly, not through remote service.");
    }

    protected override bool VerifyPreHashCore(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, string hashAlgorithm, ReadOnlySpan<byte> context)
    {
        throw new NotSupportedException("Verification should be performed using public key directly, not through remote service.");
    }

    protected override bool VerifyMuCore(ReadOnlySpan<byte> mu, ReadOnlySpan<byte> signature)
    {
        throw new NotSupportedException("Verification should be performed using public key directly, not through remote service.");
    }

    protected override void ExportMLDsaPublicKeyCore(Span<byte> destination)
    {
        _publicKey.CopyTo(destination);
    }

    protected override void ExportMLDsaPrivateKeyCore(Span<byte> destination)
    {
        throw new CryptographicException("Private key export is not supported for remote signing.");
    }

    protected override void ExportMLDsaPrivateSeedCore(Span<byte> destination)
    {
        throw new CryptographicException("Private seed export is not supported for remote signing.");
    }

    protected override bool TryExportPkcs8PrivateKeyCore(Span<byte> destination, out int bytesWritten)
    {
        throw new CryptographicException("Private key export is not supported for remote signing.");
    }

    #endregion

    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _disposed = true;
            base.Dispose(disposing);
        }
    }
}
#pragma warning restore SYSLIB5006