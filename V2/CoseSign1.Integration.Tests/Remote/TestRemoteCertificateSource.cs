// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Remote;

namespace CoseSign1.Integration.Tests.Remote;

/// <summary>
/// Test implementation of RemoteCertificateSource that simulates a remote signing service
/// by delegating to DirectCertificateSource. This allows testing the remote signing
/// architecture without requiring an actual remote service.
/// </summary>
internal sealed class TestRemoteCertificateSource : RemoteCertificateSource
{
    private readonly DirectCertificateSource _directCertificateSource;

    public TestRemoteCertificateSource(DirectCertificateSource directCertificateSource)
    {
        _directCertificateSource = directCertificateSource ?? throw new ArgumentNullException(nameof(directCertificateSource));
    }

    public override X509Certificate2 GetSigningCertificate()
    {
        return _directCertificateSource.GetSigningCertificate();
    }

    // RSA sync methods
    public override byte[] SignDataWithRsa(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        var cert = _directCertificateSource.GetSigningCertificate();
        using var rsa = cert.GetRSAPrivateKey();
        if (rsa == null)
        {
            throw new InvalidOperationException("Certificate does not have an RSA private key.");
        }
        return rsa.SignData(data, hashAlgorithm, padding);
    }

    public override byte[] SignHashWithRsa(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        var cert = _directCertificateSource.GetSigningCertificate();
        using var rsa = cert.GetRSAPrivateKey();
        if (rsa == null)
        {
            throw new InvalidOperationException("Certificate does not have an RSA private key.");
        }
        return rsa.SignHash(hash, hashAlgorithm, padding);
    }

    // RSA async methods
    public override Task<byte[]> SignDataWithRsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(SignDataWithRsa(data, hashAlgorithm, padding));
    }

    public override Task<byte[]> SignHashWithRsaAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(SignHashWithRsa(hash, hashAlgorithm, padding));
    }

    // ECDSA sync methods
    public override byte[] SignDataWithEcdsa(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        var cert = _directCertificateSource.GetSigningCertificate();
        using var ecdsa = cert.GetECDsaPrivateKey();
        if (ecdsa == null)
        {
            throw new InvalidOperationException("Certificate does not have an ECDSA private key.");
        }
        return ecdsa.SignData(data, hashAlgorithm);
    }

    public override byte[] SignHashWithEcdsa(byte[] hash)
    {
        var cert = _directCertificateSource.GetSigningCertificate();
        using var ecdsa = cert.GetECDsaPrivateKey();
        if (ecdsa == null)
        {
            throw new InvalidOperationException("Certificate does not have an ECDSA private key.");
        }
        return ecdsa.SignHash(hash);
    }

    // ECDSA async methods
    public override Task<byte[]> SignDataWithEcdsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(SignDataWithEcdsa(data, hashAlgorithm));
    }

    public override Task<byte[]> SignHashWithEcdsaAsync(byte[] hash, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(SignHashWithEcdsa(hash));
    }

    // ML-DSA sync method
    public override byte[] SignDataWithMLDsa(byte[] data, HashAlgorithmName? hashAlgorithm = null)
    {
        var cert = _directCertificateSource.GetSigningCertificate();
        using var mldsa = cert.GetMLDsaPrivateKey();
        if (mldsa == null)
        {
            throw new InvalidOperationException("Certificate does not have an ML-DSA private key.");
        }
        return mldsa.SignData(data);
    }

    // ML-DSA async method
    public override Task<byte[]> SignDataWithMLDsaAsync(byte[] data, HashAlgorithmName? hashAlgorithm = null, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(SignDataWithMLDsa(data, hashAlgorithm));
    }
}