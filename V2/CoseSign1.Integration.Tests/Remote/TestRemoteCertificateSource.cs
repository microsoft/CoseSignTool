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

    public override byte[] SignHashWithRsa(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        // Simulate remote signing by extracting the private key and signing locally
        var cert = _directCertificateSource.GetSigningCertificate();
        using var rsa = cert.GetRSAPrivateKey();
        if (rsa == null)
        {
            throw new InvalidOperationException("Certificate does not have an RSA private key.");
        }
        return rsa.SignHash(hash, hashAlgorithm, padding);
    }

    public override byte[] SignHashWithEcdsa(byte[] hash)
    {
        // Simulate remote signing by extracting the private key and signing locally
        var cert = _directCertificateSource.GetSigningCertificate();
        using var ecdsa = cert.GetECDsaPrivateKey();
        if (ecdsa == null)
        {
            throw new InvalidOperationException("Certificate does not have an ECDSA private key.");
        }
        return ecdsa.SignHash(hash);
    }

    public override byte[] SignDataWithMLDsa(byte[] data, HashAlgorithmName? hashAlgorithm = null)
    {
        // Simulate remote signing by extracting the private key and signing locally
        var cert = _directCertificateSource.GetSigningCertificate();
        using var mldsa = cert.GetMLDsaPrivateKey();
        if (mldsa == null)
        {
            throw new InvalidOperationException("Certificate does not have an ML-DSA private key.");
        }
        return mldsa.SignData(data);
    }
}
