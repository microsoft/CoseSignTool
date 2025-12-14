// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// RSA key implementation of <see cref="IGeneratedKey"/>.
/// </summary>
internal sealed class RsaGeneratedKey : IGeneratedKey
{
    private readonly RSA Rsa;
    private bool Disposed;

    public RsaGeneratedKey(RSA rsa)
    {
        Rsa = rsa ?? throw new ArgumentNullException(nameof(rsa));
    }

    public KeyAlgorithm Algorithm => KeyAlgorithm.RSA;

    public X509SignatureGenerator SignatureGenerator =>
        X509SignatureGenerator.CreateForRSA(Rsa, RSASignaturePadding.Pkcs1);

    public CertificateRequest CreateCertificateRequest(string subjectName, HashAlgorithmName hashAlgorithm)
    {
        return new CertificateRequest(subjectName, Rsa, hashAlgorithm, RSASignaturePadding.Pkcs1);
    }

    public X509Certificate2 CopyPrivateKeyTo(X509Certificate2 certificate)
    {
        return certificate.CopyWithPrivateKey(Rsa);
    }

    public void Dispose()
    {
        if (!Disposed)
        {
            Rsa.Dispose();
            Disposed = true;
        }
    }
}