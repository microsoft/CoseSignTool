// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// ECDSA key implementation of <see cref="IGeneratedKey"/>.
/// </summary>
internal sealed class EcdsaGeneratedKey : IGeneratedKey
{
    private readonly ECDsa Ecdsa;
    private bool Disposed;

    public EcdsaGeneratedKey(ECDsa ecdsa)
    {
        Ecdsa = ecdsa ?? throw new ArgumentNullException(nameof(ecdsa));
    }

    public KeyAlgorithm Algorithm => KeyAlgorithm.ECDSA;

    public X509SignatureGenerator SignatureGenerator =>
        X509SignatureGenerator.CreateForECDsa(Ecdsa);

    public CertificateRequest CreateCertificateRequest(string subjectName, HashAlgorithmName hashAlgorithm)
    {
        return new CertificateRequest(subjectName, Ecdsa, hashAlgorithm);
    }

    public X509Certificate2 CopyPrivateKeyTo(X509Certificate2 certificate)
    {
        return certificate.CopyWithPrivateKey(Ecdsa);
    }

    public void Dispose()
    {
        if (!Disposed)
        {
            Ecdsa.Dispose();
            Disposed = true;
        }
    }
}