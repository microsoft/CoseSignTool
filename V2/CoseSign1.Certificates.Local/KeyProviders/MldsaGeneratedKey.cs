// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// ML-DSA (Post-Quantum) key implementation of <see cref="IGeneratedKey"/>.
/// </summary>
internal sealed class MldsaGeneratedKey : IGeneratedKey
{
    private readonly MLDsa Mldsa;
    private bool Disposed;

    public MldsaGeneratedKey(MLDsa mldsa)
    {
        Mldsa = mldsa ?? throw new ArgumentNullException(nameof(mldsa));
    }

    public KeyAlgorithm Algorithm => KeyAlgorithm.MLDSA;

    public X509SignatureGenerator SignatureGenerator => new MLDsaX509SignatureGenerator(Mldsa);

    public CertificateRequest CreateCertificateRequest(string subjectName, HashAlgorithmName hashAlgorithm)
    {
        // ML-DSA has built-in hashing, so hashAlgorithm is ignored
        return new CertificateRequest(subjectName, Mldsa);
    }

    public X509Certificate2 CopyPrivateKeyTo(X509Certificate2 certificate)
    {
        // Use the CopyWithPrivateKey extension method for ML-DSA
        return certificate.CopyWithPrivateKey(Mldsa);
    }

    /// <inheritdoc />
    public MLDsa? GetMLDsa() => Mldsa;

    public void Dispose()
    {
        if (!Disposed)
        {
            Mldsa.Dispose();
            Disposed = true;
        }
    }
}