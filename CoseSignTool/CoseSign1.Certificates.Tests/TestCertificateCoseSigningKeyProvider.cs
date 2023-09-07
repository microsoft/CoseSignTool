// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

/// <summary>
///  Custom class to test <see cref="CertificateCoseSigningKeyProvider"/> constructor and protected methods.
/// </summary>
internal class TestCertificateCoseSigningKeyProvider : CertificateCoseSigningKeyProvider
{
    public TestCertificateCoseSigningKeyProvider(HashAlgorithmName? hashAlgorithm = null) : base(null, hashAlgorithm)
    {
    }

    public CoseHeaderMap? TestGetUnProtectedHeadersImplementation() => base.GetUnProtectedHeadersImplementation();

    protected override IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder)
    {
        throw new NotImplementedException();
    }



    protected override X509Certificate2 GetSigningCertificate()
    {
        throw new NotImplementedException();
    }

    protected override ECDsa? ProvideECDsaKey(bool publicKey = false)
    {
        throw new NotImplementedException();
    }

    protected override RSA? ProvideRSAKey(bool publicKey = false)
    {
        throw new NotImplementedException();
    }
}
