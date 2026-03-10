// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local.Tests;

[TestFixture]
public sealed class AbstractionsCoverageTests
{
    [Test]
    public void ICertificateFactory_CreatePublicOnlyCertificate_WhenNull_ThrowsArgumentNullException()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => ICertificateFactory.CreatePublicOnlyCertificate(null!));
        Assert.That(ex!.ParamName, Is.EqualTo("certificate"));
    }

    [Test]
    public void ICertificateFactory_CreatePublicOnlyCertificate_ReturnsPublicOnlyCertificate()
    {
        using var certWithPrivateKey = LocalCertificateFactory.CreateRsaCertificate("PublicOnly", 2048);

        using var publicOnly = ICertificateFactory.CreatePublicOnlyCertificate(certWithPrivateKey);

        Assert.That(publicOnly, Is.Not.Null);
        Assert.That(publicOnly.HasPrivateKey, Is.False);
        Assert.That(publicOnly.Subject, Is.EqualTo(certWithPrivateKey.Subject));
    }

    [Test]
    public void IGeneratedKey_GetMLDsa_DefaultImplementation_ReturnsNull()
    {
        using var key = new DummyGeneratedKey();
        Assert.That(((IGeneratedKey)key).GetMLDsa(), Is.Null);
    }

    private sealed class DummyGeneratedKey : IGeneratedKey
    {
        private readonly RSA Rsa = RSA.Create(2048);
        private readonly X509SignatureGenerator Generator;

        public DummyGeneratedKey()
        {
            Generator = X509SignatureGenerator.CreateForRSA(Rsa, RSASignaturePadding.Pkcs1);
        }

        public KeyAlgorithm Algorithm => KeyAlgorithm.RSA;

        public X509SignatureGenerator SignatureGenerator => Generator;

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
            Rsa.Dispose();
        }
    }
}
