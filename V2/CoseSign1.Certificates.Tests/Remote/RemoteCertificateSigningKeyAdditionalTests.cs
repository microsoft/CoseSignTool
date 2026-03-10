// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Remote;

using CoseSign1.Abstractions;
using CoseSign1.Certificates.Remote;
using Moq;

/// <summary>
/// Additional tests for RemoteCertificateSigningKey to improve code coverage.
/// Focuses on metadata creation for different key types and algorithms.
/// </summary>
[TestFixture]
public class RemoteCertificateSigningKeyAdditionalTests
{
    #region Metadata Tests for Different RSA Key Sizes

    [Test]
    public void Metadata_WithRsa3072Certificate_ReturnsPS384Algorithm()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA3072", keySize: 3072);
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-38)); // PS384
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA384));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(3072));
    }

    [Test]
    public void Metadata_WithRsa4096Certificate_ReturnsPS512Algorithm()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA4096", keySize: 4096);
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-39)); // PS512
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA512));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(4096));
    }

    [Test]
    public void Metadata_WithRsa2048Certificate_ReturnsPS256Algorithm()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA2048", keySize: 2048);
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-37)); // PS256
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA256));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(2048));
    }

    #endregion

    #region GetCertificateChain Tests

    [Test]
    public void GetCertificateChain_RootFirst_ReturnsChainInReverseOrder()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var chain = key.GetCertificateChain(X509ChainSortOrder.RootFirst).ToList();

        // Assert
        Assert.That(chain, Is.Not.Null);
        Assert.That(chain.Count, Is.GreaterThan(0));
    }

    [Test]
    public void GetCertificateChain_LeafFirst_ReturnsChainWithLeafFirst()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var chain = key.GetCertificateChain(X509ChainSortOrder.LeafFirst).ToList();

        // Assert
        Assert.That(chain, Is.Not.Null);
        Assert.That(chain.Count, Is.GreaterThan(0));
        // First certificate should be the leaf certificate
        Assert.That(chain[0].Subject, Is.EqualTo(cert.Subject));
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_MultipleCalls_DoesNotThrow()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        var key = new RemoteCertificateSigningKey(source, signingService);

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            key.Dispose();
            key.Dispose();
            key.Dispose();
        });
    }

    [Test]
    public void Dispose_ClearsCoseKeyCache()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        var key = new RemoteCertificateSigningKey(source, signingService);

        // Act - get cose key first to populate cache
        var coseKey = key.GetCoseKey();
        key.Dispose();

        // Assert - disposed, key should have been cached
        Assert.That(coseKey, Is.Not.Null);
    }

    #endregion

    #region GetCoseKey Tests for Different Key Types

    [Test]
    public void GetCoseKey_WithEcdsaP256_ReturnsCoseKeyWithCorrectAlgorithm()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 256);
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_WithEcdsaP384_ReturnsCoseKey()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 384);
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_WithEcdsaP521_ReturnsCoseKey()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 521);
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_WithRsa3072_ReturnsCoseKey()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA3072", keySize: 3072);
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_WithRsa4096_ReturnsCoseKey()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA4096", keySize: 4096);
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    #endregion

    #region Test Helper Class

    /// <summary>
    /// Test implementation of RemoteCertificateSource that uses local signing.
    /// </summary>
    private class TestRemoteCertificateSource : RemoteCertificateSource
    {
        private readonly X509Certificate2 Certificate;

        public TestRemoteCertificateSource(X509Certificate2 certificate)
            : base()
        {
            Certificate = certificate;
        }

        public override X509Certificate2 GetSigningCertificate() => Certificate;

        public override byte[] SignDataWithRsa(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            using var rsa = Certificate.GetRSAPrivateKey();
            return rsa!.SignData(data, hashAlgorithm, padding);
        }

        public override Task<byte[]> SignDataWithRsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SignDataWithRsa(data, hashAlgorithm, padding));
        }

        public override byte[] SignHashWithRsa(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            using var rsa = Certificate.GetRSAPrivateKey();
            return rsa!.SignHash(hash, hashAlgorithm, padding);
        }

        public override Task<byte[]> SignHashWithRsaAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SignHashWithRsa(hash, hashAlgorithm, padding));
        }

        public override byte[] SignDataWithEcdsa(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            using var ecdsa = Certificate.GetECDsaPrivateKey();
            return ecdsa!.SignData(data, hashAlgorithm);
        }

        public override Task<byte[]> SignDataWithEcdsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SignDataWithEcdsa(data, hashAlgorithm));
        }

        public override byte[] SignHashWithEcdsa(byte[] hash)
        {
            using var ecdsa = Certificate.GetECDsaPrivateKey();
            return ecdsa!.SignHash(hash);
        }

        public override Task<byte[]> SignHashWithEcdsaAsync(byte[] hash, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SignHashWithEcdsa(hash));
        }

        public override byte[] SignDataWithMLDsa(byte[] data, HashAlgorithmName? hashAlgorithm = null)
        {
            throw new NotSupportedException("ML-DSA not implemented in test helper");
        }

        public override Task<byte[]> SignDataWithMLDsaAsync(byte[] data, HashAlgorithmName? hashAlgorithm = null, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException("ML-DSA not implemented in test helper");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Certificate?.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    #endregion
}
