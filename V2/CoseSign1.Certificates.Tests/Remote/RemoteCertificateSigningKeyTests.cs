// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Remote;

using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Remote;
using Moq;

/// <summary>
/// Tests for <see cref="RemoteCertificateSigningKey"/>.
/// </summary>
[TestFixture]
public class RemoteCertificateSigningKeyTests
{
    #region Constructor Tests

    [Test]
    public void Constructor_WithNullCertificateSource_ThrowsArgumentNullException()
    {
        // Arrange
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new RemoteCertificateSigningKey(null!, signingService));
    }

    [Test]
    public void Constructor_WithNullSigningService_ThrowsArgumentNullException()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new RemoteCertificateSigningKey(source, null!));
    }

    [Test]
    public void Constructor_WithValidParameters_CreatesInstance()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;

        // Act
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Assert
        Assert.That(key, Is.Not.Null);
        Assert.That(key.SigningService, Is.SameAs(signingService));
    }

    #endregion

    #region Metadata Tests

    [Test]
    public void Metadata_WithRsaCertificate_ReturnsRsaMetadata()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata, Is.Not.Null);
        Assert.That(metadata.KeyType, Is.EqualTo(CoseSign1.Abstractions.CryptographicKeyType.RSA));
        Assert.That(metadata.IsRemote, Is.True);
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(2048));
    }

    [Test]
    public void Metadata_WithEcdsaP256Certificate_ReturnsEcdsaMetadata()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 256);
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata, Is.Not.Null);
        Assert.That(metadata.KeyType, Is.EqualTo(CoseSign1.Abstractions.CryptographicKeyType.ECDsa));
        Assert.That(metadata.IsRemote, Is.True);
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(256));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-7)); // ES256
    }

    [Test]
    public void Metadata_WithEcdsaP384Certificate_ReturnsES384Algorithm()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 384);
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-35)); // ES384
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA384));
    }

    [Test]
    public void Metadata_WithEcdsaP521Certificate_ReturnsES512Algorithm()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 521);
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-36)); // ES512
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA512));
    }

    [Test]
    public void Metadata_IsLazyLoaded()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act - access metadata twice
        var metadata1 = key.Metadata;
        var metadata2 = key.Metadata;

        // Assert - should return the same cached instance
        Assert.That(metadata1, Is.SameAs(metadata2));
    }

    #endregion

    #region GetCoseKey Tests

    [Test]
    public void GetCoseKey_WithRsaCertificate_ReturnsCoseKey()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_WithEcdsaCertificate_ReturnsCoseKey()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateECDsaCertificate();
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_CachesResult()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var coseKey1 = key.GetCoseKey();
        var coseKey2 = key.GetCoseKey();

        // Assert
        Assert.That(coseKey1, Is.SameAs(coseKey2));
    }

    [Test]
    public void GetCoseKey_IsThreadSafe()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act - call from multiple threads concurrently
        var tasks = Enumerable.Range(0, 10)
            .Select(_ => Task.Run(() => key.GetCoseKey()))
            .ToArray();

        var results = Task.WhenAll(tasks).Result;

        // Assert - all should return the same instance
        Assert.That(results.Distinct().Count(), Is.EqualTo(1));
    }

    #endregion

    #region GetSigningCertificate Tests

    [Test]
    public void GetSigningCertificate_ReturnsCertificateFromSource()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var signingCert = key.GetSigningCertificate();

        // Assert
        Assert.That(signingCert, Is.SameAs(cert));
    }

    #endregion

    #region GetCertificateChain Tests

    [Test]
    public void GetCertificateChain_LeafFirst_ReturnsChainInCorrectOrder()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var chain = key.GetCertificateChain(X509ChainSortOrder.LeafFirst).ToList();

        // Assert
        Assert.That(chain, Is.Not.Empty);
        Assert.That(chain[0].Subject, Is.EqualTo(cert.Subject));
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_CalledMultipleTimes_DoesNotThrow()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        var key = new RemoteCertificateSigningKey(source, signingService);

        // Act & Assert - should not throw
        Assert.DoesNotThrow(() =>
        {
            key.Dispose();
            key.Dispose();
            key.Dispose();
        });
    }

    #endregion

    #region Test Helper Class

    /// <summary>
    /// Test implementation of RemoteCertificateSource that uses local signing.
    /// </summary>
    private class TestRemoteCertificateSource : RemoteCertificateSource
    {
        private readonly X509Certificate2 Certificate;

        public TestRemoteCertificateSource(X509Certificate2 certificate, ICertificateChainBuilder? chainBuilder = null)
            : base(chainBuilder)
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
            // Don't dispose the certificate - let the test manage it
            base.Dispose(disposing);
        }
    }

    #endregion
}
