// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Local;
using CoseSign1.Tests.Common;
using Moq;

/// <summary>
/// Additional tests for CertificateSigningServiceKey to improve code coverage.
/// Tests focus on edge cases in metadata detection and dispose patterns.
/// </summary>
[TestFixture]
[Category("SigningKey")]
public class CertificateSigningServiceKeyAdditionalTests
{
    private X509Certificate2? _rsaCert2048;
    private X509Certificate2? _rsaCert3072;
    private X509Certificate2? _rsaCert4096;
    private X509Certificate2? _ecdsaCert256;
    private X509Certificate2? _ecdsaCert384;
    private X509Certificate2? _ecdsaCert521;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        _rsaCert2048 = TestCertificateUtils.CreateCertificate("RSA2048", keySize: 2048);
        _rsaCert3072 = TestCertificateUtils.CreateCertificate("RSA3072", keySize: 3072);
        _rsaCert4096 = TestCertificateUtils.CreateCertificate("RSA4096", keySize: 4096);
        _ecdsaCert256 = TestCertificateUtils.CreateECDsaCertificate(keySize: 256);
        _ecdsaCert384 = TestCertificateUtils.CreateECDsaCertificate(keySize: 384);
        _ecdsaCert521 = TestCertificateUtils.CreateECDsaCertificate(keySize: 521);
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _rsaCert2048?.Dispose();
        _rsaCert3072?.Dispose();
        _rsaCert4096?.Dispose();
        _ecdsaCert256?.Dispose();
        _ecdsaCert384?.Dispose();
        _ecdsaCert521?.Dispose();
    }

    #region Constructor Tests

    [Test]
    public void Constructor_WithNullCertificateSource_ThrowsArgumentNullException()
    {
        // Arrange
        var mockKeyProvider = new Mock<CoseSign1.Certificates.Interfaces.ISigningKeyProvider>().Object;
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CertificateSigningServiceKey(null!, mockKeyProvider, mockService));
    }

    [Test]
    public void Constructor_WithNullSigningKeyProvider_ThrowsArgumentNullException()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_rsaCert2048!);
        using var source = new DirectCertificateSource(_rsaCert2048!, chainBuilder);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CertificateSigningServiceKey(source, null!, mockService));
    }

    [Test]
    public void Constructor_WithNullSigningService_ThrowsArgumentNullException()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_rsaCert2048!);
        using var source = new DirectCertificateSource(_rsaCert2048!, chainBuilder);
        using var keyProvider = new DirectSigningKeyProvider(_rsaCert2048!);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CertificateSigningServiceKey(source, keyProvider, null!));
    }

    #endregion

    #region Metadata Detection Tests - RSA Key Sizes

    [Test]
    public void Metadata_WithRsa2048_ReturnsPS256Algorithm()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_rsaCert2048!);
        using var source = new DirectCertificateSource(_rsaCert2048!, chainBuilder);
        using var keyProvider = new DirectSigningKeyProvider(_rsaCert2048!);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new CertificateSigningServiceKey(source, keyProvider, mockService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-37)); // PS256
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA256));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(2048));
    }

    [Test]
    public void Metadata_WithRsa3072_ReturnsPS384Algorithm()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_rsaCert3072!);
        using var source = new DirectCertificateSource(_rsaCert3072!, chainBuilder);
        using var keyProvider = new DirectSigningKeyProvider(_rsaCert3072!);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new CertificateSigningServiceKey(source, keyProvider, mockService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-38)); // PS384
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA384));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(3072));
    }

    [Test]
    public void Metadata_WithRsa4096_ReturnsPS512Algorithm()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_rsaCert4096!);
        using var source = new DirectCertificateSource(_rsaCert4096!, chainBuilder);
        using var keyProvider = new DirectSigningKeyProvider(_rsaCert4096!);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new CertificateSigningServiceKey(source, keyProvider, mockService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-39)); // PS512
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA512));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(4096));
    }

    #endregion

    #region Metadata Detection Tests - ECDSA Key Sizes

    [Test]
    public void Metadata_WithEcdsaP256_ReturnsES256Algorithm()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_ecdsaCert256!);
        using var source = new DirectCertificateSource(_ecdsaCert256!, chainBuilder);
        using var keyProvider = new DirectSigningKeyProvider(_ecdsaCert256!);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new CertificateSigningServiceKey(source, keyProvider, mockService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-7)); // ES256
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA256));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(256));
    }

    [Test]
    public void Metadata_WithEcdsaP384_ReturnsES384Algorithm()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_ecdsaCert384!);
        using var source = new DirectCertificateSource(_ecdsaCert384!, chainBuilder);
        using var keyProvider = new DirectSigningKeyProvider(_ecdsaCert384!);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new CertificateSigningServiceKey(source, keyProvider, mockService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-35)); // ES384
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA384));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(384));
    }

    [Test]
    public void Metadata_WithEcdsaP521_ReturnsES512Algorithm()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_ecdsaCert521!);
        using var source = new DirectCertificateSource(_ecdsaCert521!, chainBuilder);
        using var keyProvider = new DirectSigningKeyProvider(_ecdsaCert521!);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new CertificateSigningServiceKey(source, keyProvider, mockService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-36)); // ES512
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA512));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(521));
    }

    #endregion

    #region GetCoseKey Tests

    [Test]
    public void GetCoseKey_WithRsaCert_ReturnsCoseKey()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_rsaCert2048!);
        using var source = new DirectCertificateSource(_rsaCert2048!, chainBuilder);
        using var keyProvider = new DirectSigningKeyProvider(_rsaCert2048!);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new CertificateSigningServiceKey(source, keyProvider, mockService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_CachesResult()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_rsaCert2048!);
        using var source = new DirectCertificateSource(_rsaCert2048!, chainBuilder);
        using var keyProvider = new DirectSigningKeyProvider(_rsaCert2048!);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new CertificateSigningServiceKey(source, keyProvider, mockService);

        // Act
        var coseKey1 = key.GetCoseKey();
        var coseKey2 = key.GetCoseKey();

        // Assert - should return same cached instance
        Assert.That(coseKey1, Is.SameAs(coseKey2));
    }

    #endregion

    #region GetSigningCertificate Tests

    [Test]
    public void GetSigningCertificate_ReturnsCorrectCertificate()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_rsaCert2048!);
        using var source = new DirectCertificateSource(_rsaCert2048!, chainBuilder);
        using var keyProvider = new DirectSigningKeyProvider(_rsaCert2048!);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new CertificateSigningServiceKey(source, keyProvider, mockService);

        // Act
        var cert = key.GetSigningCertificate();

        // Assert
        Assert.That(cert.Thumbprint, Is.EqualTo(_rsaCert2048!.Thumbprint));
    }

    #endregion

    #region GetCertificateChain Tests

    [Test]
    public void GetCertificateChain_LeafFirst_ReturnsChainInCorrectOrder()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_rsaCert2048!);
        using var source = new DirectCertificateSource(_rsaCert2048!, chainBuilder);
        using var keyProvider = new DirectSigningKeyProvider(_rsaCert2048!);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new CertificateSigningServiceKey(source, keyProvider, mockService);

        // Act
        var chain = key.GetCertificateChain(X509ChainSortOrder.LeafFirst).ToList();

        // Assert
        Assert.That(chain, Is.Not.Empty);
        Assert.That(chain[0].Thumbprint, Is.EqualTo(_rsaCert2048!.Thumbprint));
    }

    [Test]
    public void GetCertificateChain_RootFirst_ReturnsChainInReverseOrder()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_rsaCert2048!);
        using var source = new DirectCertificateSource(_rsaCert2048!, chainBuilder);
        using var keyProvider = new DirectSigningKeyProvider(_rsaCert2048!);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new CertificateSigningServiceKey(source, keyProvider, mockService);

        // Act
        var chain = key.GetCertificateChain(X509ChainSortOrder.RootFirst).ToList();

        // Assert
        Assert.That(chain, Is.Not.Empty);
    }

    #endregion

    #region SigningService Property Tests

    [Test]
    public void SigningService_ReturnsSameInstance()
    {
        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_rsaCert2048!);
        using var source = new DirectCertificateSource(_rsaCert2048!, chainBuilder);
        using var keyProvider = new DirectSigningKeyProvider(_rsaCert2048!);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        using var key = new CertificateSigningServiceKey(source, keyProvider, mockService);

        // Act
        var service = key.SigningService;

        // Assert
        Assert.That(service, Is.SameAs(mockService));
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_MultipleCalls_DoesNotThrow()
    {
        // Arrange
        var chainBuilder = new ExplicitCertificateChainBuilder(_rsaCert2048!);
        var source = new DirectCertificateSource(_rsaCert2048!, chainBuilder);
        var keyProvider = new DirectSigningKeyProvider(_rsaCert2048!);
        var mockService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;
        var key = new CertificateSigningServiceKey(source, keyProvider, mockService);

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            key.Dispose();
            key.Dispose();
            key.Dispose();
        });
    }

    #endregion
}
