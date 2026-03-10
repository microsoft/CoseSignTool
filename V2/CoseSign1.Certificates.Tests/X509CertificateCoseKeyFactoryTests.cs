// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Tests.Common;
using NUnit.Framework;

/// <summary>
/// Tests for X509CertificateCoseKeyFactory.
/// </summary>
[TestFixture]
[Category("CoseKey")]
public class X509CertificateCoseKeyFactoryTests
{
    private X509Certificate2? _rsaCert;
    private X509Certificate2? _ecdsaCert256;
    private X509Certificate2? _ecdsaCert384;
    private X509Certificate2? _ecdsaCert521;
    private X509Certificate2? _rsaCert3072;
    private X509Certificate2? _rsaCert4096;
    private X509Certificate2? _publicOnlyCert;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        // Create RSA certificates of various sizes
        _rsaCert = TestCertificateUtils.CreateCertificate(
            nameof(X509CertificateCoseKeyFactoryTests) + "_RSA2048",
            useEcc: false,
            keySize: 2048);

        _rsaCert3072 = TestCertificateUtils.CreateCertificate(
            nameof(X509CertificateCoseKeyFactoryTests) + "_RSA3072",
            useEcc: false,
            keySize: 3072);

        _rsaCert4096 = TestCertificateUtils.CreateCertificate(
            nameof(X509CertificateCoseKeyFactoryTests) + "_RSA4096",
            useEcc: false,
            keySize: 4096);

        // Create ECDSA certificates of various sizes
        _ecdsaCert256 = TestCertificateUtils.CreateECDsaCertificate(
            nameof(X509CertificateCoseKeyFactoryTests) + "_ECDSA256",
            keySize: 256);

        _ecdsaCert384 = TestCertificateUtils.CreateECDsaCertificate(
            nameof(X509CertificateCoseKeyFactoryTests) + "_ECDSA384",
            keySize: 384);

        _ecdsaCert521 = TestCertificateUtils.CreateECDsaCertificate(
            nameof(X509CertificateCoseKeyFactoryTests) + "_ECDSA521",
            keySize: 521);

        // Create a public-only certificate
        _publicOnlyCert = TestCertificateUtils.CreateCertificateWithoutPrivateKey(_rsaCert);
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _rsaCert?.Dispose();
        _rsaCert3072?.Dispose();
        _rsaCert4096?.Dispose();
        _ecdsaCert256?.Dispose();
        _ecdsaCert384?.Dispose();
        _ecdsaCert521?.Dispose();
        _publicOnlyCert?.Dispose();
    }

    #region CreateFromPublicKey Tests

    [Test]
    public void CreateFromPublicKey_WithNullCertificate_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            X509CertificateCoseKeyFactory.CreateFromPublicKey(null!));
    }

    [Test]
    public void CreateFromPublicKey_WithRsaCert_ReturnsCoseKey()
    {
        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPublicKey(_rsaCert!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void CreateFromPublicKey_WithEcdsaCert256_ReturnsCoseKey()
    {
        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPublicKey(_ecdsaCert256!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void CreateFromPublicKey_WithEcdsaCert384_ReturnsCoseKey()
    {
        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPublicKey(_ecdsaCert384!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void CreateFromPublicKey_WithEcdsaCert521_ReturnsCoseKey()
    {
        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPublicKey(_ecdsaCert521!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void CreateFromPublicKey_WithPublicOnlyCert_ReturnsCoseKey()
    {
        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPublicKey(_publicOnlyCert!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    #endregion

    #region CreateFromPrivateKey Tests

    [Test]
    public void CreateFromPrivateKey_WithNullCertificate_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            X509CertificateCoseKeyFactory.CreateFromPrivateKey(null!));
    }

    [Test]
    public void CreateFromPrivateKey_WithPublicOnlyCert_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            X509CertificateCoseKeyFactory.CreateFromPrivateKey(_publicOnlyCert!));
    }

    [Test]
    public void CreateFromPrivateKey_WithRsaCert_ReturnsCoseKey()
    {
        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPrivateKey(_rsaCert!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void CreateFromPrivateKey_WithEcdsaCert_ReturnsCoseKey()
    {
        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPrivateKey(_ecdsaCert256!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    #endregion

    #region GetHashAlgorithmForKeySize Tests

    [Test]
    [TestCase(256, "SHA256")]
    [TestCase(384, "SHA384")]
    [TestCase(521, "SHA512")]
    [TestCase(2048, "SHA256")]
    [TestCase(3072, "SHA384")]
    [TestCase(4096, "SHA512")]
    public void GetHashAlgorithmForKeySize_ReturnsCorrectAlgorithm(int keySize, string expectedName)
    {
        // Act
        var hashAlgorithm = X509CertificateCoseKeyFactory.GetHashAlgorithmForKeySize(keySize);

        // Assert
        Assert.That(hashAlgorithm.Name, Is.EqualTo(expectedName));
    }

    [Test]
    public void GetHashAlgorithmForKeySize_WithSmallKeySize_ReturnsSHA256()
    {
        // Act
        var hashAlgorithm = X509CertificateCoseKeyFactory.GetHashAlgorithmForKeySize(128);

        // Assert
        Assert.That(hashAlgorithm.Name, Is.EqualTo("SHA256"));
    }

    [Test]
    public void GetHashAlgorithmForKeySize_WithLargeKeySize_ReturnsSHA512()
    {
        // Act
        var hashAlgorithm = X509CertificateCoseKeyFactory.GetHashAlgorithmForKeySize(8192);

        // Assert
        Assert.That(hashAlgorithm.Name, Is.EqualTo("SHA512"));
    }

    #endregion

    #region RSA Key Size Variation Tests

    [Test]
    public void CreateFromPrivateKey_WithRsa3072_ReturnsCoseKey()
    {
        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPrivateKey(_rsaCert3072!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void CreateFromPrivateKey_WithRsa4096_ReturnsCoseKey()
    {
        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPrivateKey(_rsaCert4096!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void CreateFromPublicKey_WithRsa3072_ReturnsCoseKey()
    {
        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPublicKey(_rsaCert3072!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void CreateFromPublicKey_WithRsa4096_ReturnsCoseKey()
    {
        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPublicKey(_rsaCert4096!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    #endregion

    #region ECDSA Key Size Variation Tests

    [Test]
    public void CreateFromPrivateKey_WithEcdsa384_ReturnsCoseKey()
    {
        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPrivateKey(_ecdsaCert384!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void CreateFromPrivateKey_WithEcdsa521_ReturnsCoseKey()
    {
        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPrivateKey(_ecdsaCert521!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    #endregion
}
