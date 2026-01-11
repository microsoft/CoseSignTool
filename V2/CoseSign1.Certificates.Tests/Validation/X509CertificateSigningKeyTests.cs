// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Validation;
using CoseSign1.Tests.Common;
using NUnit.Framework;

/// <summary>
/// Tests for X509CertificateSigningKey.
/// </summary>
[TestFixture]
[Category("Validation")]
public class X509CertificateSigningKeyTests
{
    private X509Certificate2? _rsaCert;
    private X509Certificate2? _ecdsaCert;
    private X509Certificate2Collection? _testChain;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        // Create RSA certificate
        _rsaCert = TestCertificateUtils.CreateCertificate(
            nameof(X509CertificateSigningKeyTests) + "_RSA",
            useEcc: false);

        // Create ECDSA certificate
        _ecdsaCert = TestCertificateUtils.CreateECDsaCertificate(
            nameof(X509CertificateSigningKeyTests) + "_ECDSA");

        // Create a test chain
        _testChain = TestCertificateUtils.CreateTestChain(leafFirst: true);
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _rsaCert?.Dispose();
        _ecdsaCert?.Dispose();
        if (_testChain != null)
        {
            foreach (var cert in _testChain)
            {
                cert?.Dispose();
            }
        }
    }

    #region Constructor Tests

    [Test]
    public void Constructor_WithValidCert_CreatesSigningKey()
    {
        // Act
        var signingKey = new X509CertificateSigningKey(_rsaCert!);

        // Assert
        Assert.That(signingKey, Is.Not.Null);
        Assert.That(signingKey.Certificate, Is.SameAs(_rsaCert));
    }

    [Test]
    public void Constructor_WithNullCert_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new X509CertificateSigningKey(null!));
    }

    [Test]
    public void Constructor_WithChain_SetsChain()
    {
        // Act
        var signingKey = new X509CertificateSigningKey(_rsaCert!, _testChain);

        // Assert
        Assert.That(signingKey.Chain, Is.SameAs(_testChain));
    }

    [Test]
    public void Constructor_WithNullChain_SetsChainToNull()
    {
        // Act
        var signingKey = new X509CertificateSigningKey(_rsaCert!, null);

        // Assert
        Assert.That(signingKey.Chain, Is.Null);
    }

    #endregion

    #region Certificate Property Tests

    [Test]
    public void Certificate_ReturnsCertificate()
    {
        // Arrange
        var signingKey = new X509CertificateSigningKey(_rsaCert!);

        // Act & Assert
        Assert.That(signingKey.Certificate, Is.SameAs(_rsaCert));
    }

    #endregion

    #region Chain Property Tests

    [Test]
    public void Chain_ReturnsChain()
    {
        // Arrange
        var signingKey = new X509CertificateSigningKey(_rsaCert!, _testChain);

        // Act & Assert
        Assert.That(signingKey.Chain, Is.SameAs(_testChain));
    }

    #endregion

    #region GetCoseKey Tests

    [Test]
    public void GetCoseKey_WithRsaCert_ReturnsCoseKey()
    {
        // Arrange
        var signingKey = new X509CertificateSigningKey(_rsaCert!);

        // Act
        var coseKey = signingKey.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_WithEcdsaCert_ReturnsCoseKey()
    {
        // Arrange
        var signingKey = new X509CertificateSigningKey(_ecdsaCert!);

        // Act
        var coseKey = signingKey.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_CalledTwice_ReturnsSameInstance()
    {
        // Arrange
        var signingKey = new X509CertificateSigningKey(_rsaCert!);

        // Act
        var coseKey1 = signingKey.GetCoseKey();
        var coseKey2 = signingKey.GetCoseKey();

        // Assert
        Assert.That(coseKey1, Is.SameAs(coseKey2));
    }

    [Test]
    public void GetCoseKey_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var signingKey = new X509CertificateSigningKey(_rsaCert!);
        signingKey.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => signingKey.GetCoseKey());
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        var signingKey = new X509CertificateSigningKey(_rsaCert!);

        // Act & Assert - should not throw
        signingKey.Dispose();
        signingKey.Dispose();
        signingKey.Dispose();
    }

    #endregion

    #region Thread Safety Tests

    [Test]
    public void GetCoseKey_ConcurrentCalls_ReturnsSameInstance()
    {
        // Arrange
        var signingKey = new X509CertificateSigningKey(_rsaCert!);
        var coseKeys = new CoseKey[10];

        // Act
        Parallel.For(0, 10, i =>
        {
            coseKeys[i] = signingKey.GetCoseKey();
        });

        // Assert - all should be the same instance
        var first = coseKeys[0];
        foreach (var key in coseKeys)
        {
            Assert.That(key, Is.SameAs(first));
        }
    }

    #endregion
}
