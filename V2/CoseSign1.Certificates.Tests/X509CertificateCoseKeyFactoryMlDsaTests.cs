// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

using CoseSign1.Tests.Common;

/// <summary>
/// Tests for ML-DSA (Post-Quantum Cryptography) support in X509CertificateCoseKeyFactory.
/// These tests require .NET 10+ and Windows platform for ML-DSA support.
/// </summary>
[TestFixture]
[Category("MLDSA")]
[Category("PostQuantum")]
public class X509CertificateCoseKeyFactoryMlDsaTests
{
    private X509Certificate2? _mlDsaCert44;
    private X509Certificate2? _mlDsaCert65;
    private X509Certificate2? _mlDsaCert87;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        PlatformHelper.SkipIfMLDsaNotSupported("ML-DSA tests require Windows platform");

        _mlDsaCert44 = TestCertificateUtils.CreateMLDsaCertificate("MLDSA44FactoryTest", mlDsaParameterSet: 44);
        _mlDsaCert65 = TestCertificateUtils.CreateMLDsaCertificate("MLDSA65FactoryTest", mlDsaParameterSet: 65);
        _mlDsaCert87 = TestCertificateUtils.CreateMLDsaCertificate("MLDSA87FactoryTest", mlDsaParameterSet: 87);
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _mlDsaCert44?.Dispose();
        _mlDsaCert65?.Dispose();
        _mlDsaCert87?.Dispose();
    }

    #region CreateFromPublicKey ML-DSA Tests

    [Test]
    public void CreateFromPublicKey_WithMLDsa44Certificate_ReturnsCoseKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPublicKey(_mlDsaCert44!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void CreateFromPublicKey_WithMLDsa65Certificate_ReturnsCoseKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPublicKey(_mlDsaCert65!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void CreateFromPublicKey_WithMLDsa87Certificate_ReturnsCoseKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPublicKey(_mlDsaCert87!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    #endregion

    #region CreateFromPrivateKey ML-DSA Tests

    [Test]
    public void CreateFromPrivateKey_WithMLDsa44Certificate_ReturnsCoseKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPrivateKey(_mlDsaCert44!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void CreateFromPrivateKey_WithMLDsa65Certificate_ReturnsCoseKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPrivateKey(_mlDsaCert65!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void CreateFromPrivateKey_WithMLDsa87Certificate_ReturnsCoseKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Act
        var coseKey = X509CertificateCoseKeyFactory.CreateFromPrivateKey(_mlDsaCert87!);

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    #endregion
}
