// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

using CoseSign1.Abstractions;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Local;
using CoseSign1.Tests.Common;
using Moq;

/// <summary>
/// Tests for ML-DSA (Post-Quantum Cryptography) support in CertificateSigningServiceKey.
/// These tests require .NET 10+ and Windows platform for ML-DSA support.
/// </summary>
[TestFixture]
[Category("MLDSA")]
[Category("PostQuantum")]
public class CertificateSigningServiceKeyMlDsaTests
{
    private X509Certificate2? _mlDsaCert44;
    private X509Certificate2? _mlDsaCert65;
    private X509Certificate2? _mlDsaCert87;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        PlatformHelper.SkipIfMLDsaNotSupported("ML-DSA tests require Windows platform");

        _mlDsaCert44 = TestCertificateUtils.CreateMLDsaCertificate("MLDSA44ServiceKeyTest", mlDsaParameterSet: 44);
        _mlDsaCert65 = TestCertificateUtils.CreateMLDsaCertificate("MLDSA65ServiceKeyTest", mlDsaParameterSet: 65);
        _mlDsaCert87 = TestCertificateUtils.CreateMLDsaCertificate("MLDSA87ServiceKeyTest", mlDsaParameterSet: 87);
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _mlDsaCert44?.Dispose();
        _mlDsaCert65?.Dispose();
        _mlDsaCert87?.Dispose();
    }

    #region Metadata ML-DSA Tests

    [Test]
    public void Metadata_WithMLDsa44Certificate_ReturnsMLDsaKeyType()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_mlDsaCert44!);
        using var certificateSource = new DirectCertificateSource(_mlDsaCert44!, chainBuilder);
        using var signingKeyProvider = new DirectSigningKeyProvider(_mlDsaCert44!);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;

        using var key = new CertificateSigningServiceKey(certificateSource, signingKeyProvider, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.MLDSA));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-48)); // ML-DSA-44
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(44));
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA256));
    }

    [Test]
    public void Metadata_WithMLDsa65Certificate_ReturnsMLDsaKeyType()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_mlDsaCert65!);
        using var certificateSource = new DirectCertificateSource(_mlDsaCert65!, chainBuilder);
        using var signingKeyProvider = new DirectSigningKeyProvider(_mlDsaCert65!);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;

        using var key = new CertificateSigningServiceKey(certificateSource, signingKeyProvider, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.MLDSA));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-49)); // ML-DSA-65
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(65));
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA384));
    }

    [Test]
    public void Metadata_WithMLDsa87Certificate_ReturnsMLDsaKeyType()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_mlDsaCert87!);
        using var certificateSource = new DirectCertificateSource(_mlDsaCert87!, chainBuilder);
        using var signingKeyProvider = new DirectSigningKeyProvider(_mlDsaCert87!);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;

        using var key = new CertificateSigningServiceKey(certificateSource, signingKeyProvider, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.MLDSA));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-50)); // ML-DSA-87
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(87));
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA512));
    }

    [Test]
    public void Metadata_WithMLDsaCertificate_IncludesPublicKeyAlgorithmOid()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_mlDsaCert65!);
        using var certificateSource = new DirectCertificateSource(_mlDsaCert65!, chainBuilder);
        using var signingKeyProvider = new DirectSigningKeyProvider(_mlDsaCert65!);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;

        using var key = new CertificateSigningServiceKey(certificateSource, signingKeyProvider, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.AdditionalMetadata, Is.Not.Null);
        Assert.That(metadata.AdditionalMetadata, Contains.Key("PublicKeyAlgorithmOid"));
        var oid = metadata.AdditionalMetadata!["PublicKeyAlgorithmOid"] as string;
        Assert.That(oid, Does.StartWith("2.16.840.1.101.3.4.3.")); // ML-DSA OID prefix
    }

    #endregion

    #region GetCoseKey ML-DSA Tests

    [Test]
    public void GetCoseKey_WithMLDsa44Certificate_ReturnsCoseKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_mlDsaCert44!);
        using var certificateSource = new DirectCertificateSource(_mlDsaCert44!, chainBuilder);
        using var signingKeyProvider = new DirectSigningKeyProvider(_mlDsaCert44!);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;

        using var key = new CertificateSigningServiceKey(certificateSource, signingKeyProvider, signingService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_WithMLDsa65Certificate_ReturnsCoseKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_mlDsaCert65!);
        using var certificateSource = new DirectCertificateSource(_mlDsaCert65!, chainBuilder);
        using var signingKeyProvider = new DirectSigningKeyProvider(_mlDsaCert65!);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;

        using var key = new CertificateSigningServiceKey(certificateSource, signingKeyProvider, signingService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_WithMLDsa87Certificate_ReturnsCoseKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var chainBuilder = new ExplicitCertificateChainBuilder(_mlDsaCert87!);
        using var certificateSource = new DirectCertificateSource(_mlDsaCert87!, chainBuilder);
        using var signingKeyProvider = new DirectSigningKeyProvider(_mlDsaCert87!);
        var signingService = new Mock<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>().Object;

        using var key = new CertificateSigningServiceKey(certificateSource, signingKeyProvider, signingService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    #endregion
}
