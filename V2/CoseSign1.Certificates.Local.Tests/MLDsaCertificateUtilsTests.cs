// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local.Tests;

/// <summary>
/// Tests for <see cref="MLDsaCertificateUtils"/>.
/// </summary>
[TestFixture]
public class MLDsaCertificateUtilsTests
{
    [Test]
    public void MLDsa44Oid_HasExpectedValue()
    {
        Assert.That(MLDsaCertificateUtils.MLDsa44Oid, Is.EqualTo("2.16.840.1.101.3.4.3.17"));
    }

    [Test]
    public void MLDsa65Oid_HasExpectedValue()
    {
        Assert.That(MLDsaCertificateUtils.MLDsa65Oid, Is.EqualTo("2.16.840.1.101.3.4.3.18"));
    }

    [Test]
    public void MLDsa87Oid_HasExpectedValue()
    {
        Assert.That(MLDsaCertificateUtils.MLDsa87Oid, Is.EqualTo("2.16.840.1.101.3.4.3.19"));
    }

    [TestCase(44)]
    [TestCase(65)]
    [TestCase(87)]
    public void IsMLDsaCertificate_WithMLDsaCertificate_ReturnsTrue(int parameterSet)
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(parameterSet));

        // Act
        var result = MLDsaCertificateUtils.IsMLDsaCertificate(cert);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void IsMLDsaCertificate_WithRsaCertificate_ReturnsFalse()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.RSA));

        // Act
        var result = MLDsaCertificateUtils.IsMLDsaCertificate(cert);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsMLDsaCertificate_WithEcdsaCertificate_ReturnsFalse()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.ECDSA));

        // Act
        var result = MLDsaCertificateUtils.IsMLDsaCertificate(cert);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void IsMLDsaCertificate_WithNullCertificate_ReturnsFalse()
    {
        // Act
        var result = MLDsaCertificateUtils.IsMLDsaCertificate(null!);

        // Assert
        Assert.That(result, Is.False);
    }

    [TestCase(44)]
    [TestCase(65)]
    [TestCase(87)]
    public void GetParameterSet_WithMLDsaCertificate_ReturnsExpectedValue(int expectedParameterSet)
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(expectedParameterSet));

        // Act
        var result = MLDsaCertificateUtils.GetParameterSet(cert);

        // Assert
        Assert.That(result, Is.EqualTo(expectedParameterSet));
    }

    [Test]
    public void GetParameterSet_WithNonMLDsaCertificate_ReturnsNull()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.RSA));

        // Act
        var result = MLDsaCertificateUtils.GetParameterSet(cert);

        // Assert
        Assert.That(result, Is.Null);
    }

    [Test]
    public void GetParameterSet_WithNullCertificate_ReturnsNull()
    {
        // Act
        var result = MLDsaCertificateUtils.GetParameterSet(null!);

        // Assert
        Assert.That(result, Is.Null);
    }

    [TestCase(44, "2.16.840.1.101.3.4.3.17")]
    [TestCase(65, "2.16.840.1.101.3.4.3.18")]
    [TestCase(87, "2.16.840.1.101.3.4.3.19")]
    public void GetAlgorithmOid_WithValidParameterSet_ReturnsExpectedOid(int parameterSet, string expectedOid)
    {
        // Act
        var result = MLDsaCertificateUtils.GetAlgorithmOid(parameterSet);

        // Assert
        Assert.That(result, Is.EqualTo(expectedOid));
    }

    [Test]
    public void GetAlgorithmOid_WithInvalidParameterSet_ThrowsArgumentOutOfRangeException()
    {
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => MLDsaCertificateUtils.GetAlgorithmOid(100));
    }
}
