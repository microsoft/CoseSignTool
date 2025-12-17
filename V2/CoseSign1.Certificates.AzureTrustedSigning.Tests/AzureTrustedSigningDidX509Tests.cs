// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;

namespace CoseSign1.Certificates.AzureTrustedSigning.Tests;

/// <summary>
/// Tests for <see cref="AzureTrustedSigningDidX509"/>.
/// </summary>
[TestFixture]
public class AzureTrustedSigningDidX509Tests
{
    private X509Certificate2 TestCert = null!;
    private X509Certificate2 TestCert2 = null!;

    [SetUp]
    public void Setup()
    {
        // Create test certificates
        TestCert = TestCertificateUtils.CreateCertificate("AzureTrustedSigningDidX509Test");
        TestCert2 = TestCertificateUtils.CreateCertificate("CaCert");
    }

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
        TestCert2?.Dispose();
    }

    #region Generate Tests

    [Test]
    public void Generate_WithNullChain_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureTrustedSigningDidX509.Generate(null!));

        Assert.That(ex.ParamName, Is.EqualTo("certificateChain"));
    }

    [Test]
    public void Generate_WithEmptyChain_ThrowsArgumentException()
    {
        // Arrange
        var emptyChain = Array.Empty<X509Certificate2>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            AzureTrustedSigningDidX509.Generate(emptyChain));

        Assert.That(ex.ParamName, Is.EqualTo("certificateChain"));
    }

    [Test]
    public void Generate_WithCertWithoutMicrosoftEku_ThrowsInvalidOperationException()
    {
        // Arrange - test certs don't have Microsoft EKUs
        var chain = new[] { TestCert };

        // Act & Assert - the builder requires at least one policy when no EKU is present
        Assert.Throws<InvalidOperationException>(() =>
            AzureTrustedSigningDidX509.Generate(chain));
    }

    [Test]
    public void Generate_WithMultipleCertsWithoutEku_ThrowsInvalidOperationException()
    {
        // Arrange
        var chain = new[] { TestCert, TestCert2 };

        // Act & Assert - builder requires a policy
        Assert.Throws<InvalidOperationException>(() =>
            AzureTrustedSigningDidX509.Generate(chain));
    }

    #endregion

    #region GenerateWithEku Tests

    [Test]
    public void GenerateWithEku_WithNullLeafCertificate_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureTrustedSigningDidX509.GenerateWithEku(null!, TestCert2));

        Assert.That(ex.ParamName, Is.EqualTo("leafCertificate"));
    }

    [Test]
    public void GenerateWithEku_WithNullCaCertificate_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            AzureTrustedSigningDidX509.GenerateWithEku(TestCert, null!));

        Assert.That(ex.ParamName, Is.EqualTo("caCertificate"));
    }

    [Test]
    public void GenerateWithEku_WithCertWithoutMicrosoftEku_ThrowsInvalidOperationException()
    {
        // Arrange - Test certs won't have Microsoft EKUs

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            AzureTrustedSigningDidX509.GenerateWithEku(TestCert, TestCert2));

        Assert.That(ex.Message, Does.Contain("No Microsoft EKU found"));
    }

    #endregion

    #region Success Path Tests with Microsoft EKUs

    /// <summary>
    /// Microsoft Code Signing EKU: 1.3.6.1.4.1.311.10.3.13
    /// </summary>
    private const string MicrosoftCodeSigningEku = "1.3.6.1.4.1.311.10.3.13";

    /// <summary>
    /// Microsoft Azure Code Signing EKU: 1.3.6.1.4.1.311.97.1.4.1
    /// </summary>
    private const string MicrosoftAzureCodeSigningEku = "1.3.6.1.4.1.311.97.1.4.1";

    [Test]
    public void Generate_WithMicrosoftEku_ReturnsValidDidX509()
    {
        // Arrange
        using var certWithEku = TestCertificateUtils.CreateCertificate(
            "LeafWithMicrosoftEku",
            customEkus: new[] { MicrosoftCodeSigningEku });
        var chain = new[] { certWithEku };

        // Act
        var result = AzureTrustedSigningDidX509.Generate(chain);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(result, Does.Contain("::eku:"));
        Assert.That(result, Does.Contain(MicrosoftCodeSigningEku));
    }

    [Test]
    public void Generate_WithMultipleMicrosoftEkus_SelectsDeepestGreatest()
    {
        // Arrange - create certificate with multiple Microsoft EKUs
        // The deepest greatest should be selected (1.3.6.1.4.1.311.97.1.4.1 is deeper than 1.3.6.1.4.1.311.10.3.13)
        using var certWithMultipleEkus = TestCertificateUtils.CreateCertificate(
            "LeafWithMultipleEkus",
            customEkus: new[] { MicrosoftCodeSigningEku, MicrosoftAzureCodeSigningEku });
        var chain = new[] { certWithMultipleEkus };

        // Act
        var result = AzureTrustedSigningDidX509.Generate(chain);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(result, Does.Contain("::eku:"));
        // Should contain the deeper EKU (1.3.6.1.4.1.311.97.1.4.1 has more segments)
        Assert.That(result, Does.Contain(MicrosoftAzureCodeSigningEku));
    }

    [Test]
    public void Generate_WithChainContainingMicrosoftEku_ReturnsValidDidX509()
    {
        // Arrange
        using var rootCert = TestCertificateUtils.CreateCertificate("Root");
        using var leafCert = TestCertificateUtils.CreateCertificate(
            "LeafWithEku",
            issuingCa: rootCert,
            customEkus: new[] { MicrosoftCodeSigningEku });
        var chain = new[] { leafCert, rootCert };

        // Act
        var result = AzureTrustedSigningDidX509.Generate(chain);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(result, Does.Contain("::eku:"));
    }

    [Test]
    public void GenerateWithEku_WithMicrosoftEku_ReturnsValidDidX509()
    {
        // Arrange
        using var rootCert = TestCertificateUtils.CreateCertificate("CaCert");
        using var leafCert = TestCertificateUtils.CreateCertificate(
            "LeafWithMicrosoftEku",
            issuingCa: rootCert,
            customEkus: new[] { MicrosoftCodeSigningEku });

        // Act
        var result = AzureTrustedSigningDidX509.GenerateWithEku(leafCert, rootCert);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(result, Does.Contain("::eku:"));
        Assert.That(result, Does.Contain(MicrosoftCodeSigningEku));
    }

    [Test]
    public void Generate_WithSelfSignedMicrosoftEkuCert_ReturnsValidDidX509()
    {
        // Arrange - self-signed certificate with Microsoft EKU
        using var selfSignedCert = TestCertificateUtils.CreateCertificate(
            "SelfSignedWithMicrosoftEku",
            customEkus: new[] { MicrosoftCodeSigningEku });
        var chain = new[] { selfSignedCert };

        // Act
        var result = AzureTrustedSigningDidX509.Generate(chain);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Does.StartWith("did:x509:0:sha256:"));
        // Should contain EKU policy
        Assert.That(result, Does.Contain("eku"));
    }

    [Test]
    public void Generate_WithEnumerableChain_WorksCorrectly()
    {
        // Arrange - use IEnumerable instead of array
        using var certWithEku = TestCertificateUtils.CreateCertificate(
            "EnumerableTest",
            customEkus: new[] { MicrosoftCodeSigningEku });

        IEnumerable<X509Certificate2> GetCerts()
        {
            yield return certWithEku;
        }

        // Act
        var result = AzureTrustedSigningDidX509.Generate(GetCerts());

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result, Does.StartWith("did:x509:0:sha256:"));
    }

    #endregion
}
