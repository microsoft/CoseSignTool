// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.AzureTrustedSigning.Tests;

using Azure.Developer.TrustedSigning.CryptoProvider;

/// <summary>
/// Tests for <see cref="AzureTrustedSigningService"/>.
/// </summary>
[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class AzureTrustedSigningServiceTests
{
    /// <summary>
    /// Creates a test certificate for use in tests.
    /// </summary>
    private static X509Certificate2 CreateTestCert(string name = "AzureTrustedSigningServiceTest")
        => TestCertificateUtils.CreateCertificate(name);

    /// <summary>
    /// Creates a mock AzSignContext for use in tests.
    /// </summary>
    private static Mock<AzSignContext> CreateMockSignContext()
        => new Mock<AzSignContext>();

    #region Constructor Tests

    [Test]
    public void Constructor_WithNullSignContext_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new AzureTrustedSigningService(null!));

        Assert.That(ex.ParamName, Is.EqualTo("signContext"));
    }

    [Test]
    public void Constructor_WithValidContext_CreatesService()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        mockSignContext.Setup(s => s.GetSigningCertificate()).Returns(testCert);

        // Act
        var service = new AzureTrustedSigningService(mockSignContext.Object);

        // Assert
        Assert.That(service, Is.Not.Null);
        Assert.That(service.IsRemote, Is.True);
    }

    [Test]
    public void Constructor_WithCustomMetadata_UsesProvidedMetadata()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        mockSignContext.Setup(s => s.GetSigningCertificate()).Returns(testCert);
        var customMetadata = new CoseSign1.Abstractions.SigningServiceMetadata("CustomService", "Custom description");

        // Act
        var service = new AzureTrustedSigningService(mockSignContext.Object, serviceMetadata: customMetadata);

        // Assert
        Assert.That(service.ServiceMetadata.ServiceName, Is.EqualTo("CustomService"));
    }

    #endregion

    #region ServiceMetadata Tests

    [Test]
    public void ServiceMetadata_HasCorrectDefaultValues()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        mockSignContext.Setup(s => s.GetSigningCertificate()).Returns(testCert);

        // Act
        var service = new AzureTrustedSigningService(mockSignContext.Object);

        // Assert
        Assert.That(service.ServiceMetadata.ServiceName, Is.EqualTo("AzureTrustedSigning"));
        Assert.That(service.ServiceMetadata.Description, Does.Contain("FIPS 140-2"));
    }

    #endregion

    #region IsRemote Tests

    [Test]
    public void IsRemote_ReturnsTrue()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        mockSignContext.Setup(s => s.GetSigningCertificate()).Returns(testCert);

        // Act
        var service = new AzureTrustedSigningService(mockSignContext.Object);

        // Assert
        Assert.That(service.IsRemote, Is.True);
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_DoesNotThrow()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        mockSignContext.Setup(s => s.GetSigningCertificate()).Returns(testCert);
        var service = new AzureTrustedSigningService(mockSignContext.Object);

        // Act & Assert
        Assert.DoesNotThrow(() => service.Dispose());
    }

    [Test]
    public void Dispose_CalledMultipleTimes_DoesNotThrow()
    {
        // Arrange
        using var testCert = CreateTestCert();
        var mockSignContext = CreateMockSignContext();
        var chain = new List<X509Certificate2> { testCert };
        mockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        mockSignContext.Setup(s => s.GetSigningCertificate()).Returns(testCert);
        var service = new AzureTrustedSigningService(mockSignContext.Object);

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            service.Dispose();
            service.Dispose();
            service.Dispose();
        });
    }

    #endregion
}
