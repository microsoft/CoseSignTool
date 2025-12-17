// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using CoseSign1.Certificates.Local;

namespace CoseSign1.Certificates.AzureTrustedSigning.Tests;

/// <summary>
/// Tests for <see cref="AzureTrustedSigningService"/>.
/// </summary>
[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class AzureTrustedSigningServiceTests
{
    private Mock<AzSignContext> MockSignContext = null!;
    private X509Certificate2 TestCert = null!;

    [SetUp]
    public void Setup()
    {
        // Create a real test certificate for use in tests
        TestCert = TestCertificateUtils.CreateCertificate("AzureTrustedSigningServiceTest");

        // Create mock AzSignContext
        MockSignContext = new Mock<AzSignContext>();
    }

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

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
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        MockSignContext.Setup(s => s.GetSigningCertificate()).Returns(TestCert);

        // Act
        var service = new AzureTrustedSigningService(MockSignContext.Object);

        // Assert
        Assert.That(service, Is.Not.Null);
        Assert.That(service.IsRemote, Is.True);
    }

    [Test]
    public void Constructor_WithCustomMetadata_UsesProvidedMetadata()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        MockSignContext.Setup(s => s.GetSigningCertificate()).Returns(TestCert);
        var customMetadata = new CoseSign1.Abstractions.SigningServiceMetadata("CustomService", "Custom description");

        // Act
        var service = new AzureTrustedSigningService(MockSignContext.Object, serviceMetadata: customMetadata);

        // Assert
        Assert.That(service.ServiceMetadata.ServiceName, Is.EqualTo("CustomService"));
    }

    #endregion

    #region ServiceMetadata Tests

    [Test]
    public void ServiceMetadata_HasCorrectDefaultValues()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        MockSignContext.Setup(s => s.GetSigningCertificate()).Returns(TestCert);

        // Act
        var service = new AzureTrustedSigningService(MockSignContext.Object);

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
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        MockSignContext.Setup(s => s.GetSigningCertificate()).Returns(TestCert);

        // Act
        var service = new AzureTrustedSigningService(MockSignContext.Object);

        // Assert
        Assert.That(service.IsRemote, Is.True);
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_DoesNotThrow()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        MockSignContext.Setup(s => s.GetSigningCertificate()).Returns(TestCert);
        var service = new AzureTrustedSigningService(MockSignContext.Object);

        // Act & Assert
        Assert.DoesNotThrow(() => service.Dispose());
    }

    [Test]
    public void Dispose_CalledMultipleTimes_DoesNotThrow()
    {
        // Arrange
        var chain = new List<X509Certificate2> { TestCert };
        MockSignContext.Setup(s => s.GetCertChain()).Returns(chain);
        MockSignContext.Setup(s => s.GetSigningCertificate()).Returns(TestCert);
        var service = new AzureTrustedSigningService(MockSignContext.Object);

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
