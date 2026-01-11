// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.Validation;
using CoseSign1.Validation.Abstractions;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for CertificateDefaultComponentProvider.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CertificateDefaultComponentProviderTests
{
    [Test]
    public void Priority_Returns100()
    {
        // Arrange
        var provider = new CertificateDefaultComponentProvider();

        // Assert
        Assert.That(provider.Priority, Is.EqualTo(100));
    }

    [Test]
    public void GetDefaultComponents_WithNullLoggerFactory_ReturnsTwoComponents()
    {
        // Arrange
        var provider = new CertificateDefaultComponentProvider();

        // Act
        var components = provider.GetDefaultComponents(null).ToList();

        // Assert
        Assert.That(components, Has.Count.EqualTo(2));
    }

    [Test]
    public void GetDefaultComponents_ReturnsCertificateSigningKeyResolver()
    {
        // Arrange
        var provider = new CertificateDefaultComponentProvider();

        // Act
        var components = provider.GetDefaultComponents(null).ToList();

        // Assert
        Assert.That(components[0], Is.InstanceOf<CertificateSigningKeyResolver>());
        Assert.That(components[0], Is.InstanceOf<ISigningKeyResolver>());
    }

    [Test]
    public void GetDefaultComponents_ReturnsCertificateChainAssertionProvider()
    {
        // Arrange
        var provider = new CertificateDefaultComponentProvider();

        // Act
        var components = provider.GetDefaultComponents(null).ToList();

        // Assert
        Assert.That(components[1], Is.InstanceOf<CertificateChainAssertionProvider>());
        Assert.That(components[1], Is.InstanceOf<ISigningKeyAssertionProvider>());
    }

    [Test]
    public void GetDefaultComponents_WithLoggerFactory_PassesLogger()
    {
        // Arrange
        var provider = new CertificateDefaultComponentProvider();
        var mockLoggerFactory = new Mock<ILoggerFactory>();
        var mockLogger = new Mock<ILogger>();
        mockLoggerFactory
            .Setup(f => f.CreateLogger(It.IsAny<string>()))
            .Returns(mockLogger.Object);

        // Act
        var components = provider.GetDefaultComponents(mockLoggerFactory.Object).ToList();

        // Assert
        Assert.That(components, Has.Count.EqualTo(2));
        // Verify logger factory was used
        mockLoggerFactory.Verify(f => f.CreateLogger(It.IsAny<string>()), Times.Exactly(2));
    }

    [Test]
    public void Provider_ImplementsIDefaultValidationComponentProvider()
    {
        // Arrange
        var provider = new CertificateDefaultComponentProvider();

        // Assert
        Assert.That(provider, Is.InstanceOf<IDefaultValidationComponentProvider>());
    }
}
