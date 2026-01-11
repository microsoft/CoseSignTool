// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for SignatureValidationExtensions.
/// </summary>
[TestFixture]
[Category("Validation")]
public class SignatureValidationExtensionsTests
{
    #region ValidateCertificate Extension Method Tests

    [Test]
    public void ValidateCertificate_WithNullBuilder_ThrowsArgumentNullException()
    {
        // Arrange
        ICoseSign1ValidationBuilder? builder = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            builder!.ValidateCertificate(cert => cert.NotExpired()));
    }

    [Test]
    public void ValidateCertificate_WithNullConfigure_ThrowsArgumentNullException()
    {
        // Arrange
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        mockBuilder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>()))
            .Returns(mockBuilder.Object);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            mockBuilder.Object.ValidateCertificate(null!));
    }

    [Test]
    public void ValidateCertificate_WithValidConfiguration_AddsComponents()
    {
        // Arrange
        var addedComponents = new List<IValidationComponent>();
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        mockBuilder.Setup(b => b.LoggerFactory).Returns((ILoggerFactory?)null);
        mockBuilder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>()))
            .Callback<IValidationComponent>(c => addedComponents.Add(c))
            .Returns(mockBuilder.Object);

        // Act
        var result = mockBuilder.Object.ValidateCertificate(cert => cert.NotExpired());

        // Assert
        Assert.That(result, Is.SameAs(mockBuilder.Object));
        Assert.That(addedComponents, Has.Count.EqualTo(2));
        Assert.That(addedComponents[0], Is.InstanceOf<CertificateSigningKeyResolver>());
        Assert.That(addedComponents[1], Is.InstanceOf<CertificateExpirationAssertionProvider>());
    }

    [Test]
    public void ValidateCertificate_WithMultipleValidations_AddsMultipleComponents()
    {
        // Arrange
        var addedComponents = new List<IValidationComponent>();
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        mockBuilder.Setup(b => b.LoggerFactory).Returns((ILoggerFactory?)null);
        mockBuilder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>()))
            .Callback<IValidationComponent>(c => addedComponents.Add(c))
            .Returns(mockBuilder.Object);

        // Act
        var result = mockBuilder.Object.ValidateCertificate(cert => cert
            .NotExpired()
            .HasCommonName("TestCN")
            .IsIssuedBy("TestIssuer"));

        // Assert
        Assert.That(result, Is.SameAs(mockBuilder.Object));
        Assert.That(addedComponents, Has.Count.EqualTo(4));
        Assert.That(addedComponents[0], Is.InstanceOf<CertificateSigningKeyResolver>());
        Assert.That(addedComponents[1], Is.InstanceOf<CertificateExpirationAssertionProvider>());
        Assert.That(addedComponents[2], Is.InstanceOf<CertificateCommonNameAssertionProvider>());
        Assert.That(addedComponents[3], Is.InstanceOf<CertificateIssuerAssertionProvider>());
    }

    [Test]
    public void ValidateCertificate_WithChainValidation_AddsChainProvider()
    {
        // Arrange
        var addedComponents = new List<IValidationComponent>();
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        mockBuilder.Setup(b => b.LoggerFactory).Returns((ILoggerFactory?)null);
        mockBuilder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>()))
            .Callback<IValidationComponent>(c => addedComponents.Add(c))
            .Returns(mockBuilder.Object);

        // Act
        mockBuilder.Object.ValidateCertificate(cert => cert.ValidateChain());

        // Assert
        Assert.That(addedComponents, Has.Count.EqualTo(2));
        Assert.That(addedComponents[0], Is.InstanceOf<CertificateSigningKeyResolver>());
        Assert.That(addedComponents[1], Is.InstanceOf<CertificateChainAssertionProvider>());
    }

    [Test]
    public void ValidateCertificate_WithKeyUsageValidation_AddsKeyUsageProvider()
    {
        // Arrange
        var addedComponents = new List<IValidationComponent>();
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        mockBuilder.Setup(b => b.LoggerFactory).Returns((ILoggerFactory?)null);
        mockBuilder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>()))
            .Callback<IValidationComponent>(c => addedComponents.Add(c))
            .Returns(mockBuilder.Object);

        // Act
        mockBuilder.Object.ValidateCertificate(cert =>
            cert.HasKeyUsage(X509KeyUsageFlags.DigitalSignature));

        // Assert
        Assert.That(addedComponents, Has.Count.EqualTo(2));
        Assert.That(addedComponents[0], Is.InstanceOf<CertificateSigningKeyResolver>());
        Assert.That(addedComponents[1], Is.InstanceOf<CertificateKeyUsageAssertionProvider>());
    }

    [Test]
    public void ValidateCertificate_WithLoggerFactory_PassesLoggerToProviders()
    {
        // Arrange
        var addedComponents = new List<IValidationComponent>();
        var mockLoggerFactory = new Mock<ILoggerFactory>();
        mockLoggerFactory
            .Setup(f => f.CreateLogger(It.IsAny<string>()))
            .Returns(Mock.Of<ILogger>());
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        mockBuilder.Setup(b => b.LoggerFactory).Returns(mockLoggerFactory.Object);
        mockBuilder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>()))
            .Callback<IValidationComponent>(c => addedComponents.Add(c))
            .Returns(mockBuilder.Object);

        // Act
        mockBuilder.Object.ValidateCertificate(cert => cert.NotExpired());

        // Assert - just verify it doesn't throw and components are added
        Assert.That(addedComponents, Has.Count.EqualTo(2));
    }

    #endregion
}
