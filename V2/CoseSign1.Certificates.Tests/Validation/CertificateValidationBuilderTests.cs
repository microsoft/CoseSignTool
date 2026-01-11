// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Validation;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for CertificateValidationBuilder.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CertificateValidationBuilderTests
{
    #region Constructor Tests

    [Test]
    public void Constructor_Default_CreatesEmptyBuilder()
    {
        // Arrange & Act
        var builder = new CertificateValidationBuilder();
        var result = builder.Build();

        // Assert
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void Constructor_WithLoggerFactory_CreatesBuilder()
    {
        // Arrange
        var mockLoggerFactory = new Mock<ILoggerFactory>().Object;

        // Act
        var builder = new CertificateValidationBuilder(mockLoggerFactory);
        var result = builder.Build();

        // Assert
        Assert.That(result, Is.Empty);
    }

    #endregion

    #region WithLoggerFactory Tests

    [Test]
    public void WithLoggerFactory_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();
        var mockLoggerFactory = new Mock<ILoggerFactory>().Object;

        // Act
        var result = builder.WithLoggerFactory(mockLoggerFactory);

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void WithLoggerFactory_WithNull_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        var result = builder.WithLoggerFactory(null);

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    #endregion

    #region HasCommonName Tests

    [Test]
    public void HasCommonName_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        builder.HasCommonName("CN=Test");
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificateCommonNameAssertionProvider>());
    }

    [Test]
    public void HasCommonName_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        var result = builder.HasCommonName("CN=Test");

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    #endregion

    #region IsIssuedBy Tests

    [Test]
    public void IsIssuedBy_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        builder.IsIssuedBy("CN=Issuer");
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificateIssuerAssertionProvider>());
    }

    [Test]
    public void IsIssuedBy_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        var result = builder.IsIssuedBy("CN=Issuer");

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    #endregion

    #region NotExpired Tests

    [Test]
    public void NotExpired_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        builder.NotExpired();
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificateExpirationAssertionProvider>());
    }

    [Test]
    public void NotExpired_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        var result = builder.NotExpired();

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void NotExpired_WithAsOf_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();
        var asOf = DateTime.UtcNow.AddDays(-7);

        // Act
        builder.NotExpired(asOf);
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificateExpirationAssertionProvider>());
    }

    [Test]
    public void NotExpired_WithAsOf_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        var result = builder.NotExpired(DateTime.UtcNow);

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    #endregion

    #region HasEnhancedKeyUsage Tests

    [Test]
    public void HasEnhancedKeyUsage_WithOid_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();
        var eku = new Oid("1.3.6.1.5.5.7.3.3", "Code Signing"); // Code Signing EKU

        // Act
        builder.HasEnhancedKeyUsage(eku);
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificateKeyUsageAssertionProvider>());
    }

    [Test]
    public void HasEnhancedKeyUsage_WithOid_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();
        var eku = new Oid("1.3.6.1.5.5.7.3.3");

        // Act
        var result = builder.HasEnhancedKeyUsage(eku);

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void HasEnhancedKeyUsage_WithOidString_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        builder.HasEnhancedKeyUsage("1.3.6.1.5.5.7.3.3");
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificateKeyUsageAssertionProvider>());
    }

    [Test]
    public void HasEnhancedKeyUsage_WithOidString_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        var result = builder.HasEnhancedKeyUsage("1.3.6.1.5.5.7.3.3");

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    #endregion

    #region HasKeyUsage Tests

    [Test]
    public void HasKeyUsage_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        builder.HasKeyUsage(X509KeyUsageFlags.DigitalSignature);
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificateKeyUsageAssertionProvider>());
    }

    [Test]
    public void HasKeyUsage_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        var result = builder.HasKeyUsage(X509KeyUsageFlags.DigitalSignature);

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    #endregion

    #region Matches Tests

    [Test]
    public void Matches_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();
        Func<X509Certificate2, bool> predicate = cert => cert.Subject.Contains("Test");

        // Act
        builder.Matches(predicate);
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificatePredicateAssertionProvider>());
    }

    [Test]
    public void Matches_WithFailureMessage_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();
        Func<X509Certificate2, bool> predicate = cert => cert.Subject.Contains("Test");

        // Act
        builder.Matches(predicate, "Custom failure message");
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificatePredicateAssertionProvider>());
    }

    [Test]
    public void Matches_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();
        Func<X509Certificate2, bool> predicate = cert => true;

        // Act
        var result = builder.Matches(predicate);

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void Matches_WithNullPredicate_ThrowsArgumentNullException()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => builder.Matches(null!));
    }

    #endregion

    #region WithCertificateHeaderLocation Tests

    [Test]
    public void WithCertificateHeaderLocation_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act - this is a no-op but should return the builder
        var result = builder.WithCertificateHeaderLocation(CoseHeaderLocation.Protected);

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void WithCertificateHeaderLocation_DoesNotAddProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        builder.WithCertificateHeaderLocation(CoseHeaderLocation.Protected);
        var providers = builder.Build();

        // Assert - no provider should be added, it's a no-op
        Assert.That(providers, Is.Empty);
    }

    #endregion

    #region ValidateChain Tests

    [Test]
    public void ValidateChain_Default_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        builder.ValidateChain();
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificateChainAssertionProvider>());
    }

    [Test]
    public void ValidateChain_WithAllowUntrusted_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        builder.ValidateChain(allowUntrusted: true);
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificateChainAssertionProvider>());
    }

    [Test]
    public void ValidateChain_WithRevocationMode_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        builder.ValidateChain(allowUntrusted: false, revocationMode: X509RevocationMode.Offline);
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificateChainAssertionProvider>());
    }

    [Test]
    public void ValidateChain_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        var result = builder.ValidateChain();

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateChain_WithCustomRoots_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();
        var customRoots = new X509Certificate2Collection();

        // Act
        builder.ValidateChain(customRoots);
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificateChainAssertionProvider>());
    }

    [Test]
    public void ValidateChain_WithCustomRoots_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();
        var customRoots = new X509Certificate2Collection();

        // Act
        var result = builder.ValidateChain(customRoots);

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateChain_WithNullCustomRoots_ThrowsArgumentNullException()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => builder.ValidateChain((X509Certificate2Collection)null!));
    }

    [Test]
    public void ValidateChain_WithChainBuilder_AddsProvider()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();
        var mockChainBuilder = new Mock<ICertificateChainBuilder>().Object;

        // Act
        builder.ValidateChain(mockChainBuilder);
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        Assert.That(providers[0], Is.InstanceOf<CertificateChainAssertionProvider>());
    }

    [Test]
    public void ValidateChain_WithChainBuilder_ReturnsBuilder()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();
        var mockChainBuilder = new Mock<ICertificateChainBuilder>().Object;

        // Act
        var result = builder.ValidateChain(mockChainBuilder);

        // Assert
        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateChain_WithNullChainBuilder_ThrowsArgumentNullException()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => builder.ValidateChain((ICertificateChainBuilder)null!));
    }

    #endregion

    #region Build Tests

    [Test]
    public void Build_WithMultipleProviders_ReturnsAll()
    {
        // Arrange
        var builder = new CertificateValidationBuilder();

        // Act
        builder
            .HasCommonName("CN=Test")
            .IsIssuedBy("CN=Issuer")
            .NotExpired()
            .ValidateChain();
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(4));
        Assert.That(providers[0], Is.InstanceOf<CertificateCommonNameAssertionProvider>());
        Assert.That(providers[1], Is.InstanceOf<CertificateIssuerAssertionProvider>());
        Assert.That(providers[2], Is.InstanceOf<CertificateExpirationAssertionProvider>());
        Assert.That(providers[3], Is.InstanceOf<CertificateChainAssertionProvider>());
    }

    [Test]
    public void Build_CanBeCalledMultipleTimes()
    {
        // Arrange
        var builder = new CertificateValidationBuilder()
            .HasCommonName("CN=Test");

        // Act
        var result1 = builder.Build();
        var result2 = builder.Build();

        // Assert
        Assert.That(result1, Has.Count.EqualTo(1));
        Assert.That(result2, Has.Count.EqualTo(1));
        // Each Build() creates a new list
        Assert.That(result1, Is.Not.SameAs(result2));
    }

    [Test]
    public void Build_WithLoggerFactory_PassesLoggerToProviders()
    {
        // Arrange
        var mockLoggerFactory = new Mock<ILoggerFactory>();
        var mockLogger = new Mock<ILogger<CertificateCommonNameAssertionProvider>>();
        mockLoggerFactory
            .Setup(f => f.CreateLogger(It.IsAny<string>()))
            .Returns(mockLogger.Object);

        var builder = new CertificateValidationBuilder(mockLoggerFactory.Object)
            .HasCommonName("CN=Test");

        // Act
        var providers = builder.Build();

        // Assert
        Assert.That(providers, Has.Count.EqualTo(1));
        // Logger factory was invoked
        mockLoggerFactory.Verify(f => f.CreateLogger(It.IsAny<string>()), Times.Once);
    }

    #endregion
}
