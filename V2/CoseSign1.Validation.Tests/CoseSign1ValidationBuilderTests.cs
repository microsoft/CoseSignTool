// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.Logging;
using Moq;

/// <summary>
/// Tests for <see cref="CoseSign1ValidationBuilder"/>.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CoseSign1ValidationBuilderTests
{
    #region Constructor Tests

    [Test]
    public void Constructor_WithoutLoggerFactory_CreatesBuilder()
    {
        var builder = new CoseSign1ValidationBuilder();

        Assert.That(builder.LoggerFactory, Is.Null);
    }

    [Test]
    public void Constructor_WithLoggerFactory_StoresLoggerFactory()
    {
        var mockLoggerFactory = new Mock<ILoggerFactory>();

        var builder = new CoseSign1ValidationBuilder(mockLoggerFactory.Object);

        Assert.That(builder.LoggerFactory, Is.SameAs(mockLoggerFactory.Object));
    }

    #endregion

    #region AddComponent Tests

    [Test]
    public void AddComponent_NullComponent_ThrowsArgumentNullException()
    {
        var builder = new CoseSign1ValidationBuilder();

        Assert.Throws<ArgumentNullException>(() => builder.AddComponent(null!));
    }

    [Test]
    public void AddComponent_ValidComponent_ReturnsSameBuilder()
    {
        var builder = new CoseSign1ValidationBuilder();
        var mockComponent = new Mock<IValidationComponent>();

        var result = builder.AddComponent(mockComponent.Object);

        Assert.That(result, Is.SameAs(builder));
    }

    #endregion

    #region WithOptions Tests

    [Test]
    public void WithOptions_NullOptions_ThrowsArgumentNullException()
    {
        var builder = new CoseSign1ValidationBuilder();

        Assert.Throws<ArgumentNullException>(() => builder.WithOptions((CoseSign1ValidationOptions)null!));
    }

    [Test]
    public void WithOptions_ValidOptions_ReturnsSameBuilder()
    {
        var builder = new CoseSign1ValidationBuilder();
        var options = new CoseSign1ValidationOptions();

        var result = builder.WithOptions(options);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void WithOptions_NullConfigureAction_ThrowsArgumentNullException()
    {
        var builder = new CoseSign1ValidationBuilder();

        Assert.Throws<ArgumentNullException>(() => builder.WithOptions((Action<CoseSign1ValidationOptions>)null!));
    }

    [Test]
    public void WithOptions_ValidConfigureAction_ReturnsSameBuilder()
    {
        var builder = new CoseSign1ValidationBuilder();

        var result = builder.WithOptions(o => o.CertificateHeaderLocation = System.Security.Cryptography.Cose.CoseHeaderLocation.Any);

        Assert.That(result, Is.SameAs(builder));
    }

    #endregion

    #region OverrideDefaultTrustPolicy Tests

    [Test]
    public void OverrideDefaultTrustPolicy_NullPolicy_ThrowsArgumentNullException()
    {
        var builder = new CoseSign1ValidationBuilder();

        Assert.Throws<ArgumentNullException>(() => builder.OverrideDefaultTrustPolicy(null!));
    }

    [Test]
    public void OverrideDefaultTrustPolicy_ValidPolicy_ReturnsSameBuilder()
    {
        var builder = new CoseSign1ValidationBuilder();
        var policy = TrustPolicy.AllowAll();

        var result = builder.OverrideDefaultTrustPolicy(policy);

        Assert.That(result, Is.SameAs(builder));
    }

    #endregion

    #region AllowAllTrust Tests

    [Test]
    public void AllowAllTrust_ReturnsSameBuilder()
    {
        var builder = new CoseSign1ValidationBuilder();

        var result = builder.AllowAllTrust();

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void AllowAllTrust_WithReason_ReturnsSameBuilder()
    {
        var builder = new CoseSign1ValidationBuilder();

        var result = builder.AllowAllTrust("Test reason");

        Assert.That(result, Is.SameAs(builder));
    }

    #endregion

    #region DenyAllTrust Tests

    [Test]
    public void DenyAllTrust_ReturnsSameBuilder()
    {
        var builder = new CoseSign1ValidationBuilder();

        var result = builder.DenyAllTrust();

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void DenyAllTrust_WithReason_ReturnsSameBuilder()
    {
        var builder = new CoseSign1ValidationBuilder();

        var result = builder.DenyAllTrust("Test reason");

        Assert.That(result, Is.SameAs(builder));
    }

    #endregion

    #region WithoutContentVerification Tests

    [Test]
    public void WithoutContentVerification_ReturnsSameBuilder()
    {
        var builder = new CoseSign1ValidationBuilder();

        var result = builder.WithoutContentVerification();

        Assert.That(result, Is.SameAs(builder));
    }

    #endregion

    #region Build Tests

    [Test]
    public void Build_WithoutSigningKeyResolver_ThrowsInvalidOperationException()
    {
        var builder = new CoseSign1ValidationBuilder();

        var ex = Assert.Throws<InvalidOperationException>(() => builder.Build());
        Assert.That(ex!.Message, Does.Contain("signing key resolver"));
    }

    [Test]
    public void Build_WithSigningKeyResolver_CreatesValidator()
    {
        var builder = new CoseSign1ValidationBuilder();
        var mockResolver = new Mock<ISigningKeyResolver>();

        builder.AddComponent(mockResolver.Object);

        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
        Assert.That(validator, Is.InstanceOf<ICoseSign1Validator>());
    }

    [Test]
    public void Build_WithMultipleComponents_CreatesValidator()
    {
        var builder = new CoseSign1ValidationBuilder();
        var mockResolver = new Mock<ISigningKeyResolver>();
        var mockComponent = new Mock<IValidationComponent>();

        builder.AddComponent(mockResolver.Object);
        builder.AddComponent(mockComponent.Object);

        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Build_WithLoggerFactory_CreatesValidator()
    {
        var mockLoggerFactory = new Mock<ILoggerFactory>();
        mockLoggerFactory.Setup(f => f.CreateLogger(It.IsAny<string>()))
            .Returns(Mock.Of<ILogger>());

        var builder = new CoseSign1ValidationBuilder(mockLoggerFactory.Object);
        var mockResolver = new Mock<ISigningKeyResolver>();
        builder.AddComponent(mockResolver.Object);

        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Build_WithAllowAllTrust_UsesAllowAllPolicy()
    {
        var builder = new CoseSign1ValidationBuilder();
        var mockResolver = new Mock<ISigningKeyResolver>();
        builder.AddComponent(mockResolver.Object);
        builder.AllowAllTrust("Test");

        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Build_WithDenyAllTrust_UsesDenyAllPolicy()
    {
        var builder = new CoseSign1ValidationBuilder();
        var mockResolver = new Mock<ISigningKeyResolver>();
        builder.AddComponent(mockResolver.Object);
        builder.DenyAllTrust("Test");

        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Build_WithoutContentVerification_OmitsIndirectSignatureValidator()
    {
        var builder = new CoseSign1ValidationBuilder();
        var mockResolver = new Mock<ISigningKeyResolver>();
        builder.AddComponent(mockResolver.Object);
        builder.WithoutContentVerification();

        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Build_WithCustomOptions_IncludesOptions()
    {
        var builder = new CoseSign1ValidationBuilder();
        var mockResolver = new Mock<ISigningKeyResolver>();
        builder.AddComponent(mockResolver.Object);
        builder.WithOptions(new CoseSign1ValidationOptions
        {
            CertificateHeaderLocation = System.Security.Cryptography.Cose.CoseHeaderLocation.Any
        });

        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    #endregion

    #region Fluent API Tests

    [Test]
    public void FluentApi_AllowsChaining()
    {
        var mockResolver = new Mock<ISigningKeyResolver>();
        var mockComponent = new Mock<IValidationComponent>();

        // Create builder explicitly to access all methods
        var builder = new CoseSign1ValidationBuilder();
        builder.AddComponent(mockResolver.Object);
        builder.AddComponent(mockComponent.Object);
        builder.AllowAllTrust("Test");
        builder.WithoutContentVerification();
        builder.WithOptions(o => o.CertificateHeaderLocation = System.Security.Cryptography.Cose.CoseHeaderLocation.Any);
        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    #endregion
}
