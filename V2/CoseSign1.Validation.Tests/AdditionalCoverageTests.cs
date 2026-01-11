// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Abstractions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using Microsoft.Extensions.Logging;
using Moq;

/// <summary>
/// Tests for <see cref="DefaultValidationComponentProviderAttribute"/>.
/// </summary>
[TestFixture]
[Category("Validation")]
public class DefaultValidationComponentProviderAttributeTests
{
    #region Test Provider Classes

    /// <summary>
    /// A valid provider implementation for testing.
    /// </summary>
    private class ValidProvider : IDefaultValidationComponentProvider
    {
        public int Priority => 100;

        public IEnumerable<IValidationComponent> GetDefaultComponents(ILoggerFactory? loggerFactory = null) =>
            Enumerable.Empty<IValidationComponent>();
    }

    /// <summary>
    /// An invalid class that does not implement the interface.
    /// </summary>
    private class InvalidProvider
    {
    }

    #endregion

    #region Constructor Tests

    [Test]
    public void Constructor_NullType_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new DefaultValidationComponentProviderAttribute(null!));
    }

    [Test]
    public void Constructor_TypeNotImplementingInterface_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new DefaultValidationComponentProviderAttribute(typeof(InvalidProvider)));

        Assert.Multiple(() =>
        {
            Assert.That(ex!.Message, Does.Contain("must implement"));
            Assert.That(ex.ParamName, Is.EqualTo("providerType"));
        });
    }

    [Test]
    public void Constructor_ValidType_CreatesAttribute()
    {
        var attribute = new DefaultValidationComponentProviderAttribute(typeof(ValidProvider));

        Assert.That(attribute.ProviderType, Is.EqualTo(typeof(ValidProvider)));
    }

    [Test]
    public void Attribute_AllowsMultiple()
    {
        var usageAttribute = typeof(DefaultValidationComponentProviderAttribute)
            .GetCustomAttributes(typeof(AttributeUsageAttribute), false)
            .Cast<AttributeUsageAttribute>()
            .FirstOrDefault();

        Assert.Multiple(() =>
        {
            Assert.That(usageAttribute, Is.Not.Null);
            Assert.That(usageAttribute!.AllowMultiple, Is.True);
            Assert.That(usageAttribute.ValidOn, Is.EqualTo(AttributeTargets.Assembly));
        });
    }

    #endregion
}

/// <summary>
/// Tests for <see cref="CoseSign1MessageValidationExtensions"/>.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CoseSign1MessageValidationExtensionsTests
{
    #region Validate with Validator Tests

    [Test]
    public void Validate_NullMessage_ThrowsArgumentNullException()
    {
        var mockValidator = new Mock<ICoseSign1Validator>();

        Assert.Throws<ArgumentNullException>(() =>
            CoseSign1MessageValidationExtensions.Validate(null!, mockValidator.Object));
    }

    [Test]
    public void Validate_NullValidator_ThrowsArgumentNullException()
    {
        var message = CreateSignedMessage();

        Assert.Throws<ArgumentNullException>(() => message.Validate((ICoseSign1Validator)null!));
    }

    [Test]
    public void Validate_ValidParameters_DelegatestoValidator()
    {
        var message = CreateSignedMessage();
        var expectedResult = CreateMockValidationResult();
        var mockValidator = new Mock<ICoseSign1Validator>();
        mockValidator.Setup(v => v.Validate(message)).Returns(expectedResult);

        var result = message.Validate(mockValidator.Object);

        Assert.That(result, Is.SameAs(expectedResult));
        mockValidator.Verify(v => v.Validate(message), Times.Once);
    }

    #endregion

    #region Validate with Configure Action Tests

    [Test]
    public void Validate_NullMessageWithConfigure_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            CoseSign1MessageValidationExtensions.Validate(null!, _ => { }));
    }

    [Test]
    public void Validate_NullConfigure_UsesAutoDiscovery()
    {
        var message = CreateSignedMessage();

        var result = message.Validate((Action<ICoseSign1ValidationBuilder>?)null);

        Assert.That(result.Overall, Is.Not.Null);
    }

    [Test]
    public void Validate_WithConfigure_BuildsAndValidates()
    {
        using var key = ECDsa.Create();
        var message = CreateSignedMessage(key);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var result = message.Validate(builder =>
        {
            var mockResolver = new Mock<ISigningKeyResolver>();
            mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
                .Returns(true);
            mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
            mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
                .Returns(SigningKeyResolutionResult.Success(mockSigningKey.Object));
            builder.AddComponent(mockResolver.Object);
        });

        Assert.That(result.Overall, Is.Not.Null);
    }

    #endregion

    #region ValidateAsync with Validator Tests

    [Test]
    public async Task ValidateAsync_NullMessage_ThrowsArgumentNullException()
    {
        var mockValidator = new Mock<ICoseSign1Validator>();

        await Task.Run(() => Assert.ThrowsAsync<ArgumentNullException>(() =>
            CoseSign1MessageValidationExtensions.ValidateAsync(null!, mockValidator.Object)));
    }

    [Test]
    public async Task ValidateAsync_NullValidator_ThrowsArgumentNullException()
    {
        var message = CreateSignedMessage();

        await Task.Run(() => Assert.ThrowsAsync<ArgumentNullException>(() =>
            message.ValidateAsync((ICoseSign1Validator)null!)));
    }

    [Test]
    public async Task ValidateAsync_ValidParameters_DelegatestoValidator()
    {
        var message = CreateSignedMessage();
        var expectedResult = CreateMockValidationResult();
        var mockValidator = new Mock<ICoseSign1Validator>();
        mockValidator.Setup(v => v.ValidateAsync(message, It.IsAny<CancellationToken>()))
            .ReturnsAsync(expectedResult);

        var result = await message.ValidateAsync(mockValidator.Object);

        Assert.That(result, Is.SameAs(expectedResult));
        mockValidator.Verify(v => v.ValidateAsync(message, It.IsAny<CancellationToken>()), Times.Once);
    }

    #endregion

    #region ValidateAsync with Configure Action Tests

    [Test]
    public async Task ValidateAsync_NullMessageWithConfigure_ThrowsArgumentNullException()
    {
        await Task.Run(() => Assert.ThrowsAsync<ArgumentNullException>(() =>
            CoseSign1MessageValidationExtensions.ValidateAsync(null!, _ => { })));
    }

    [Test]
    public async Task ValidateAsync_NullConfigure_UsesAutoDiscovery()
    {
        var message = CreateSignedMessage();

        var result = await message.ValidateAsync((Action<ICoseSign1ValidationBuilder>?)null);

        Assert.That(result.Overall, Is.Not.Null);
    }

    [Test]
    public async Task ValidateAsync_WithConfigure_BuildsAndValidates()
    {
        using var key = ECDsa.Create();
        var message = CreateSignedMessage(key);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var result = await message.ValidateAsync(builder =>
        {
            var mockResolver = new Mock<ISigningKeyResolver>();
            mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
                .Returns(true);
            mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
            mockResolver.Setup(r => r.ResolveAsync(It.IsAny<CoseSign1Message>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(SigningKeyResolutionResult.Success(mockSigningKey.Object));
            builder.AddComponent(mockResolver.Object);
        });

        Assert.That(result.Overall, Is.Not.Null);
    }

    #endregion

    #region Helper Methods

    private static CoseSign1Message CreateSignedMessage(ECDsa? key = null)
    {
        key ??= ECDsa.Create();
        var payload = "Test payload"u8.ToArray();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var signedBytes = CoseSign1Message.SignEmbedded(payload, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseSign1ValidationResult CreateMockValidationResult()
    {
        return new CoseSign1ValidationResult(
            ValidationResult.Success("test"),
            ValidationResult.Success("test"),
            ValidationResult.Success("test"),
            ValidationResult.Success("test"),
            ValidationResult.Success("test"));
    }

    #endregion
}
