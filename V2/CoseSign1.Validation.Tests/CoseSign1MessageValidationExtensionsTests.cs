// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation.Extensions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;

[TestFixture]
public class CoseSign1MessageValidationExtensionsTests
{
    private CoseSign1Message TestMessage = null!;

    [SetUp]
    public void Setup()
    {
        // Create a simple test message
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var payload = new byte[] { 1, 2, 3, 4 };
        var signedBytes = CoseSign1Message.SignEmbedded(payload, signer);
        TestMessage = CoseSign1Message.DecodeSign1(signedBytes);
    }

    #region Validate with ICoseSign1Validator Tests

    [Test]
    public void Validate_WithValidator_NullMessage_ThrowsArgumentNullException()
    {
        // Arrange
        CoseSign1Message? message = null;
        var mockValidator = new Mock<ICoseSign1Validator>();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => message!.Validate(mockValidator.Object));
        Assert.That(ex!.ParamName, Is.EqualTo("message"));
    }

    [Test]
    public void Validate_WithValidator_NullValidator_ThrowsArgumentNullException()
    {
        // Arrange
        ICoseSign1Validator? validator = null;

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => TestMessage.Validate(validator!));
        Assert.That(ex!.ParamName, Is.EqualTo("validator"));
    }

    [Test]
    public void Validate_WithValidator_DelegatesToValidator()
    {
        // Arrange
        var expectedResult = new CoseSign1ValidationResult(
            ValidationResult.Success("Resolution"),
            ValidationResult.Success("Trust"),
            ValidationResult.Success("Signature"),
            ValidationResult.Success("PostSignature"),
            ValidationResult.Success("Overall"));

        var mockValidator = new Mock<ICoseSign1Validator>();
        mockValidator.Setup(v => v.Validate(TestMessage)).Returns(expectedResult);

        // Act
        var result = TestMessage.Validate(mockValidator.Object);

        // Assert
        Assert.That(result, Is.SameAs(expectedResult));
        mockValidator.Verify(v => v.Validate(TestMessage), Times.Once);
    }

    #endregion

    #region Validate with Configure Action Tests

    [Test]
    public void Validate_WithConfigure_NullMessage_ThrowsArgumentNullException()
    {
        // Arrange
        CoseSign1Message? message = null;

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => 
            message!.Validate(builder => builder.AddValidator(CreateDummySignatureValidator())));
        Assert.That(ex!.ParamName, Is.EqualTo("message"));
    }

    [Test]
    public void Validate_WithConfigure_NullConfigure_ThrowsArgumentNullException()
    {
        // Arrange
        Action<ICoseSign1ValidationBuilder>? configure = null;

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => TestMessage.Validate(configure!));
        Assert.That(ex!.ParamName, Is.EqualTo("configure"));
    }

    [Test]
    public void Validate_WithConfigure_NoSignatureValidator_ThrowsInvalidOperationException()
    {
        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => 
            TestMessage.Validate(builder => { /* No validators added */ }));
    }

    [Test]
    public void Validate_WithConfigure_WithSignatureValidator_ReturnsResult()
    {
        // Act
        var result = TestMessage.Validate(builder => builder
            .AddValidator(CreateDummySignatureValidator())
            .AllowAllTrust("Testing"));

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Overall, Is.Not.Null);
    }

    [Test]
    public void Validate_WithConfigure_WithLoggerFactory_PassesLogger()
    {
        // Arrange
        var mockLoggerFactory = new Mock<ILoggerFactory>();
        mockLoggerFactory.Setup(f => f.CreateLogger(It.IsAny<string>()))
            .Returns(Mock.Of<ILogger>());

        // Act
        var result = TestMessage.Validate(
            builder => builder
                .AddValidator(CreateDummySignatureValidator())
                .AllowAllTrust("Testing"),
            mockLoggerFactory.Object);

        // Assert
        Assert.That(result, Is.Not.Null);
    }

    #endregion

    #region Helper Methods

    private static IValidator CreateDummySignatureValidator()
    {
        return new DummySignatureValidator();
    }

    private sealed class DummySignatureValidator : IValidator
    {
        public IReadOnlyCollection<ValidationStage> Stages => new[] { ValidationStage.Signature };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
        {
            return ValidationResult.Success("DummySignatureValidator", stage);
        }

        public Task<ValidationResult> ValidateAsync(
            CoseSign1Message input,
            ValidationStage stage,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Validate(input, stage));
        }
    }

    #endregion
}
