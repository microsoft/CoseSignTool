// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using NUnit.Framework;

namespace CoseSign1.Validation.Tests;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class FunctionValidatorTests
{
    private CoseSign1Message? ValidMessage;

    [SetUp]
    public void Setup()
    {
        // Create a simple valid message for testing
        var payload = new byte[] { 1, 2, 3, 4 };
        using var ecdsa = ECDsa.Create();
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var signedBytes = CoseSign1Message.SignDetached(payload, signer);
        ValidMessage = CoseSign1Message.DecodeSign1(signedBytes);
    }

    [Test]
    public void Constructor_WithValidFunction_CreatesValidator()
    {
        // Arrange & Act
        var validator = new FunctionValidator(msg => ValidationResult.Success("TestValidator"));

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullFunction_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new FunctionValidator(null!));
    }

    [Test]
    public void Validate_WithSuccessFunction_ReturnsSuccess()
    {
        // Arrange
        var validator = new FunctionValidator(msg => ValidationResult.Success("TestValidator"));

        // Act
        var result = validator.Validate(ValidMessage!);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithFailureFunction_ReturnsFailure()
    {
        // Arrange
        var validator = new FunctionValidator(msg =>
            ValidationResult.Failure("TestValidator", "Test error", "TEST_ERROR"));

        // Act
        var result = validator.Validate(ValidMessage!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Count, Is.EqualTo(1));
        Assert.That(result.Failures[0].Message, Is.EqualTo("Test error"));
    }

    [Test]
    public void Validate_WithNullMessage_PassesNullToFunction()
    {
        // Arrange
        CoseSign1Message? capturedMessage = ValidMessage;
        var validator = new FunctionValidator(msg =>
        {
            capturedMessage = msg;
            return ValidationResult.Success("TestValidator");
        });

        // Act
        validator.Validate(null!);

        // Assert
        Assert.That(capturedMessage, Is.Null);
    }

    [Test]
    public void Validate_FunctionReceivesCorrectMessage()
    {
        // Arrange
        CoseSign1Message? capturedMessage = null;
        var validator = new FunctionValidator(msg =>
        {
            capturedMessage = msg;
            return ValidationResult.Success("TestValidator");
        });

        // Act
        validator.Validate(ValidMessage!);

        // Assert
        Assert.That(capturedMessage, Is.SameAs(ValidMessage));
    }

    [Test]
    public async Task ValidateAsync_WithSuccessFunction_ReturnsSuccess()
    {
        // Arrange
        var validator = new FunctionValidator(msg => ValidationResult.Success("TestValidator"));

        // Act
        var result = await validator.ValidateAsync(ValidMessage!);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithFailureFunction_ReturnsFailure()
    {
        // Arrange
        var validator = new FunctionValidator(msg =>
            ValidationResult.Failure("TestValidator", "Async error", "ASYNC_ERROR"));

        // Act
        var result = await validator.ValidateAsync(ValidMessage!);

        // Assert
        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_CompletesSuccessfully()
    {
        // Arrange
        var validator = new FunctionValidator(msg => ValidationResult.Success("TestValidator"));
        var cts = new CancellationTokenSource();

        // Act
        var result = await validator.ValidateAsync(ValidMessage!, cts.Token);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithExceptionInFunction_ReturnsFailure()
    {
        // Arrange
        var validator = new FunctionValidator(msg => throw new InvalidOperationException("Test exception"));

        // Act
        var result = validator.Validate(ValidMessage!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Count, Is.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("VALIDATOR_EXCEPTION"));
        Assert.That(result.Failures[0].Exception, Is.InstanceOf<InvalidOperationException>());
    }

    [Test]
    public void Validate_WithMetadataInResult_PreservesMetadata()
    {
        // Arrange
        var metadata = new Dictionary<string, object> { ["TestKey"] = "TestValue" };
        var validator = new FunctionValidator(msg =>
            ValidationResult.Success("TestValidator", metadata));

        // Act
        var result = validator.Validate(ValidMessage!);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["TestKey"], Is.EqualTo("TestValue"));
    }
}